use std::cmp::{self, Ordering, min};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process;
use std::str::FromStr;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use chrono::{DateTime, Local, TimeZone, Utc};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use compact_str::CompactString;
use csv::{QuoteStyle, Writer, WriterBuilder};
use hashbrown::hash_map::RawEntryMut;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use krapslog::{build_sparkline, build_time_markers};
use nested::Nested;
use num_format::{Locale, ToFormattedString};
use strum::IntoEnumIterator;
use termcolor::{Buffer, BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use terminal_size::Width;
use terminal_size::terminal_size;

use crate::detections::configs::{
    Action, CONTROL_CHAR_REPLACE_MAP, CURRENT_EXE_PATH, GEOIP_DB_PARSER, StoredStatic,
    TimeFormatOptions,
};
use crate::detections::message::{AlertMessage, COMPUTER_MITRE_ATTCK_MAP, DetectInfo};

/// Escapes user-supplied data values before embedding them into the Markdown that
/// is rendered as HTML for the report, to prevent XSS and Markdown injection.
///
/// HTML special characters are entity-escaped (stops raw-HTML injection like
/// `<script>`), and Markdown metacharacters that could otherwise form links or
/// break table structure are backslash-escaped. The latter matters because the
/// escaped values are placed inside Markdown list/link/table constructs and
/// rendered by pulldown-cmark, which does not sanitize URL schemes: without it a
/// value such as `[x](javascript:alert(1))` would render as a clickable
/// `javascript:` anchor (click-to-execute XSS), and a `|` would break a table row.
///
/// This should be applied only to dynamic data values (e.g. computer names from
/// logs), not to the Markdown template strings that may contain intentional HTML
/// like `<br>` or intentional Markdown like table pipes.
fn html_escape_value(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // HTML special characters -> entities.
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            // Markdown metacharacters -> backslash-escaped. A backslash in the input
            // is itself doubled so it cannot cancel the escaping of the following
            // character when the Markdown is rendered.
            '\\' => escaped.push_str("\\\\"),
            '[' => escaped.push_str("\\["),
            ']' => escaped.push_str("\\]"),
            '(' => escaped.push_str("\\("),
            ')' => escaped.push_str("\\)"),
            '|' => escaped.push_str("\\|"),
            _ => escaped.push(c),
        }
    }
    escaped
}
use crate::detections::utils::{
    self, check_setting_path, format_time, get_writable_color, output_and_data_stack_for_html,
    write_color_buffer,
};
use crate::level::{_get_output_color, LEVEL, create_output_color_map};
use crate::options::htmlreport;
use crate::options::profile::Profile;

/// The same display color expressed once for the termcolor crate (plain terminal output) and
/// once for the comfy_table crate (table output).
#[derive(Debug)]
pub struct Colors {
    pub output_color: termcolor::Color,
    pub table_color: comfy_table::Color,
}

/// State accumulated while emitting detection results, used afterwards to build the results
/// summary: detection counts broken down by level/date/computer/rule, timestamps for the
/// detection frequency timeline, and the previous-record data needed for duplicate suppression.
pub struct AfterfactInfo {
    pub timeline_start_time: Option<DateTime<Utc>>,
    pub timeline_end_time: Option<DateTime<Utc>>,
    pub detect_starttime: Option<DateTime<Utc>>,
    pub detect_endtime: Option<DateTime<Utc>>,
    pub record_cnt: u128,
    pub recover_record_cnt: u128,
    pub detected_record_idset: HashSet<CompactString>,
    pub total_detect_counts_by_level: Vec<u128>,
    pub unique_detect_counts_by_level: Vec<u128>,
    pub detect_counts_by_date_and_level: HashMap<LEVEL, HashMap<CompactString, i128>>,
    pub detect_counts_by_computer_and_level: HashMap<LEVEL, HashMap<CompactString, i128>>,
    pub detect_counts_by_rule_and_level: HashMap<LEVEL, HashMap<CompactString, i128>>,
    pub detect_rule_authors: HashMap<CompactString, CompactString>,
    pub rule_title_path_map: HashMap<CompactString, CompactString>,
    pub rule_author_counter: HashMap<CompactString, i128>,
    pub timestamps: Vec<i64>,
    pub has_displayed_header: bool,
    pub detected_rule_files: HashSet<CompactString>,
    pub detected_rule_ids: HashSet<CompactString>,
    pub detected_computer_and_rule_names: HashSet<CompactString>,
    pub prev_message: HashMap<CompactString, Profile>,
    pub prev_details_convert_map: HashMap<CompactString, Vec<CompactString>>,
}

/// The three per-level count maps (by date, by computer, by rule) created together in
/// `AfterfactInfo::default`.
struct InitLevelMapResult(
    HashMap<LEVEL, HashMap<CompactString, i128>>,
    HashMap<LEVEL, HashMap<CompactString, i128>>,
    HashMap<LEVEL, HashMap<CompactString, i128>>,
);

impl Default for AfterfactInfo {
    fn default() -> Self {
        let InitLevelMapResult(
            detect_counts_by_date_and_level,
            detect_counts_by_computer_and_level,
            detect_counts_by_rule_and_level,
        ) = {
            let mut detect_counts_by_date_and_level: HashMap<LEVEL, HashMap<CompactString, i128>> =
                HashMap::new();
            let mut detect_counts_by_computer_and_level: HashMap<
                LEVEL,
                HashMap<CompactString, i128>,
            > = HashMap::new();
            let mut detect_counts_by_rule_and_level: HashMap<LEVEL, HashMap<CompactString, i128>> =
                HashMap::new();
            // Pre-insert an empty inner map for every level so later per-level lookups always
            // find an entry (several output functions rely on this and unwrap the result).
            for level_init in LEVEL::iter() {
                detect_counts_by_date_and_level.insert(level_init.clone(), HashMap::new());
                detect_counts_by_computer_and_level.insert(level_init.clone(), HashMap::new());
                detect_counts_by_rule_and_level.insert(level_init, HashMap::new());
            }

            InitLevelMapResult(
                detect_counts_by_date_and_level,
                detect_counts_by_computer_and_level,
                detect_counts_by_rule_and_level,
            )
        };
        AfterfactInfo {
            timeline_start_time: Option::None,
            timeline_end_time: Option::None,
            detect_starttime: Option::None,
            detect_endtime: Option::None,
            record_cnt: 0,
            recover_record_cnt: 0,
            detected_record_idset: HashSet::new(),
            total_detect_counts_by_level: vec![0; 7],
            unique_detect_counts_by_level: vec![0; 7],
            detect_counts_by_date_and_level,
            detect_counts_by_computer_and_level,
            detect_counts_by_rule_and_level,
            detect_rule_authors: HashMap::new(),
            rule_title_path_map: HashMap::new(),
            rule_author_counter: HashMap::new(),
            timestamps: vec![],
            has_displayed_header: false,
            detected_rule_files: HashSet::new(),
            detected_rule_ids: HashSet::new(),
            detected_computer_and_rule_names: HashSet::new(),
            prev_message: HashMap::new(),
            prev_details_convert_map: HashMap::new(),
        }
    }
}

/// The writers used for result output: a termcolor writer for colored terminal display and a
/// csv crate writer for the CSV/JSON output itself. `display_flag` is true when no output file
/// was specified, i.e. results are displayed on the terminal.
pub struct AfterfactWriter {
    display_writer: BufferWriter,
    disp_wtr_buf: Buffer,
    csv_writer: Writer<Box<dyn io::Write>>,
    pub display_flag: bool,
}

/// Creates the result writer, targeting the file given with the output option if one was
/// specified, otherwise stdout (the pivot-keywords-list and logon-summary commands write their
/// own files elsewhere, so their writer stays on stdout). The csv writer is also (ab)used for
/// JSON output by configuring
/// it to perform no quoting and use newline as the delimiter.
pub fn init_writer(stored_static: &StoredStatic) -> AfterfactWriter {
    let display_writer = BufferWriter::stdout(ColorChoice::Always);
    let mut disp_wtr_buf = display_writer.buffer();

    disp_wtr_buf.set_color(ColorSpec::new().set_fg(None)).ok();

    let mut display_flag = false;
    let target: Box<dyn io::Write> = if let Some(path) = &stored_static.output_path {
        if matches!(
            stored_static.config.action.as_ref().unwrap(),
            Action::PivotKeywordsList(_) | Action::LogonSummary(_)
        ) {
            Box::new(BufWriter::new(io::stdout()))
        } else {
            // Write the results to the specified output file.
            match File::create(path) {
                Ok(file) => Box::new(BufWriter::new(file)),
                Err(err) => {
                    AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                    process::exit(1);
                }
            }
        }
    } else {
        display_flag = true;
        // No output file was specified, so results go to stdout. Colored display output is
        // produced through the termcolor writer (display_writer), not through this csv writer.
        Box::new(BufWriter::new(io::stdout()))
    };

    let writer = match &stored_static.config.action.as_ref().unwrap() {
        Action::JsonTimeline(_) => WriterBuilder::new()
            .delimiter(b'\n')
            .double_quote(false)
            .quote_style(QuoteStyle::Never)
            .from_writer(target),
        Action::CsvTimeline(_) => WriterBuilder::new()
            .quote_style(QuoteStyle::NonNumeric)
            .from_writer(target),
        _ => WriterBuilder::new().from_writer(target),
    };

    // Bundle the display writer and the CSV/JSON writer used by emit_csv and the summary output.
    AfterfactWriter {
        display_writer,
        disp_wtr_buf,
        csv_writer: writer,
        display_flag,
    }
}

/// Sorts and deduplicates all collected detections, writes them out, and prints the results
/// summary. Exits the process if writing fails.
pub fn output_afterfact(
    detect_infos: &mut [DetectInfo],
    afterfact_writer: &mut AfterfactWriter,
    stored_static: &StoredStatic,
    afterfact_info: &mut AfterfactInfo,
) {
    let ret = output_afterfact_inner(
        detect_infos,
        afterfact_writer,
        stored_static,
        afterfact_info,
    );
    if ret.is_err() {
        output_afterfact_err(Box::new(ret.err().unwrap()));
    }
}

/// Writes one batch of detections and folds it into the summary statistics. This is the
/// streaming output path used in low-memory mode, where results are emitted per batch instead
/// of being collected, sorted, and written all at once by `output_afterfact`. Exits the process
/// if writing fails.
pub fn emit_csv(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    stored_static: &StoredStatic,
    afterfact_writer: &mut AfterfactWriter,
    afterfact_info: &mut AfterfactInfo,
) {
    if detect_infos.is_empty() {
        return;
    }

    let result = emit_csv_inner(
        detect_infos,
        duplicate_indices,
        stored_static,
        afterfact_writer,
        afterfact_info,
    );
    if result.is_err() {
        output_afterfact_err(Box::new(result.err().unwrap()));
    }

    calc_statistic_info(
        detect_infos,
        duplicate_indices,
        afterfact_info,
        stored_static,
    );
}

fn output_afterfact_err(err: Box<dyn Error>) {
    AlertMessage::alert(&format!("Failed to write CSV. {err}")).ok();
    process::exit(1);
}

fn output_afterfact_inner(
    detect_infos: &mut [DetectInfo],
    afterfact_writer: &mut AfterfactWriter,
    stored_static: &StoredStatic,
    afterfact_info: &mut AfterfactInfo,
) -> io::Result<()> {
    if afterfact_writer.display_flag {
        println!();
    }

    // Sort the detections, then determine which ones to drop as duplicates if the
    // remove-duplicate-detections option is enabled.
    sort_detect_info(detect_infos);
    let duplicate_indices = if stored_static
        .output_option
        .as_ref()
        .unwrap()
        .remove_duplicate_detections
    {
        get_duplicate_indices(detect_infos)
    } else {
        HashSet::new()
    };

    emit_csv_inner(
        detect_infos,
        &duplicate_indices,
        stored_static,
        afterfact_writer,
        afterfact_info,
    )?;

    // Calculate the statistics for the results summary.
    calc_statistic_info(
        detect_infos,
        &duplicate_indices,
        afterfact_info,
        stored_static,
    );
    afterfact_writer.disp_wtr_buf.clear();

    output_additional_afterfact(stored_static, afterfact_writer, afterfact_info);

    Ok(())
}

fn emit_csv_inner(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    stored_static: &StoredStatic,
    afterfact_writer: &mut AfterfactWriter,
    afterfact_info: &mut AfterfactInfo,
) -> io::Result<()> {
    // Control characters in record field values were escaped earlier in the pipeline as
    // "🛂r"/"🛂n"/"🛂t" (see utils::remove_sp_char). output_replacer first restores them to the
    // real control characters, then output_remover flattens control characters to spaces for
    // single-line output. With the multiline (or tab-separator) option, the "🛂🛂" marker used to
    // join multi-valued entries and the " ¦ " field separator become line breaks (or tabs)
    // instead.
    let output_replaced_maps: HashMap<&str, &str> =
        HashMap::from_iter(vec![("🛂r", "\r"), ("🛂n", "\n"), ("🛂t", "\t")]);
    let mut removed_replaced_maps: HashMap<&str, &str> =
        HashMap::from_iter(vec![("\n", " "), ("\r", " "), ("\t", " ")]);
    if stored_static.multiline_flag {
        removed_replaced_maps.insert("🛂🛂", "\r\n");
        removed_replaced_maps.insert(" ¦ ", "\r\n");
    } else if stored_static.tab_separator_flag {
        removed_replaced_maps.insert("🛂🛂", "\t");
        removed_replaced_maps.insert(" ¦ ", "\t");
    }
    let output_replacer = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(output_replaced_maps.keys())
        .unwrap();
    let output_remover = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(removed_replaced_maps.keys())
        .unwrap();

    // Prepare the per-level color map, then determine the output format and whether duplicate
    // field data should be replaced with "DUP" (the remove-duplicate-data option).
    let color_map = create_output_color_map(stored_static.common_options.no_color);
    let (json_output_flag, jsonl_output_flag, remove_duplicate_data) =
        match &stored_static.config.action.as_ref().unwrap() {
            Action::JsonTimeline(option) => (
                true,
                option.jsonl_timeline,
                option.output_options.remove_duplicate_data,
            ),
            Action::CsvTimeline(option) => {
                (false, false, option.output_options.remove_duplicate_data)
            }
            _ => (false, false, false),
        };

    let profile = stored_static.profiles.as_ref().unwrap();
    for (i, detect_info) in detect_infos.iter().enumerate() {
        if duplicate_indices.contains(&i) {
            continue;
        }
        if afterfact_writer.display_flag && !(json_output_flag || jsonl_output_flag) {
            // Terminal display output.
            if !afterfact_info.has_displayed_header {
                // Print the header row only once.
                _get_serialized_disp_output(
                    &afterfact_writer.display_writer,
                    profile,
                    true,
                    (&output_replacer, &output_replaced_maps),
                    (&output_remover, &removed_replaced_maps),
                    stored_static.common_options.no_color,
                    get_writable_color(
                        _get_output_color(&color_map, &detect_info.level),
                        stored_static.common_options.no_color,
                    ),
                );
                afterfact_info.has_displayed_header = true;
            }
            _get_serialized_disp_output(
                &afterfact_writer.display_writer,
                &detect_info.output_fields,
                false,
                (&output_replacer, &output_replaced_maps),
                (&output_remover, &removed_replaced_maps),
                stored_static.common_options.no_color,
                get_writable_color(
                    _get_output_color(&color_map, &detect_info.level),
                    stored_static.common_options.no_color,
                ),
            );
        } else if jsonl_output_flag {
            // JSONL output format
            let result = output_json_str(
                detect_info,
                afterfact_info,
                jsonl_output_flag,
                GEOIP_DB_PARSER.read().unwrap().is_some(),
                remove_duplicate_data,
            );
            afterfact_info.prev_message = result.1;
            afterfact_info
                .prev_details_convert_map
                .clone_from(&detect_info.details_convert_map);
            if afterfact_writer.display_flag {
                write_color_buffer(
                    &afterfact_writer.display_writer,
                    None,
                    &format!("{{ {} }}", &result.0),
                    true,
                )
                .ok();
            } else {
                afterfact_writer
                    .csv_writer
                    .write_field(format!("{{ {} }}", &result.0))?;
            }
        } else if json_output_flag {
            // JSON output
            let result = output_json_str(
                detect_info,
                afterfact_info,
                jsonl_output_flag,
                GEOIP_DB_PARSER.read().unwrap().is_some(),
                remove_duplicate_data,
            );
            afterfact_info.prev_message = result.1;
            afterfact_info
                .prev_details_convert_map
                .clone_from(&detect_info.details_convert_map);
            if afterfact_writer.display_flag {
                write_color_buffer(
                    &afterfact_writer.display_writer,
                    None,
                    &format!("{{\n{}\n}}", &result.0),
                    true,
                )
                .ok();
            } else {
                afterfact_writer.csv_writer.write_field("{")?;
                afterfact_writer.csv_writer.write_field(&result.0)?;
                afterfact_writer.csv_writer.write_field("}")?;
            }
        } else {
            // CSV output format
            if !afterfact_info.has_displayed_header {
                afterfact_writer
                    .csv_writer
                    .write_record(detect_info.output_fields.iter().map(|x| x.0.trim()))?;
                afterfact_info.has_displayed_header = true;
            }
            afterfact_writer
                .csv_writer
                .write_record(detect_info.output_fields.iter().map(|x| {
                    match x.1 {
                        Profile::Details(_)
                        | Profile::AllFieldInfo(_)
                        | Profile::ExtraFieldInfo(_) => {
                            let ret = if remove_duplicate_data
                                && x.1.to_value()
                                    == afterfact_info
                                        .prev_message
                                        .get(&x.0)
                                        .unwrap_or(&Profile::Literal("-".into()))
                                        .to_value()
                            {
                                "DUP".to_string()
                            } else {
                                output_remover.replace_all(
                                    &output_replacer
                                        .replace_all(
                                            &x.1.to_value(),
                                            &output_replaced_maps.values().collect_vec(),
                                        )
                                        .split_whitespace()
                                        .join(" "),
                                    &removed_replaced_maps.values().collect_vec(),
                                )
                            };
                            afterfact_info.prev_message.insert(x.0.clone(), x.1.clone());
                            ret
                        }
                        _ => output_remover.replace_all(
                            &output_replacer
                                .replace_all(
                                    &x.1.to_value(),
                                    &output_replaced_maps.values().collect_vec(),
                                )
                                .split_whitespace()
                                .join(" "),
                            &removed_replaced_maps.values().collect_vec(),
                        ),
                    }
                }))?;
        }
    }

    if !afterfact_writer.display_flag {
        afterfact_writer.csv_writer.flush()?;
    }
    if json_output_flag && stored_static.output_path.is_none() {
        println!()
    }
    Ok(())
}

/// Folds a batch of detections into `afterfact_info`: records the detection timestamps and the
/// IDs of detected records, and (unless no-summary is set) updates the per-level counts by
/// date, computer, and rule, plus the rule author statistics used by the results summary.
fn calc_statistic_info(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    afterfact_info: &mut AfterfactInfo,
    stored_static: &StoredStatic,
) {
    let output_option = stored_static.output_option.as_ref().unwrap();
    for (i, detect_info) in detect_infos.iter().enumerate() {
        if duplicate_indices.contains(&i) {
            continue;
        }
        afterfact_info
            .timestamps
            .push(detect_info.detected_time.timestamp());
        match &detect_info.agg_result {
            None => {
                afterfact_info
                    .detected_record_idset
                    .insert(CompactString::from(format!(
                        "{}_{}",
                        detect_info.detected_time, detect_info.eventid
                    )));
            }
            Some(agg_result) => {
                agg_result.agg_record_time_info.iter().for_each(|a| {
                    afterfact_info
                        .detected_record_idset
                        .insert(CompactString::from(format!("{}_{}", a.time, a.event_id)));
                });
            }
        }
        if !output_option.no_summary {
            let level_index = detect_info.level.index();
            let author_list = extract_author_name(&detect_info.ruleauthor);
            let author_str = author_list.iter().join(", ");
            afterfact_info.detect_rule_authors.insert(
                detect_info.rule_path.to_owned(),
                author_str.to_string().into(),
            );

            if author_str != "-"
                && !afterfact_info
                    .detected_rule_files
                    .contains(&detect_info.rule_path)
            {
                afterfact_info
                    .detected_rule_files
                    .insert(detect_info.rule_path.to_owned());
                for author in author_list.iter() {
                    *afterfact_info
                        .rule_author_counter
                        .entry(CompactString::from(author))
                        .or_insert(0) += 1;
                }
            }
            if !afterfact_info
                .detected_rule_ids
                .contains(&detect_info.ruleid)
            {
                afterfact_info
                    .detected_rule_ids
                    .insert(detect_info.ruleid.to_owned());
                afterfact_info.unique_detect_counts_by_level[level_index] += 1;
            }
            let computer_names = match &detect_info.agg_result {
                None => vec![detect_info.computername.clone()],
                Some(agg) => agg
                    .agg_record_time_info
                    .iter()
                    .map(|a| CompactString::from(a.computer.clone()))
                    .collect::<std::collections::HashSet<_>>() // Convert to HashSet to remove duplicates
                    .into_iter()
                    .sorted()
                    .collect(),
            };
            for computername in &computer_names {
                let computer_rule_check_key =
                    CompactString::from(format!("{}|{}", computername, &detect_info.rule_path));
                if !afterfact_info
                    .detected_computer_and_rule_names
                    .contains(&computer_rule_check_key)
                {
                    afterfact_info
                        .detected_computer_and_rule_names
                        .insert(computer_rule_check_key);
                    countup_aggregation(
                        &mut afterfact_info.detect_counts_by_computer_and_level,
                        &detect_info.level,
                        computername,
                    );
                }
            }
            afterfact_info.rule_title_path_map.insert(
                detect_info.ruletitle.to_owned(),
                detect_info.rule_path.to_owned(),
            );

            countup_aggregation(
                &mut afterfact_info.detect_counts_by_date_and_level,
                &detect_info.level,
                &format_time(
                    &detect_info.detected_time,
                    true,
                    &output_option.time_format_options,
                ),
            );
            countup_aggregation(
                &mut afterfact_info.detect_counts_by_rule_and_level,
                &detect_info.level,
                &detect_info.ruletitle,
            );
            let level_index = detect_info.level.index();
            afterfact_info.total_detect_counts_by_level[level_index] += 1;
        }
    }
}

/// Prints everything that follows the timeline itself: the rule author table, the detection
/// frequency timeline (if requested), and the results summary (event counts, detection counts
/// per level/date/computer/rule). Also accumulates the same content for the HTML report if enabled.
pub fn output_additional_afterfact(
    stored_static: &StoredStatic,
    afterfact_writer: &mut AfterfactWriter,
    afterfact_info: &AfterfactInfo,
) {
    if afterfact_writer.display_flag {
        println!();
    }

    let terminal_width = match terminal_size() {
        Some((Width(w), _)) => w as usize,
        None => 100,
    };

    let output_option = stored_static.output_option.as_ref().unwrap();
    if !output_option.no_summary && !afterfact_info.rule_author_counter.is_empty() {
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Rule Authors:",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " ",
            true,
        )
        .ok();

        println!();
        let table_column_num = if terminal_width <= 105 {
            2
        } else if terminal_width < 140 {
            3
        } else if terminal_width < 175 {
            4
        } else if terminal_width <= 210 {
            5
        } else {
            6
        };
        output_detected_rule_authors(&afterfact_info.rule_author_counter, table_column_num);
    }

    println!();
    if output_option.visualize_timeline {
        _print_timeline_hist(&afterfact_info.timestamps, terminal_width, 3);
        println!();
    }

    let mut html_output_stock = Nested::<String>::new();
    if !output_option.no_summary {
        afterfact_writer.disp_wtr_buf.clear();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Results Summary:",
            false,
        )
        .ok();

        if let Some(timeline_start_time) = afterfact_info.timeline_start_time {
            output_and_data_stack_for_html(
                &format!(
                    "First timestamp: {}",
                    utils::format_time(
                        &timeline_start_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
        }
        if let Some(timeline_end_time) = afterfact_info.timeline_end_time {
            output_and_data_stack_for_html(
                &format!(
                    "Last timestamp: {}",
                    utils::format_time(
                        &timeline_end_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
            println!();
        }
        if let Some(detect_starttime) = afterfact_info.detect_starttime {
            output_and_data_stack_for_html(
                &format!(
                    "First detection: {}",
                    utils::format_time(
                        &detect_starttime,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
        }
        if let Some(detect_endtime) = afterfact_info.detect_endtime {
            output_and_data_stack_for_html(
                &format!(
                    "Last detection: {}",
                    utils::format_time(
                        &detect_endtime,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
            println!();
        }

        let reduced_record_cnt: u128 =
            afterfact_info.record_cnt - afterfact_info.detected_record_idset.len() as u128;
        let reduced_percent = if afterfact_info.record_cnt == 0 {
            0 as f64
        } else {
            (reduced_record_cnt as f64) / (afterfact_info.record_cnt as f64) * 100.0
        };
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Events with hits",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            "Total events",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            ": ",
            false,
        )
        .ok();
        let saved_alerts_output =
            (afterfact_info.record_cnt - reduced_record_cnt).to_formatted_string(&Locale::en);
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &saved_alerts_output,
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();

        let all_record_output = afterfact_info.record_cnt.to_formatted_string(&Locale::en);
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            &all_record_output,
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " (",
            false,
        )
        .ok();
        let reduction_output = format!(
            "Data reduction: {} events ({:.2}%)",
            reduced_record_cnt.to_formatted_string(&Locale::en),
            reduced_percent
        );
        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &reduction_output,
            false,
        )
        .ok();

        write_color_buffer(
            &afterfact_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            ")",
            true,
        )
        .ok();
        if stored_static.enable_recover_records {
            write_color_buffer(
                &afterfact_writer.display_writer,
                get_writable_color(
                    Some(Color::Rgb(0, 255, 255)),
                    stored_static.common_options.no_color,
                ),
                "Recovered records",
                false,
            )
            .ok();
            write_color_buffer(
                &afterfact_writer.display_writer,
                get_writable_color(None, stored_static.common_options.no_color),
                ": ",
                false,
            )
            .ok();
            let recovered_record_output = afterfact_info
                .recover_record_cnt
                .to_formatted_string(&Locale::en);
            write_color_buffer(
                &afterfact_writer.display_writer,
                get_writable_color(
                    Some(Color::Rgb(0, 255, 255)),
                    stored_static.common_options.no_color,
                ),
                &recovered_record_output,
                true,
            )
            .ok();
        }
        println!();

        if stored_static.html_report_flag {
            html_output_stock.push(format!("- Events with hits: {}", &saved_alerts_output));
            html_output_stock.push(format!("- Total events analyzed: {}", &all_record_output));
            html_output_stock.push(format!("- {reduction_output}"));
            html_output_stock.push(format!(
                "- Recovered events analyzed: {}",
                &afterfact_info
                    .recover_record_cnt
                    .to_formatted_string(&Locale::en)
            ));
        }

        let color_map = create_output_color_map(stored_static.common_options.no_color);
        _print_unique_results(
            &afterfact_info.total_detect_counts_by_level,
            &afterfact_info.unique_detect_counts_by_level,
            (
                CompactString::from("Total | Unique"),
                CompactString::from("detections"),
            ),
            &color_map,
            &mut html_output_stock,
            stored_static.html_report_flag,
        );
        println!();
        if let Some(timeline_start_time) = afterfact_info.timeline_start_time {
            let ts = format!(
                "First timestamp: {}",
                format_time(
                    &timeline_start_time,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
        }
        if let Some(timeline_end_time) = afterfact_info.timeline_end_time {
            let ts = format!(
                "Last timestamp: {}",
                format_time(
                    &timeline_end_time,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
            println!();
        }
        if let Some(detect_starttime) = afterfact_info.detect_starttime {
            let ts = format!(
                "First detection: {}",
                format_time(
                    &detect_starttime,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
        }
        if let Some(detect_endtime) = afterfact_info.detect_endtime {
            let ts = format!(
                "Last detection: {}",
                format_time(
                    &detect_endtime,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
            println!();
        }

        _print_detection_summary_by_date(
            &afterfact_info.detect_counts_by_date_and_level,
            &color_map,
            &mut html_output_stock,
            stored_static,
        );
        println!();
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }

        _print_detection_summary_by_computer(
            &afterfact_info.detect_counts_by_computer_and_level,
            &color_map,
            &mut html_output_stock,
            stored_static,
        );
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }

        _print_detection_summary_tables(
            &afterfact_info.detect_counts_by_rule_and_level,
            &color_map,
            (
                &afterfact_info.rule_title_path_map,
                &afterfact_info.detect_rule_authors,
            ),
            &mut html_output_stock,
            stored_static,
            cmp::min((terminal_width / 2) - 15, 200),
        );
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }
    }
    if stored_static.html_report_flag {
        _output_html_computer_by_mitre_attck(&mut html_output_stock);
        htmlreport::add_md_data("Results Summary {#results_summary}", html_output_stock);
    }
}

/// Sorts detections by detected time, level, event ID, rule path, computer name, record ID,
/// and finally by the rendered field values, giving a total order so the output is
/// deterministic.
pub fn sort_detect_info(detect_infos: &mut [DetectInfo]) {
    detect_infos.sort_unstable_by(|a, b| {
        let cmp_time = a.detected_time.cmp(&b.detected_time);
        if cmp_time != Ordering::Equal {
            return cmp_time;
        }

        let a_level = a.level.index();
        let b_level = b.level.index();
        let level_cmp = a_level.cmp(&b_level);
        if level_cmp != Ordering::Equal {
            return level_cmp;
        }

        let event_id_cmp = a.eventid.cmp(&b.eventid);
        if event_id_cmp != Ordering::Equal {
            return event_id_cmp;
        }

        let rule_path_cmp = a.rule_path.cmp(&b.rule_path);
        if rule_path_cmp != Ordering::Equal {
            return rule_path_cmp;
        }

        let computer_cmp = a.computername.cmp(&b.computername);
        if computer_cmp != Ordering::Equal {
            return computer_cmp;
        }

        let rec_id_cmp = a.rec_id.cmp(&b.rec_id);
        if rec_id_cmp != Ordering::Equal {
            return rec_id_cmp;
        }

        // Final tie-breaker: order by the rendered field values so the sort is a
        // total order and the output is deterministic run-to-run (previously,
        // records equal on every key above — e.g. the same event collected from
        // two overlapping evtx files, differing only in the EvtxFile column — got
        // a run-dependent order from the unstable sort + parallel collection).
        // Records still equal here are indistinguishable (identical rendered
        // fields), so their relative order does not affect the output. Only
        // reached when all keys above tie (rare) and short-circuits at the first
        // differing field, so the added cost is negligible.
        a.output_fields
            .iter()
            .map(|(_, p)| p.to_value())
            .cmp(b.output_fields.iter().map(|(_, p)| p.to_value()))
    });
}

/// Returns the indexes of detections considered duplicates of an earlier detection with the
/// same timestamp, comparing every profile field except EvtxFile (so the same event ingested
/// from overlapping evtx files counts as a duplicate). Assumes `detect_infos` is already sorted
/// by detected time, so records sharing a timestamp are contiguous. Within each timestamp group
/// the first occurrence is kept and every later record with identical fields is flagged, so of N
/// identical detections exactly one survives.
pub fn get_duplicate_indices(detect_infos: &mut [DetectInfo]) -> HashSet<usize> {
    // Collect the indexes of duplicate events.
    let mut filtered_detect_infos = HashSet::new();
    let mut prev_detect_infos = HashSet::new();
    for (i, detect_info) in detect_infos.iter().enumerate() {
        // Records are sorted by time, so a change of timestamp starts a new group; reset the
        // comparison set so duplicates are only matched within a single timestamp.
        if i > 0
            && detect_infos[i - 1]
                .detected_time
                .cmp(&detect_info.detected_time)
                != Ordering::Equal
        {
            prev_detect_infos.clear();
        }

        let fields: Vec<&(CompactString, Profile)> = detect_info
            .output_fields
            .iter()
            .filter(|(_, profile)| !matches!(profile, Profile::EvtxFile(_)))
            .collect();
        // Remember this record as the surviving occurrence for its timestamp group.
        // HashSet::insert returns false when an identical earlier record is already present,
        // which flags this one as a duplicate in a single hash lookup. Inserting the first
        // record of each group (which the previous logic skipped) is what lets the second
        // identical copy be flagged instead of slipping through.
        if !prev_detect_infos.insert(fields) {
            filtered_detect_infos.insert(i);
        }
    }

    filtered_detect_infos
}

fn _get_table_color(
    color_map: &HashMap<LEVEL, Colors>,
    level: &LEVEL,
) -> Option<comfy_table::Color> {
    let mut color = None;
    if let Some(c) = color_map.get(level) {
        color = Some(c.table_color);
    }
    color
}

/// Prints the detection frequency timeline (a sparkline histogram of detection timestamps with
/// time markers) to stdout. Requires at least 5 events to render.
fn _print_timeline_hist(timestamps: &[i64], length: usize, side_margin_size: usize) {
    if timestamps.is_empty() {
        return;
    }

    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    if timestamps.len() < 5 {
        writeln!(
            wtr,
            "Detection Frequency Timeline could not be displayed as there needs to be more than 5 events.",
        )
        .ok();
        buf_wtr.print(&wtr).ok();
        return;
    }

    let title = "Detection Frequency Timeline";
    let header_row_space = (length - title.len()) / 2;
    writeln!(wtr, "{}{}", " ".repeat(header_row_space), title).ok();
    println!();

    let timestamp_marker_max = if timestamps.len() < 2 {
        0
    } else {
        timestamps.len() - 2
    };
    let marker_num = min(timestamp_marker_max, 18);

    let (header_raw, footer_raw) =
        build_time_markers(timestamps, marker_num, length - (side_margin_size * 2));
    let sparkline = build_sparkline(timestamps, length - (side_margin_size * 2), 5_usize);
    for header_str in header_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), header_str).ok();
    }
    for line in sparkline.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), line).ok();
    }
    for footer_str in footer_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), footer_str).ok();
    }

    buf_wtr.print(&wtr).ok();
}

/// Increments the counter for `entry_key` in the inner map for `level`, falling back to the
/// UNDEFINED level's map if the level has no entry.
fn countup_aggregation(
    count_map: &mut HashMap<LEVEL, HashMap<CompactString, i128>>,
    level: &LEVEL,
    entry_key: &str,
) {
    let mut detect_counts_by_rules = count_map
        .get(level)
        .unwrap_or_else(|| count_map.get(&LEVEL::UNDEFINED).unwrap())
        .to_owned();
    *detect_counts_by_rules.entry(entry_key.into()).or_insert(0) += 1;
    count_map.insert(level.clone(), detect_counts_by_rules);
}

/// Column position within a display cell, which determines where padding spaces are added:
/// First: |<str> |
/// Last: | <str>|
/// Other: | <str> |
enum ColPos {
    First,
    Last,
    Other,
}

/// Writes one record (or, when `header` is true, the column header row) to the terminal in the
/// "·"-separated display format, coloring the timestamp/level/rule-title fields by detection
/// level and the field names/values inside the details sections individually.
fn _get_serialized_disp_output(
    display_writer: &BufferWriter,
    data: &[(CompactString, Profile)],
    header: bool,
    (output_replacer, output_replaced_maps): (&AhoCorasick, &HashMap<&str, &str>),
    (output_remover, removed_replaced_maps): (&AhoCorasick, &HashMap<&str, &str>),
    no_color: bool,
    level_color: Option<Color>,
) {
    let data_length = data.len();
    let mut ret = Nested::<String>::new();
    if header {
        for (i, d) in data.iter().enumerate() {
            if i == 0 {
                ret.push(_format_cellpos(&d.0, ColPos::First))
            } else if i == data_length - 1 {
                ret.push(_format_cellpos(&d.0, ColPos::Last))
            } else {
                ret.push(_format_cellpos(&d.0, ColPos::Other))
            }
        }
        let mut disp_serializer = WriterBuilder::new()
            .double_quote(false)
            .quote_style(QuoteStyle::Never)
            .delimiter(b'|')
            .has_headers(false)
            .from_writer(vec![]);

        disp_serializer
            .write_record(ret.iter().collect::<Vec<_>>())
            .ok();

        write_color_buffer(
            display_writer,
            get_writable_color(None, no_color),
            // The serializer above uses '|' as its delimiter; show those separators as '·' and
            // then restore any '🦅' placeholders back to '|'. Historically cell values had
            // literal '|' replaced with '🦅' before serialization so this delimiter
            // substitution would not clobber them; nothing currently inserts that placeholder
            // on this path, so the second replace is defensive/vestigial.
            &String::from_utf8(disp_serializer.into_inner().unwrap_or_default())
                .unwrap_or_default()
                .replace('|', "·")
                .replace('🦅', "|"),
            false,
        )
        .ok();
    } else {
        for (i, d) in data.iter().enumerate() {
            let col_pos = if i == 0 {
                ColPos::First
            } else if i == data_length - 1 {
                ColPos::Last
            } else {
                ColPos::Other
            };
            let display_contents = _format_cellpos(
                &output_remover
                    .replace_all(
                        &output_replacer
                            .replace_all(
                                &d.1.to_value(),
                                &output_replaced_maps.values().collect_vec(),
                            )
                            .split_whitespace()
                            .join(" "),
                        &removed_replaced_maps.values().collect_vec(),
                    )
                    .split_ascii_whitespace()
                    .join(" "),
                col_pos,
            );
            let output_color_and_contents = match d.1 {
                Profile::Timestamp(_) | Profile::Level(_) | Profile::RuleTitle(_) => {
                    vec![vec![(
                        display_contents,
                        get_writable_color(level_color, no_color),
                    )]]
                }
                Profile::AllFieldInfo(_) | Profile::Details(_) | Profile::ExtraFieldInfo(_) => {
                    let mut output_str_char_pair = vec![];
                    for c in display_contents.split('¦') {
                        if let Some((field, val)) = c.split_once(':') {
                            let mut field_val_col_pair = vec![];
                            field_val_col_pair.push((
                                format!(" {}: ", field.trim()),
                                get_writable_color(Some(Color::Rgb(255, 158, 61)), no_color),
                            ));

                            field_val_col_pair.push((
                                format!(
                                    "{} ",
                                    output_remover
                                        .replace_all(
                                            &output_replacer
                                                .replace_all(
                                                    val,
                                                    &output_replaced_maps.values().collect_vec(),
                                                )
                                                .split_whitespace()
                                                .join(" "),
                                            &removed_replaced_maps.values().collect_vec(),
                                        )
                                        .split_ascii_whitespace()
                                        .join(" ")
                                ),
                                get_writable_color(Some(Color::Rgb(0, 255, 255)), no_color),
                            ));
                            output_str_char_pair.push(field_val_col_pair);
                        }
                    }
                    if output_str_char_pair.is_empty() {
                        vec![vec![(display_contents, None)]]
                    } else {
                        output_str_char_pair
                    }
                }
                _ => {
                    vec![vec![(display_contents, None)]]
                }
            };

            let col_cnt = output_color_and_contents.len();
            for (field_idx, col_contents) in output_color_and_contents.iter().enumerate() {
                for (c, color) in col_contents {
                    write_color_buffer(display_writer, *color, c, false).ok();
                }
                if field_idx != col_cnt - 1 {
                    write_color_buffer(display_writer, None, "¦", false).ok();
                }
            }

            if i != data_length - 1 {
                write_color_buffer(
                    display_writer,
                    get_writable_color(Some(Color::Rgb(255, 158, 61)), no_color),
                    "·",
                    false,
                )
                .ok();
            } else {
                // Line break after the last element of one record (plus a blank separator line).
                println!();
                println!();
            }
        }
    }
}

/// Pads a cell value with spaces according to its column position in the display output.
fn _format_cellpos(colval: &str, column: ColPos) -> String {
    match column {
        ColPos::First => format!("{colval} "),
        ColPos::Last => format!(" {colval}"),
        ColPos::Other => format!(" {colval} "),
    }
}

/// Prints the total and unique detection counts (overall and per level, with percentages) to
/// stdout, and accumulates the same information for the HTML report when enabled.
fn _print_unique_results(
    counts_by_level: &[u128],
    unique_counts_by_level: &[u128],
    head_and_tail_word: (CompactString, CompactString),
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    html_output_flag: bool,
) {
    // The counts are stored in ascending level order, but levels are displayed from highest to
    // lowest, so iterate over them in reverse.
    let mut counts_by_level_rev = counts_by_level.iter().rev();
    let mut unique_counts_by_level_rev = unique_counts_by_level.iter().rev();

    let total_count = counts_by_level.iter().sum::<u128>();
    let unique_total_count = unique_counts_by_level.iter().sum::<u128>();
    // Output the totals across all levels first.
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        None,
        &format!(
            "{} {}: {} | {}",
            head_and_tail_word.0,
            head_and_tail_word.1,
            total_count.to_formatted_string(&Locale::en),
            unique_total_count.to_formatted_string(&Locale::en)
        ),
        true,
    )
    .ok();

    let mut total_detect_md = vec!["- Total detections:".to_string()];
    let mut unique_detect_md = vec!["- Unique detections:".to_string()];

    for level_name in LEVEL::iter().rev() {
        if level_name == LEVEL::UNDEFINED {
            continue;
        }
        let count_by_level = *counts_by_level_rev.next().unwrap();
        let unique_count_by_level = *unique_counts_by_level_rev.next().unwrap();
        let percent = if total_count == 0 {
            0 as f64
        } else {
            (count_by_level as f64) / (total_count as f64) * 100.0
        };
        let unique_percent = if unique_total_count == 0 {
            0 as f64
        } else {
            (unique_count_by_level as f64) / (unique_total_count as f64) * 100.0
        };
        if html_output_flag {
            total_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name.to_full(),
                count_by_level.to_formatted_string(&Locale::en),
                percent
            ));
            unique_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name.to_full(),
                unique_count_by_level.to_formatted_string(&Locale::en),
                unique_percent
            ));
        }
        let output_raw_str = format!(
            "{} {} {}: {} ({:.2}%) | {} ({:.2}%)",
            head_and_tail_word.0,
            level_name.to_full(),
            head_and_tail_word.1,
            count_by_level.to_formatted_string(&Locale::en),
            percent,
            unique_count_by_level.to_formatted_string(&Locale::en),
            unique_percent
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            _get_output_color(color_map, &level_name),
            &output_raw_str,
            true,
        )
        .ok();
    }
    if html_output_flag {
        html_output_stock.extend(total_detect_md.iter());
        html_output_stock.extend(unique_detect_md.iter());
    }
}

/// Output the date with the highest detection count for each level.
fn _print_detection_summary_by_date(
    detect_counts_by_date: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let output_header = "Dates with most total detections:";
    write_color_buffer(&buf_wtr, None, output_header, true).ok();

    if stored_static.html_report_flag {
        html_output_stock.push(format!("- {output_header}"));
    }
    for (i, level) in LEVEL::iter().rev().enumerate() {
        if level == LEVEL::UNDEFINED {
            continue;
        }
        // An inner map was inserted for every level when AfterfactInfo was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_day = detect_counts_by_date.get(&level).unwrap();
        let mut max_detect_str = CompactString::default();
        let mut max_date: Option<&CompactString> = None;
        let mut tmp_cnt: i128 = 0;
        let mut exist_max_data = false;
        for (date, cnt) in detections_by_day {
            // On a tie, pick the lexicographically-smallest date string so the
            // choice is deterministic rather than HashMap-iteration-dependent.
            // (The key is the already-formatted date, so this is lexical, not
            // necessarily chronological under non-ISO date formats — fine, since
            // only determinism matters here.)
            if *cnt > tmp_cnt || (*cnt == tmp_cnt && exist_max_data && Some(date) < max_date) {
                exist_max_data = true;
                max_date = Some(date);
                tmp_cnt = *cnt;
            }
        }
        if let Some(date) = max_date {
            max_detect_str =
                format!("{} ({})", date, tmp_cnt.to_formatted_string(&Locale::en)).into();
        }
        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, &level)))
            .ok();
        if !exist_max_data {
            max_detect_str = "n/a".into();
        }
        let output_str = format!("{}: {}", level.to_full(), &max_detect_str);
        write!(wtr, "{output_str}").ok();
        // Print a ", " separator after every level except the last displayed one (count() - 2
        // because UNDEFINED, the final item of the reversed iteration, is skipped).
        if i != LEVEL::iter().count() - 2 {
            wtr.set_color(ColorSpec::new().set_fg(None)).ok();
            write!(wtr, ", ").ok();
        }
        if stored_static.html_report_flag {
            html_output_stock.push(format!("    - {output_str}"));
        }
    }
    buf_wtr.print(&wtr).ok();
}

/// Output the top 5 computers with the most unique detections for each level (the HTML report
/// gets the full list).
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    writeln!(wtr, "Top 5 computers with most unique detections:").ok();
    for level in LEVEL::iter().rev() {
        if level == LEVEL::UNDEFINED {
            continue;
        }
        // An inner map was inserted for every level when AfterfactInfo was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_computer = detect_counts_by_computer.get(&level).unwrap();
        let mut result_vec = Nested::<String>::new();
        // Exclude entries where the computer name is "-" from the aggregation.
        let mut sorted_detections: Vec<(&CompactString, &i128)> = detections_by_computer
            .iter()
            .filter(|a| a.0.as_str() != "-")
            .collect();

        // Sort by count descending, then by name ascending so equal-count
        // entries have a deterministic (rather than HashMap-iteration-dependent)
        // order.
        sorted_detections.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        // For HTML output, display all computer names.
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### Computers with most unique {} detections: {{#computers_with_most_unique_{}_detections}}",
                level.to_full(),
                level.to_full(),
            ));
            for x in sorted_detections.iter() {
                html_output_stock.push(format!(
                    "- {} ({})",
                    html_escape_value(x.0),
                    x.1.to_formatted_string(&Locale::en)
                ));
            }
            html_output_stock.push("");
        }
        for x in sorted_detections.iter().take(5) {
            result_vec.push(format!(
                "{} ({})",
                x.0,
                x.1.to_formatted_string(&Locale::en)
            ));
        }
        let result_str = if result_vec.is_empty() {
            "n/a".to_string()
        } else {
            result_vec.iter().collect::<Vec<_>>().join(", ")
        };

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, &level)))
            .ok();
        writeln!(wtr, "{}: {}", level.to_full(), &result_str).ok();
    }
    buf_wtr.print(&wtr).ok();
}

/// Output the rules with the most detections for each level in table format (top 5 per level;
/// the HTML report gets the full list). Rule titles longer than `limit_num` characters are
/// truncated with "...".
fn _print_detection_summary_tables(
    detect_counts_by_rule_and_level: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    (rule_title_path_map, rule_detect_author_map): (
        &HashMap<CompactString, CompactString>,
        &HashMap<CompactString, CompactString>,
    ),
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
    limit_num: usize,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let mut output = vec![];
    let mut col_color = vec![];
    for level in LEVEL::iter().rev() {
        if level == LEVEL::UNDEFINED {
            continue;
        }

        let mut col_output: Nested<String> = Nested::<String>::new();
        col_output.push(format!("Top {} alerts:", level.to_full()));

        col_color.push(_get_table_color(color_map, &level));

        // An inner map was inserted for every level when AfterfactInfo was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_computer = detect_counts_by_rule_and_level.get(&level).unwrap();
        let mut sorted_detections: Vec<(&CompactString, &i128)> =
            detections_by_computer.iter().collect();

        // Sort by count descending, then by name ascending so equal-count
        // entries have a deterministic (rather than HashMap-iteration-dependent)
        // order.
        sorted_detections.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        // For HTML output, list every rule rather than only the top five.
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### All {} alerts: {{#all_{}_alerts}}",
                level.to_full(),
                level.to_full()
            ));
            let rule_path = stored_static.output_option.as_ref().unwrap().rules.clone();
            let rule_encoded =
                check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "encoded_rules.yml", true)
                    .unwrap();
            let is_encoded_rule = rule_encoded.exists() && rule_encoded.to_path_buf() == rule_path;
            for x in sorted_detections.iter() {
                let not_found_str = CompactString::from_str("<Not Found Path>").unwrap();
                let rule_path = rule_title_path_map.get(x.0).unwrap_or(&not_found_str);
                if is_encoded_rule {
                    html_output_stock.push(format!(
                        "- {} ({}) - {}",
                        html_escape_value(x.0),
                        x.1.to_formatted_string(&Locale::en),
                        html_escape_value(
                            rule_detect_author_map
                                .get(rule_path)
                                .unwrap_or(&not_found_str)
                        )
                    ));
                } else {
                    html_output_stock.push(format!(
                        "- [{}]({}) ({}) - {}",
                        html_escape_value(x.0),
                        &rule_path.replace('\\', "/"),
                        x.1.to_formatted_string(&Locale::en),
                        html_escape_value(
                            rule_detect_author_map
                                .get(rule_path)
                                .unwrap_or(&not_found_str)
                        )
                    ));
                }
            }
            html_output_stock.push("");
        }

        let take_cnt = 5;
        for x in sorted_detections.iter().take(take_cnt) {
            let output_title = if x.0.len() > limit_num - 3 {
                format!("{}...", &x.0[..(limit_num - 3)])
            } else {
                x.0.to_string()
            };
            col_output.push(format!(
                "{output_title} ({})",
                x.1.to_formatted_string(&Locale::en)
            ));
        }
        let na_cnt = if sorted_detections.len() > take_cnt {
            0
        } else {
            take_cnt - sorted_detections.len()
        };
        for _x in 0..na_cnt {
            col_output.push("n/a");
        }
        output.push(col_output);
    }

    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    let horizontal_line_char = tb.style(TableComponent::HorizontalLines).unwrap();
    let top_border_char = tb.style(TableComponent::TopBorder).unwrap();
    for x in 0..output.len() / 2 {
        tb.add_row(vec![
            Cell::new(&output[2 * x][0]).fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(&output[2 * x + 1][0])
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ])
        .set_style(TableComponent::MiddleIntersections, horizontal_line_char)
        .set_style(TableComponent::TopBorderIntersections, top_border_char)
        .set_style(
            TableComponent::BottomBorderIntersections,
            horizontal_line_char,
        );
        tb.add_row(vec![
            Cell::new(output[2 * x].iter().skip(1).join("\n"))
                .fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(output[2 * x + 1].iter().skip(1).join("\n"))
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ]);
    }
    println!("{tb}");
}

/// Converts the given datetime to epoch seconds. Unless UTC or ISO 8601 output was requested,
/// the local UTC offset is added so the value reflects local wall-clock time.
fn _get_timestamp(output_option: &TimeFormatOptions, time: &DateTime<Utc>) -> i64 {
    if output_option.utc || output_option.iso_8601 {
        time.timestamp()
    } else {
        let offset_sec = Local
            .timestamp_opt(0, 0)
            .unwrap()
            .offset()
            .local_minus_utc();
        offset_sec as i64 + time.with_timezone(&Local).timestamp()
    }
}

/// Splits the value into its elements for the profile members that are output as JSON arrays or
/// objects: MitreTactics/MitreTags/OtherTags (": "-separated) and Details/AllFieldInfo/
/// ExtraFieldInfo (" ¦ "-separated key-value pairs). Returns an empty Vec for everything else,
/// and also for a details value that is a single element with no "key: value" structure.
fn _get_json_vec(profile: &Profile, target_data: &String) -> Vec<String> {
    match profile {
        Profile::MitreTactics(_) | Profile::MitreTags(_) | Profile::OtherTags(_) => {
            target_data.split(": ").map(|x| x.to_string()).collect()
        }
        Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
            let ret: Vec<String> = target_data.split(" ¦ ").map(|x| x.to_string()).collect();
            if target_data == &ret[0] && !utils::contains_str(target_data, ": ") {
                vec![]
            } else {
                ret
            }
        }
        _ => vec![],
    }
}

/// Formats one key/value pair as a JSON fragment (`"key": value`), indenting it with
/// `space_cnt` spaces. Values that parse as integers or booleans are emitted unquoted;
/// `concat_flag` marks values that are already valid JSON (arrays/objects/pre-quoted strings)
/// and must not be wrapped in quotes again. Control characters are replaced on both key and
/// value via CONTROL_CHAR_REPLACE_MAP.
fn _create_json_output_format(
    key: &str,
    value: &str,
    key_quote_exclude_flag: bool,
    concat_flag: bool,
    space_cnt: usize,
) -> String {
    let head = if key_quote_exclude_flag {
        key.chars()
            .map(|x| {
                if let Some(c) = CONTROL_CHAR_REPLACE_MAP.get(&x) {
                    c.to_string()
                } else {
                    String::from(x)
                }
            })
            .collect::<CompactString>()
    } else {
        format!("\"{key}\"")
            .chars()
            .map(|x| {
                if let Some(c) = CONTROL_CHAR_REPLACE_MAP.get(&x) {
                    c.to_string()
                } else {
                    String::from(x)
                }
            })
            .collect::<CompactString>()
    };
    // The indent is space_cnt spaces: 4 for top-level JSON keys, 8 for nested keys.
    if let Ok(i) = i64::from_str(value) {
        format!("{}{}: {}", " ".repeat(space_cnt), head, i)
    } else if let Ok(b) = bool::from_str(value) {
        format!("{}{}: {}", " ".repeat(space_cnt), head, b)
    } else if concat_flag {
        format!(
            "{}{}: {}",
            " ".repeat(space_cnt),
            head,
            value
                .chars()
                .map(|x| {
                    if let Some(c) = CONTROL_CHAR_REPLACE_MAP.get(&x) {
                        c.to_string()
                    } else {
                        String::from(x)
                    }
                })
                .collect::<CompactString>()
        )
    } else {
        format!(
            "{}{}: \"{}\"",
            " ".repeat(space_cnt),
            head,
            value
                .chars()
                .map(|x| {
                    if let Some(c) = CONTROL_CHAR_REPLACE_MAP.get(&x) {
                        c.to_string()
                    } else {
                        String::from(x)
                    }
                })
                .collect::<CompactString>()
        )
    }
}

/// Escapes a string value (joining multi-part "key: value" input as needed) so it can be
/// embedded in the JSON output without producing invalid JSON.
fn _convert_valid_json_str(input: &[&str], concat_flag: bool) -> String {
    let joined_value = if input.len() == 1 {
        input[0].to_string()
    } else if concat_flag {
        input.join(": ")
    } else {
        input[1..].join(": ")
    };
    let char_cnt = joined_value.char_indices().count();
    if char_cnt == 0 {
        joined_value
    } else if joined_value.starts_with('\"') {
        // The value already starts with a quote, so no opening quote is prepended here; only a
        // closing quote is added when the value does not already end with one.
        let addition_quote = if !joined_value.ends_with('\"') && concat_flag {
            "\""
        } else if !joined_value.ends_with('\"') {
            "\\\""
        } else {
            ""
        };
        let escaped = joined_value
            .replace('🛂', "\\")
            .replace('\\', "\\\\")
            .replace('\"', "\\\"");
        [escaped.as_str(), addition_quote].join("")
    } else {
        joined_value
            .replace('🛂', "\\")
            .replace('\\', "\\\\")
            .replace('\"', "\\\"")
    }
}

/// Builds the JSON object body for one detection. Returns the body string (without the
/// surrounding braces, which the caller adds) together with the updated previous-record field
/// map used for duplicate-data suppression on the next record.
pub fn output_json_str(
    detect_info: &DetectInfo,
    afterfact_info: &mut AfterfactInfo,
    jsonl_output_flag: bool,
    is_included_geo_ip: bool,
    remove_duplicate_flag: bool,
) -> (String, HashMap<CompactString, Profile>) {
    let mut target: Vec<String> = vec![];
    let mut target_ext_field = Vec::new();
    let ext_field_map: HashMap<CompactString, Profile> =
        HashMap::from_iter(detect_info.output_fields.to_owned());
    let mut next_prev_message = afterfact_info.prev_message.clone();
    if remove_duplicate_flag {
        for (field_name, profile) in detect_info.output_fields.iter() {
            match profile {
                Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                    let details_key = match profile {
                        Profile::Details(_) => "Details",
                        Profile::AllFieldInfo(_) => "AllFieldInfo",
                        Profile::ExtraFieldInfo(_) => "ExtraFieldInfo",
                        _ => "",
                    };

                    let empty = vec![];
                    let now = detect_info
                        .details_convert_map
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let prev = afterfact_info
                        .prev_details_convert_map
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let dup_flag = (!profile.to_value().is_empty()
                        && afterfact_info
                            .prev_message
                            .get(field_name)
                            .unwrap_or(&Profile::Literal("".into()))
                            .to_value()
                            == profile.to_value())
                        || (!&now.is_empty() && !&prev.is_empty() && now == prev);
                    if dup_flag {
                        // Duplicate of the previous record: output the plain string "DUP"
                        // instead of the value (Profile::Literal emits it as-is). The previous
                        // message is intentionally NOT updated, so consecutive duplicates keep
                        // being compared against the last non-duplicate value.
                        target_ext_field.push((field_name.clone(), Profile::Literal("DUP".into())));
                    } else {
                        // Not a duplicate: remember this value for comparison with the next
                        // record.
                        next_prev_message.insert(field_name.clone(), profile.clone());
                        target_ext_field.push((field_name.clone(), profile.clone()));
                    }
                }
                _ => {
                    target_ext_field.push((field_name.clone(), profile.clone()));
                }
            }
        }
    } else {
        target_ext_field.clone_from(&detect_info.output_fields);
    }
    // GeoIP enrichment fields that are folded into the Details (and AllFieldInfo) objects of
    // the JSON output instead of being emitted as top-level keys.
    let key_add_to_details = [
        "SrcASN",
        "SrcCountry",
        "SrcCity",
        "TgtASN",
        "TgtCountry",
        "TgtCity",
    ];

    let valid_key_add_to_details: Vec<&str> = key_add_to_details
        .iter()
        .filter(|target_key| {
            let target = ext_field_map.get(&CompactString::from(**target_key));
            target.is_some() && target.unwrap().to_value() != "-"
        })
        .copied()
        .collect();
    for (key, profile) in target_ext_field.iter() {
        let val = profile.to_value();
        if !matches!(
            profile,
            Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_)
        ) && val.is_empty()
        {
            continue;
        }
        let vec_data = _get_json_vec(profile, &val.to_string());
        if (!key_add_to_details.contains(&key.as_str())
            && !matches!(
                profile,
                Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_)
            ))
            && vec_data.is_empty()
        {
            if matches!(profile, Profile::Details(_)) && val == "-" {
                target.push(format!("{}\"{}\": {{}}", " ".repeat(4), key));
                continue;
            }
            let tmp_val: Vec<&str> = val.split(": ").collect();
            let output_val =
                _convert_valid_json_str(&tmp_val, matches!(profile, Profile::AllFieldInfo(_)));
            target.push(_create_json_output_format(
                key,
                output_val.trim(),
                key.starts_with('\"'),
                output_val.starts_with('\"'),
                4,
            ));
        } else {
            match profile {
                // GeoIP profile fields are skipped here because they are emitted inside the
                // Details/AllFieldInfo sections instead (see the key_add_to_details handling
                // below).
                Profile::SrcASN(_)
                | Profile::SrcCountry(_)
                | Profile::SrcCity(_)
                | Profile::TgtASN(_)
                | Profile::TgtCountry(_)
                | Profile::TgtCity(_) => continue,
                Profile::RecoveredRecord(data) => {
                    target.push(_create_json_output_format(
                        "RecoveredRecord",
                        data,
                        false,
                        data.starts_with('\"'),
                        4,
                    ));
                }
                Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                    let mut output_stock: Vec<String> = vec![];
                    let details_key = match profile {
                        Profile::Details(_) => "Details",
                        Profile::AllFieldInfo(_) => "AllFieldInfo",
                        Profile::ExtraFieldInfo(_) => "ExtraFieldInfo",
                        _ => "",
                    };
                    let details_target_stocks = detect_info
                        .details_convert_map
                        .get(&CompactString::from(format!("#{details_key}")));
                    if details_target_stocks.is_none() {
                        continue;
                    }
                    let details_target_stock = details_target_stocks.unwrap();
                    let mut children_output_stock: HashMap<CompactString, Vec<CompactString>> =
                        HashMap::new();
                    let mut children_output_order = vec![];
                    if detect_info.agg_result.is_some() {
                        if details_target_stock.is_empty() || details_target_stock[0] == "-" {
                            output_stock.push(format!("{}\"{}\": {{}}", " ".repeat(4), key));
                            if jsonl_output_flag {
                                target.push(output_stock.join(""));
                            } else {
                                target.push(output_stock.join("\n"));
                            }
                            continue;
                        }
                        let split_agg_details = details_target_stock[0]
                            .split(" ¦ ")
                            .map(|x| x.into())
                            .collect_vec();
                        process_target_stock(
                            &split_agg_details,
                            &mut children_output_stock,
                            &mut children_output_order,
                        );
                    } else if details_target_stock.is_empty() {
                        output_stock.push(format!("{}\"{}\": {{}}", " ".repeat(4), key));
                        if jsonl_output_flag {
                            target.push(output_stock.join(""));
                        } else {
                            target.push(output_stock.join("\n"));
                        }
                        continue;
                    } else {
                        process_target_stock(
                            details_target_stock,
                            &mut children_output_stock,
                            &mut children_output_order,
                        );
                    }
                    output_stock.push(format!("    \"{key}\": {{"));

                    // Rebuild the field order to match the order in which the fields appear in
                    // the rule (recorded in children_output_order), since HashMap iteration
                    // order is arbitrary.
                    let mut sorted_children_output_stock: Vec<(
                        &CompactString,
                        &Vec<CompactString>,
                    )> = children_output_stock.iter().collect_vec();
                    for (k, v) in children_output_stock.iter() {
                        let index_in_rule =
                            children_output_order.iter().position(|x| x == k).unwrap();
                        sorted_children_output_stock[index_in_rule] = (k, v);
                    }
                    for (idx, (c_key, c_val)) in sorted_children_output_stock.iter().enumerate() {
                        let fmted_c_val = if c_val.len() == 1 {
                            c_val[0].to_string()
                        } else {
                            format!(
                                "[{}]",
                                c_val.iter().map(|x| { format!("\"{x}\"") }).join(", ")
                            )
                        };
                        if idx != children_output_stock.len() - 1 {
                            output_stock.push(format!(
                                "{},",
                                _create_json_output_format(
                                    c_key,
                                    &fmted_c_val,
                                    c_key.starts_with('\"'),
                                    fmted_c_val.starts_with('\"') || c_val.len() != 1,
                                    8
                                )
                            ));
                        } else {
                            let last_contents_end = if is_included_geo_ip
                                && !matches!(profile, Profile::ExtraFieldInfo(_))
                                && !valid_key_add_to_details.is_empty()
                            {
                                ","
                            } else {
                                ""
                            };
                            output_stock.push(format!(
                                "{}{last_contents_end}",
                                _create_json_output_format(
                                    c_key,
                                    &fmted_c_val,
                                    c_key.starts_with('\"'),
                                    fmted_c_val.starts_with('\"') || c_val.len() != 1,
                                    8,
                                )
                            ));
                        }
                    }
                    if is_included_geo_ip && !matches!(profile, Profile::ExtraFieldInfo(_)) {
                        for (geo_ip_field_cnt, target_key) in
                            valid_key_add_to_details.iter().enumerate()
                        {
                            let val = ext_field_map
                                .get(&CompactString::from(*target_key))
                                .unwrap()
                                .to_value();
                            let output_end_fmt =
                                if geo_ip_field_cnt == valid_key_add_to_details.len() - 1 {
                                    ""
                                } else {
                                    ","
                                };
                            output_stock.push(format!(
                                "{}{output_end_fmt}",
                                _create_json_output_format(
                                    target_key,
                                    &val,
                                    target_key.starts_with('\"'),
                                    val.starts_with('\"'),
                                    8
                                )
                            ));
                        }
                    }
                    output_stock.push("    }".to_string());
                    if jsonl_output_flag {
                        target.push(output_stock.join(""));
                    } else {
                        target.push(output_stock.join("\n"));
                    }
                }
                Profile::MitreTags(_) | Profile::MitreTactics(_) | Profile::OtherTags(_) => {
                    let key = _convert_valid_json_str(&[key.as_str()], false);
                    let values = val.split(": ").filter(|x| x.trim() != "");
                    let values_len = values.clone().count();
                    if values_len == 0 {
                        continue;
                    }
                    let mut value: Vec<String> = vec![];
                    for (idx, tag_val) in values.enumerate() {
                        if idx == 0 {
                            value.push("[\n".to_string());
                        }
                        let insert_val = format!(
                            "        \"{}\"",
                            tag_val.split('¦').map(|x| x.trim()).join("\", \"")
                        );
                        value.push(insert_val);
                        if idx != values_len - 1 {
                            value.push(",\n".to_string());
                        }
                    }
                    value.push("\n    ]".to_string());

                    let fmted_val = if jsonl_output_flag {
                        value.iter().map(|x| x.replace('\n', "")).join("")
                    } else {
                        value.join("")
                    };
                    target.push(_create_json_output_format(
                        &key,
                        fmted_val.trim(),
                        key.starts_with('\"'),
                        true,
                        4,
                    ));
                }
                _ => {}
            }
        }
    }
    if jsonl_output_flag {
        // JSONL output
        (
            target.into_iter().map(|x| x.replace("  ", "")).join(","),
            next_prev_message,
        )
    } else {
        // JSON format output
        (target.join(",\n"), next_prev_message)
    }
}

/// Splits each "key: value" detail entry and groups the values by key in
/// `children_output_stock` (a key gets multiple values when it appears more than once, e.g.
/// Data[1]/Data[2] fields), recording first-seen key order in `children_output_order`.
fn process_target_stock(
    details_target_stock: &[CompactString],
    children_output_stock: &mut HashMap<CompactString, Vec<CompactString>>,
    children_output_order: &mut Vec<CompactString>,
) {
    for contents in details_target_stock.iter() {
        let (key, value) = contents.split_once(':').unwrap_or_default();
        let output_key = _convert_valid_json_str(&[key.trim()], false);
        let fmted_val = _convert_valid_json_str(&[value.trim()], false);
        if let RawEntryMut::Vacant(_) = children_output_stock
            .raw_entry_mut()
            .from_key(output_key.as_str())
        {
            children_output_order.push(output_key.clone().into());
        }
        children_output_stock
            .entry(output_key.into())
            .or_insert(vec![])
            .push(fmted_val.into());
    }
}
/// Prints a table of the detected rule authors and the number of their rules that produced
/// detections, laid out over `table_column_num` columns.
fn output_detected_rule_authors(
    rule_author_counter: &HashMap<CompactString, i128>,
    table_column_num: usize,
) {
    let mut sorted_authors: Vec<(&CompactString, &i128)> = rule_author_counter.iter().collect();

    // Count descending, then author name ascending for a deterministic order
    // among equal-count authors.
    sorted_authors.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let authors_num = sorted_authors.len();
    let div = if authors_num <= table_column_num {
        1
    } else if !authors_num.is_multiple_of(4) {
        authors_num / table_column_num + 1
    } else {
        authors_num / table_column_num
    };
    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    let mut stored_by_column = vec![];
    let horizontal_line_char = tb.style(TableComponent::HorizontalLines).unwrap();
    let top_border_char = tb.style(TableComponent::TopBorder).unwrap();
    for x in 0..table_column_num {
        let mut tmp = Vec::new();
        for y in 0..div {
            if y * table_column_num + x < sorted_authors.len() {
                // Limit length to 27 to prevent the table from wrapping
                let filter_author = if sorted_authors[y * table_column_num + x].0.len() <= 27 {
                    sorted_authors[y * table_column_num + x].0.to_string()
                } else {
                    format!("{}...", &sorted_authors[y * table_column_num + x].0[0..24])
                };
                tmp.push(format!(
                    "{} ({})",
                    filter_author,
                    sorted_authors[y * table_column_num + x].1
                ));
            }
        }
        if !tmp.is_empty() {
            stored_by_column.push(tmp);
        }
    }
    let mut output = vec![];
    for col_data in stored_by_column {
        output.push(col_data.join("\n"));
    }
    if !output.is_empty() {
        tb.add_row(output)
            .set_style(TableComponent::MiddleIntersections, horizontal_line_char)
            .set_style(TableComponent::TopBorderIntersections, top_border_char)
            .set_style(
                TableComponent::BottomBorderIntersections,
                horizontal_line_char,
            );
    }
    println!("{tb}");
}

/// Extracts the individual author names from a rule's author string and returns them as an
/// array.
fn extract_author_name(author: &str) -> Nested<String> {
    let mut ret = Nested::<String>::new();
    for author in author.split(',').map(|s| {
        // Keep only the part before '(': a parenthesized remark after a name is a description,
        // not part of the name. Double and single quotes are stripped from the names below.
        s.split('(').next().unwrap_or_default().to_string()
    }) {
        ret.extend(author.split(';'));
    }

    ret.iter()
        .map(|r| {
            r.split('/')
                .map(|p| p.trim().replace(['"', '\''], ""))
                .collect::<String>()
        })
        .collect()
}

/// Appends to `html_output_stock` a Markdown table of computer names and the MITRE ATT&CK
/// tactics detected on them (with unique and total counts), for the HTML report.
fn _output_html_computer_by_mitre_attck(html_output_stock: &mut Nested<String>) {
    html_output_stock.push("### MITRE ATT&CK Tactics:{#computers_with_mitre_attck_detections}");
    if COMPUTER_MITRE_ATTCK_MAP.is_empty() {
        html_output_stock.push("- No computers were detected with MITRE ATT&CK Tactics.<br>Make sure you run Hayabusa with a profile that includes %MitreTactics% in order to get this info.<br>");
    }
    for (idx, sorted_output_map) in COMPUTER_MITRE_ATTCK_MAP
        .iter()
        .sorted_by(|a, b| {
            Ord::cmp(
                &format!("{}-{}", &b.value()[b.value().len() - 1].0, b.key()),
                &format!("{}-{}", &a.value()[a.value().len() - 1].0, a.key()),
            )
        })
        .enumerate()
    {
        if idx == 0 {
            html_output_stock.push("|Computer| MITRE ATT&CK Tactics|");
            html_output_stock.push("|---|---|");
        }
        html_output_stock.push(format!(
            "|{}|{}|",
            html_escape_value(sorted_output_map.key()),
            sorted_output_map
                .value()
                .iter()
                .map(|(tactic, unique, total)| format!("{} ({} &#124; {})", tactic, unique, total))
                .collect::<Vec<_>>()
                .join("<br>")
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{read_to_string, remove_file};
    use std::path::Path;

    use chrono::NaiveDateTime;
    use chrono::{DateTime, Local, TimeZone, Utc};
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use serde_json::Value;

    use crate::afterfact::_convert_valid_json_str;
    use crate::afterfact::_print_unique_results;
    use crate::afterfact::AfterfactInfo;
    use crate::afterfact::format_time;
    use crate::afterfact::get_duplicate_indices;
    use crate::afterfact::html_escape_value;
    use crate::afterfact::init_writer;
    use crate::afterfact::output_afterfact_inner;
    use crate::afterfact::sort_detect_info;
    use crate::detections::configs::Action;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::JSONOutputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::{TimeFormatOptions, load_eventkey_alias};
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::detections::message;
    use crate::detections::message::DetectInfo;
    use crate::detections::utils;
    use crate::level::LEVEL;
    use crate::options::profile::{Profile, load_profile};

    #[test]
    fn test_print_unique_results_percentages_align_with_levels() {
        // The count arrays are indexed by LEVEL::index():
        // [undefined, informational, low, medium, high, critical, emergency].
        // Both arrays are deliberately asymmetric so every level has a distinct
        // percentage; with the reversed-index regression (#1812) the critical row
        // would show informational's percentage and vice versa.
        let counts_by_level: Vec<u128> = vec![0, 60, 15, 30, 24, 21, 0]; // total 150
        let unique_counts_by_level: Vec<u128> = vec![0, 5, 4, 3, 2, 1, 0]; // total 15
        let mut html_output_stock = nested::Nested::<String>::new();
        _print_unique_results(
            &counts_by_level,
            &unique_counts_by_level,
            (
                CompactString::from("Total"),
                CompactString::from("detections"),
            ),
            &crate::level::create_output_color_map(true),
            &mut html_output_stock,
            true,
        );
        let lines: Vec<&str> = html_output_stock.iter().collect();
        let expected = vec![
            "- Total detections:",
            "    - emergency: 0 (0.00%)",
            "    - critical: 21 (14.00%)",
            "    - high: 24 (16.00%)",
            "    - medium: 30 (20.00%)",
            "    - low: 15 (10.00%)",
            "    - informational: 60 (40.00%)",
            "- Unique detections:",
            "    - emergency: 0 (0.00%)",
            "    - critical: 1 (6.67%)",
            "    - high: 2 (13.33%)",
            "    - medium: 3 (20.00%)",
            "    - low: 4 (26.67%)",
            "    - informational: 5 (33.33%)",
        ];
        assert_eq!(lines, expected);
    }

    #[test]
    fn test_html_escape_value_neutralises_markdown_and_html() {
        // HTML special characters -> entities (blocks raw-HTML injection).
        assert_eq!(
            html_escape_value("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&#39;f"
        );
        // Markdown link syntax -> inert (brackets and parens are backslash-escaped),
        // so `[x](javascript:...)` can no longer become a clickable anchor.
        assert_eq!(html_escape_value("[x](y)"), "\\[x\\]\\(y\\)");
        // Table pipe -> escaped, so it cannot break a table row.
        assert_eq!(html_escape_value("a|b"), "a\\|b");
        // Backslash -> doubled, so it cannot escape a following character.
        assert_eq!(html_escape_value("a\\b"), "a\\\\b");
        // Ordinary text is unchanged.
        assert_eq!(html_escape_value("WORKSTATION-01"), "WORKSTATION-01");
    }

    #[test]
    fn test_report_neutralises_markdown_link_injection() {
        // End-to-end: a user value carrying Markdown link syntax with a `javascript:`
        // URL must NOT render as a clickable anchor after html_escape_value +
        // create_html (pulldown-cmark does not sanitize URL schemes).
        let mut reporter = crate::options::htmlreport::HtmlReporter::default();
        let mut data = nested::Nested::<String>::new();
        data.push(format!(
            "- {} (5)",
            html_escape_value("[x](javascript:alert(1))")
        ));
        reporter
            .section_markdown
            .insert("General Overview {#general_overview}".to_string(), data);
        let html = reporter.create_html();
        assert!(
            !html.contains("href=\"javascript:"),
            "payload must not become a javascript: link, got: {html}"
        );
        assert!(
            html.contains("[x](javascript:alert(1))"),
            "payload should render as inert literal text, got: {html}"
        );
    }

    /// `sort_detect_info` must be a total order so the `-s` output is
    /// deterministic: records equal on every primary key (here: same time/level/
    /// eventid/rule/computer/rec_id, differing only in the EvtxFile field — the
    /// overlapping-evtx-collection case) must sort to the same order regardless of
    /// their (non-deterministic) input order.
    #[test]
    fn test_sort_detect_info_deterministic_on_ties() {
        let make = |evtx: &str| DetectInfo {
            detected_time: Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
            rule_path: "rule.yml".into(),
            ruleid: "id".into(),
            ruletitle: "title".into(),
            ruleauthor: "author".into(),
            level: LEVEL::INFORMATIONAL,
            computername: "PC".into(),
            rec_id: "100".into(),
            eventid: "1".into(),
            detail: CompactString::default(),
            output_fields: vec![(
                CompactString::from("EvtxFile"),
                Profile::EvtxFile(evtx.to_string().into()),
            )],
            agg_result: None,
            details_convert_map: HashMap::default(),
        };
        let evtx_of = |d: &DetectInfo| d.output_fields[0].1.to_value();

        let mut a = vec![make("c.evtx"), make("a.evtx"), make("b.evtx")];
        let mut b = vec![make("b.evtx"), make("c.evtx"), make("a.evtx")];
        sort_detect_info(&mut a);
        sort_detect_info(&mut b);
        let a_order: Vec<_> = a.iter().map(evtx_of).collect();
        let b_order: Vec<_> = b.iter().map(evtx_of).collect();
        assert_eq!(
            a_order, b_order,
            "sort order must not depend on input order"
        );
        assert_eq!(a_order, vec!["a.evtx", "b.evtx", "c.evtx"]);
    }

    #[test]
    fn test_emit_csv_output() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer2";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
        }
        let expect =
            "\"Timestamp\",\"Computer\",\"Channel\",\"Level\",\"EventID\",\"MitreAttack\",\"RecordID\",\"RuleTitle\",\"Details\",\"RecordInformation\",\"RuleFile\",\"EvtxFile\",\"Tags\"\n\""
                .to_string()
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
                + "\",\""
                + test_computername
                + "\",\""
                + test_channel
                + "\",\""
                + test_level.to_abbrev()
                + "\","
                + test_eventid
                + ",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\""
                + output
                + "\",\""
                + test_recinfo
                + "\",\""
                + test_rule_path
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n\""
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z")
                .to_string()
                + "\",\""
                + test_computername2
                + "\",\""
                + test_channel
                + "\",\""
                + test_level.to_abbrev()
                + "\","
                + test_eventid
                + ",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\""
                + output
                + "\",\""
                + test_recinfo
                + "\",\""
                + test_rule_path
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n";

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);

        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv.csv").is_ok());
    }

    #[test]
    fn test_emit_csv_output_with_multiline_opt() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer2";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge ¦ Test1: hogetest1 ¦ Test2: hogetest2";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                profile: Some("verbose-2".to_string()),
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv_multiline.csv").to_path_buf()),
            multiline: true,
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        stored_static.profiles = Option::Some(
            load_profile(
                "test_files/config/default_profile.yaml",
                "test_files/config/profiles.yaml",
                Some(&stored_static),
            )
            .unwrap_or_default(),
        );
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge",
                            "Test1": "hogetest1",
                            "Test2": "hogetest2"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                profile: Some("verbose-2".to_string()),
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                ("AllFieldInfo", Profile::AllFieldInfo(test_recinfo.into())),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
        }
        let expect =
            "\"Timestamp\",\"Computer\",\"Channel\",\"EventID\",\"Level\",\"Tags\",\"RecordID\",\"RuleTitle\",\"Details\",\"AllFieldInfo\"\n\""
                .to_string()
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
                + "\",\""
                + test_computername
                + "\",\""
                + test_channel
                + "\","
                + test_eventid
                + ",\""
                + test_level.to_abbrev()
                + "\",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\""
                + output
                + "\",\""
                + &test_recinfo.replace(" ¦ ", "\r\n")
                + "\"\n\""
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z")
                .to_string()
                + "\",\""
                + test_computername2
                + "\",\""
                + test_channel
                + "\","
                + test_eventid
                + ",\""
                + test_level.to_abbrev()
                + "\",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\""
                + output
                + "\",\""
                + &test_recinfo.replace(" ¦ ", "\r\n")
                + "\"\n";

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv_multiline.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv_multiline.csv").is_ok());
    }

    /// A value that already starts with a quote is escaped with only a trailing quote added, and
    /// no spurious leading quote (regression guard for #1832, where the always-empty
    /// `addition_header` was removed from `_convert_valid_json_str`).
    #[test]
    fn test_convert_valid_json_str_quote_prefixed() {
        // Value starts and ends with a quote: both quotes are backslash-escaped, nothing prepended.
        assert_eq!(_convert_valid_json_str(&["\"hi\""], false), "\\\"hi\\\"");
        // Starts with a quote but does not end with one: a closing escaped quote is appended.
        assert_eq!(_convert_valid_json_str(&["\"hi"], false), "\\\"hi\\\"");
    }

    /// `get_duplicate_indices` must flag every identical copy after the first within a timestamp
    /// group, including the second of only two copies (regression test for issue #1813, where the
    /// first record of each group was never added to the comparison set so the second copy
    /// survived). Duplicates are only matched within the same timestamp, ignoring the EvtxFile
    /// column.
    #[test]
    fn test_get_duplicate_indices_flags_second_and_later_copies() {
        // A detection whose duplicate-relevant fields are `detail` (varying it makes a distinct
        // detection) and whose EvtxFile source `evtx` must be ignored when comparing.
        fn make(time: DateTime<Utc>, detail: &str, evtx: &str) -> DetectInfo {
            DetectInfo {
                detected_time: time,
                rule_path: CompactString::from("rule.yml"),
                ruleid: CompactString::from("id"),
                ruletitle: CompactString::from("title"),
                ruleauthor: CompactString::from("author"),
                level: LEVEL::HIGH,
                computername: CompactString::from("computer"),
                rec_id: CompactString::from("1"),
                eventid: CompactString::from("1"),
                detail: CompactString::default(),
                output_fields: vec![
                    (
                        CompactString::from("Details"),
                        Profile::Details(detail.to_string().into()),
                    ),
                    (
                        CompactString::from("EvtxFile"),
                        Profile::EvtxFile(evtx.to_string().into()),
                    ),
                ],
                agg_result: None,
                details_convert_map: HashMap::default(),
            }
        }

        let t1 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 1).unwrap();
        // Sorted by time, as `get_duplicate_indices` requires.
        let mut detect_infos = vec![
            make(t1, "A", "a.evtx"), // 0: first "A" in group t1 -> kept
            make(t1, "A", "b.evtx"), // 1: second "A" (differs only in EvtxFile) -> duplicate
            make(t1, "B", "c.evtx"), // 2: distinct detection -> kept
            make(t2, "A", "a.evtx"), // 3: same fields as group t1 but new timestamp -> kept
            make(t2, "A", "b.evtx"), // 4: second "A" in group t2 -> duplicate
        ];

        let dup = get_duplicate_indices(&mut detect_infos);
        let mut got: Vec<usize> = dup.into_iter().collect();
        got.sort_unstable();
        assert_eq!(got, vec![1, 4]);
    }

    #[test]
    fn test_emit_csv_output_with_remove_duplicate_opt() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer2";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                remove_duplicate_data: true,
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv_remove_duplicate.csv").to_path_buf()),
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
        }
        let expect =
            "\"Timestamp\",\"Computer\",\"Channel\",\"Level\",\"EventID\",\"MitreAttack\",\"RecordID\",\"RuleTitle\",\"Details\",\"RecordInformation\",\"RuleFile\",\"EvtxFile\",\"Tags\"\n\""
                .to_string()
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
                + "\",\""
                + test_computername
                + "\",\""
                + test_channel
                + "\",\""
                + test_level.to_abbrev()
                + "\","
                + test_eventid
                + ",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\""
                + output
                + "\",\""
                + test_recinfo
                + "\",\""
                + test_rule_path
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n\""
                + &expect_tz.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S%.3f %:z")
                .to_string()
                + "\",\""
                + test_computername2
                + "\",\""
                + test_channel
                + "\",\""
                + test_level.to_abbrev()
                + "\","
                + test_eventid
                + ",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\"DUP\",\"DUP\",\""
                + test_rule_path
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n";

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv_remove_duplicate.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv_remove_duplicate.csv").is_ok());
    }

    #[test]
    fn test_emit_json_output_with_remove_duplicate_opt() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer2";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let dummy_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                remove_duplicate_data: true,
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv_remove_duplicate.json").to_path_buf()),
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let details_convert_map: HashMap<CompactString, Vec<CompactString>> =
                HashMap::from_iter([("#AllFieldInfo".into(), vec![test_recinfo.into()])]);
            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map,
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info2 = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map: HashMap::default(),
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info2);
        }

        let expect_target = [
            vec![
                (
                    "Timestamp",
                    CompactString::from(
                        "\"".to_string()
                            + &expect_tz
                                .with_timezone(&Local)
                                .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                                .to_string()
                            + "\"",
                    ),
                ),
                (
                    "Computer",
                    CompactString::from("\"".to_string() + test_computername + "\""),
                ),
                (
                    "Channel",
                    CompactString::from("\"".to_string() + test_channel + "\""),
                ),
                (
                    "Level",
                    CompactString::from("\"".to_string() + test_level.to_abbrev() + "\""),
                ),
                ("EventID", CompactString::from(test_eventid)),
                (
                    "MitreAttack",
                    CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
                ),
                ("RecordID", CompactString::from(test_record_id)),
                (
                    "RuleTitle",
                    CompactString::from("\"".to_string() + test_title + "\""),
                ),
                (
                    "Details",
                    CompactString::from("\"".to_string() + output + "\""),
                ),
                (
                    "RecordInformation",
                    CompactString::from("{\n        \"CommandRLine\": \"hoge\"\n    }"),
                ),
                (
                    "RuleFile",
                    CompactString::from("\"".to_string() + test_rule_path + "\""),
                ),
                (
                    "EvtxFile",
                    CompactString::from("\"".to_string() + test_filepath + "\""),
                ),
                (
                    "Tags",
                    CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
                ),
            ],
            vec![
                (
                    "Timestamp",
                    CompactString::from(
                        "\"".to_string()
                            + &expect_tz
                                .with_timezone(&Local)
                                .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                                .to_string()
                            + "\"",
                    ),
                ),
                (
                    "Computer",
                    CompactString::from("\"".to_string() + test_computername2 + "\""),
                ),
                (
                    "Channel",
                    CompactString::from("\"".to_string() + test_channel + "\""),
                ),
                (
                    "Level",
                    CompactString::from("\"".to_string() + test_level.to_abbrev() + "\""),
                ),
                ("EventID", test_eventid.into()),
                (
                    "MitreAttack",
                    CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
                ),
                ("RecordID", test_record_id.into()),
                (
                    "RuleTitle",
                    CompactString::from("\"".to_string() + test_title + "\""),
                ),
                ("Details", "\"DUP\"".into()),
                ("RecordInformation", "\"DUP\"".into()),
                (
                    "RuleFile",
                    CompactString::from("\"".to_string() + test_rule_path + "\""),
                ),
                (
                    "EvtxFile",
                    CompactString::from("\"".to_string() + test_filepath + "\""),
                ),
                (
                    "Tags",
                    CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
                ),
            ],
        ];
        let mut expect_str = String::default();
        for (target_idx, target) in expect_target.iter().enumerate() {
            let mut expect_json = "{\n".to_string();
            for (idx, (key, value)) in target.iter().enumerate() {
                expect_json = expect_json + "    \"" + key + "\": " + value;
                if idx != target.len() - 1 {
                    expect_json += ",\n";
                } else {
                    expect_json += "\n";
                }
            }
            expect_json += "}";
            if target_idx != expect_target.len() - 1 {
                expect_json += "\n";
            }
            expect_str = expect_str.to_string() + &expect_json;
        }

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv_remove_duplicate.json") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect_str);
            }
        };
        assert!(remove_file("./test_emit_csv_remove_duplicate.json").is_ok());
    }

    #[test]
    fn test_emit_json_output_with_multiple_data_in_details() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge, Data: [xxx, yyy]";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let dummy_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                remove_duplicate_data: true,
                no_wizard: true,
                ..Default::default()
            },
            geo_ip: None,
            output: Some(Path::new("./test_multiple_data_in_details.json").to_path_buf()),
            jsonl_timeline: false,
            disable_abbreviations: false,
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge",
                            "Data": ["xxx", "yyy"]
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                rules: Path::new("./rules").to_path_buf(),
                remove_duplicate_data: true,
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let details_convert_map: HashMap<CompactString, Vec<CompactString>> =
                HashMap::from_iter([("#AllFieldInfo".into(), vec![test_recinfo.into()])]);
            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map,
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());
        }

        let expect_target = [vec![
            (
                "Timestamp",
                CompactString::from(
                    "\"".to_string()
                        + &expect_tz
                            .with_timezone(&Local)
                            .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                            .to_string()
                        + "\"",
                ),
            ),
            (
                "Computer",
                CompactString::from("\"".to_string() + test_computername + "\""),
            ),
            (
                "Channel",
                CompactString::from("\"".to_string() + test_channel + "\""),
            ),
            (
                "Level",
                CompactString::from("\"".to_string() + test_level.to_abbrev() + "\""),
            ),
            ("EventID", CompactString::from(test_eventid)),
            (
                "MitreAttack",
                CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
            ),
            ("RecordID", CompactString::from(test_record_id)),
            (
                "RuleTitle",
                CompactString::from("\"".to_string() + test_title + "\""),
            ),
            (
                "Details",
                CompactString::from("\"".to_string() + output + "\""),
            ),
            (
                "RecordInformation",
                CompactString::from(
                    "{\n        \"CommandRLine\": \"hoge\",\n        \"Data[1]\": \"xxx\",\n        \"Data[2]\": \"yyy\"\n    }",
                ),
            ),
            (
                "RuleFile",
                CompactString::from("\"".to_string() + test_rule_path + "\""),
            ),
            (
                "EvtxFile",
                CompactString::from("\"".to_string() + test_filepath + "\""),
            ),
            (
                "Tags",
                CompactString::from("[\n        \"".to_string() + test_attack + "\"\n    ]"),
            ),
        ]];
        let mut expect_str = String::default();
        for (target_idx, target) in expect_target.iter().enumerate() {
            let mut expect_json = "{\n".to_string();
            for (idx, (key, value)) in target.iter().enumerate() {
                expect_json = expect_json + "    \"" + key + "\": " + value;
                if idx != target.len() - 1 {
                    expect_json += ",\n";
                } else {
                    expect_json += "\n";
                }
            }
            expect_json += "}";
            if target_idx != expect_target.len() - 1 {
                expect_json += "\n";
            }
            expect_str = expect_str.to_string() + &expect_json;
        }

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_multiple_data_in_details.json") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect_str);
            }
        };
        assert!(remove_file("./test_multiple_data_in_details.json").is_ok());
    }

    #[test]
    fn test_emit_csv_json_output() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer";
        let test_eventid = "1111";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let json_dummy_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv_json.json").to_path_buf()),
            ..Default::default()
        });

        let dummy_config = Some(Config {
            action: Some(json_dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                time_format_options: TimeFormatOptions {
                    utc: true,
                    ..Default::default()
                },
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            let details_convert_map: HashMap<CompactString, Vec<CompactString>> =
                HashMap::from_iter([("#AllFieldInfo".into(), vec![test_recinfo.into()])]);
            let message_detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map,
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(message_detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());
        }
        let expect = vec![
            "{",
            "\"Timestamp\": \"1996-02-27 01:05:01.000 +00:00\",",
            "\"Computer\": \"testcomputer\",",
            "\"Channel\": \"Sec\",",
            "\"Level\": \"high\",",
            "\"EventID\": 1111,",
            "\"MitreAttack\": [\n        \"execution/txxxx.yyy\"\n    ],",
            "\"RecordID\": 11111,",
            "\"RuleTitle\": \"test_title\",",
            "\"Details\": \"pokepoke\",",
            "\"RecordInformation\": {\n        \"CommandRLine\": \"hoge\"\n    },",
            "\"RuleFile\": \"test-rule.yml\",",
            "\"EvtxFile\": \"test.evtx\",",
            "\"Tags\": [\n        \"execution/txxxx.yyy\"\n    ]",
        ];

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv_json.json") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, format!("{}\n}}", expect.join("\n    ")));
            }
        };
        assert!(remove_file("./test_emit_csv_json.json").is_ok());
    }

    #[test]
    fn test_emit_csv_jsonl_output() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mut detect_infos = vec![];
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
            false,
        );
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = LEVEL::HIGH;
        let test_computername = "testcomputer";
        let test_computername2 = "testcomputer";
        let test_eventid = "1111";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "CommandRLine: hoge";
        let test_record_id = "11111";
        let expect_naivetime =
            NaiveDateTime::parse_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let expect_time = Utc.from_local_datetime(&expect_naivetime).unwrap();
        let expect_tz = expect_time.with_timezone(&Utc);
        let json_dummy_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv_jsonl.jsonl").to_path_buf()),
            jsonl_timeline: true,
            ..Default::default()
        });

        let dummy_config = Some(Config {
            action: Some(json_dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        let output_profile: Vec<(CompactString, Profile)> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
            Some(&stored_static),
        )
        .unwrap_or_default();
        {
            let val = r#"
                {
                    "Event": {
                        "EventData": {
                            "CommandRLine": "hoge"
                        },
                        "System": {
                            "TimeCreated_attributes": {
                                "SystemTime": "1996-02-27T01:05:01Z"
                            }
                        }
                    }
                }
            "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let output_option = OutputOption {
                min_level: "informational".to_string(),
                time_format_options: TimeFormatOptions {
                    utc: true,
                    ..Default::default()
                },
                no_wizard: true,
                ..Default::default()
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(
                        format_time(&expect_time, false, &output_option.time_format_options).into(),
                    ),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level("high".into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rule_path.into())),
                ("EvtxFile", Profile::EvtxFile(test_filepath.into())),
                ("Tags", Profile::MitreTags(test_attack.into())),
            ]);
            let details_convert_map: HashMap<CompactString, Vec<CompactString>> =
                HashMap::from_iter([("#AllFieldInfo".into(), vec![test_recinfo.into()])]);
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );

            let message_detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rule_path: CompactString::from(test_rule_path),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    ruleauthor: CompactString::from("test_author"),
                    level: test_level.clone(),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    output_fields: output_profile.to_owned(),
                    agg_result: None,
                    details_convert_map,
                    rec_id: CompactString::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            detect_infos.push(message_detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());
        }
        let expect = vec![
            "{ ",
            "\"Timestamp\": \"1996-02-27 01:05:01.000 +00:00\",",
            "\"Computer\": \"testcomputer\",",
            "\"Channel\": \"Sec\",",
            "\"Level\": \"high\",",
            "\"EventID\": 1111,",
            "\"MitreAttack\": [\"execution/txxxx.yyy\"],",
            "\"RecordID\": 11111,",
            "\"RuleTitle\": \"test_title\",",
            "\"Details\": \"pokepoke\",",
            "\"RecordInformation\": {\"CommandRLine\": \"hoge\"},",
            "\"RuleFile\": \"test-rule.yml\",",
            "\"EvtxFile\": \"test.evtx\",",
            "\"Tags\": [\"execution/txxxx.yyy\"]",
        ];

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.timeline_start_time = Some(expect_tz);
        additional_afterfact.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_afterfact_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut additional_afterfact,
            )
            .is_ok()
        );
        match read_to_string("./test_emit_csv_jsonl.jsonl") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, format!("{} }}", expect.join("")));
            }
        };
        assert!(remove_file("./test_emit_csv_jsonl.jsonl").is_ok());
    }
}

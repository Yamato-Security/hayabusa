use std::cmp::Ordering;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process;

use ::csv::{QuoteStyle, Writer, WriterBuilder};
use chrono::{DateTime, Local, TimeZone, Utc};
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use strum::IntoEnumIterator;
use termcolor::{Buffer, BufferWriter, ColorChoice, ColorSpec, WriteColor};

use crate::detections::configs::{Action, StoredStatic, TimeFormatOptions};
use crate::detections::message::{AlertMessage, DetectInfo};

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
pub(crate) fn html_escape_value(s: &str) -> String {
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
use crate::level::LEVEL;
use crate::options::profile::Profile;

mod csv;
mod display;
mod html_stock;
mod json;
mod summary;

use csv::emit_csv_inner;
use summary::calc_statistic_info;

pub use csv::emit_csv;
pub use json::output_json_str;
pub use summary::output_result_summary;

#[cfg(test)]
pub(crate) use crate::detections::utils::format_time;
#[cfg(test)]
pub(crate) use json::{close_unterminated_quote, json_scalar, json_string};
#[cfg(test)]
pub(crate) use summary::_print_unique_results;

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
pub struct ResultOutputState {
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
/// `ResultOutputState::default`.
struct InitLevelMapResult(
    HashMap<LEVEL, HashMap<CompactString, i128>>,
    HashMap<LEVEL, HashMap<CompactString, i128>>,
    HashMap<LEVEL, HashMap<CompactString, i128>>,
);

impl Default for ResultOutputState {
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
        ResultOutputState {
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

/// The timeline output sink. CSV goes through a `csv::Writer`; JSON/JSONL is written directly to
/// the target (records separated by a newline — `first` tracks whether one has been written yet —
/// reproducing the byte layout the CSV writer's `\n` delimiter previously produced, without
/// abusing it as a plain-text sink).
pub(crate) enum ResultWriter {
    // Boxed: a `csv::Writer` is much larger than the `Json` variant.
    Csv(Box<Writer<Box<dyn io::Write>>>),
    Json {
        writer: Box<dyn io::Write>,
        first: bool,
    },
}

/// The writers used for result output: a termcolor writer for colored terminal display and a
/// `ResultWriter` for the timeline output itself (CSV via `csv::Writer`, JSON/JSONL written
/// directly). `display_flag` is true when no output file was specified, i.e. results are
/// displayed on the terminal.
pub struct OutputWriter {
    pub(crate) display_writer: BufferWriter,
    pub(crate) disp_wtr_buf: Buffer,
    pub(crate) result_writer: ResultWriter,
    pub display_flag: bool,
}

/// Creates the result writer, targeting the file given with the output option if one was
/// specified, otherwise stdout (the pivot-keywords-list and logon-summary commands write their
/// own files elsewhere, so their writer stays on stdout). CSV output goes through a `csv::Writer`;
/// JSON/JSONL output is written directly to the target.
pub fn init_writer(stored_static: &StoredStatic) -> OutputWriter {
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
        // produced through the termcolor writer (display_writer), not through the result writer.
        Box::new(BufWriter::new(io::stdout()))
    };

    let writer = match &stored_static.config.action.as_ref().unwrap() {
        // JSON/JSONL records serialize themselves; write them straight to the target.
        Action::JsonTimeline(_) => ResultWriter::Json {
            writer: target,
            first: true,
        },
        Action::CsvTimeline(_) => ResultWriter::Csv(Box::new(
            WriterBuilder::new()
                .quote_style(QuoteStyle::NonNumeric)
                .from_writer(target),
        )),
        _ => ResultWriter::Csv(Box::new(WriterBuilder::new().from_writer(target))),
    };

    // Bundle the display writer (colored terminal display and the results summary) and the
    // result writer (the CSV/JSON timeline output).
    OutputWriter {
        display_writer,
        disp_wtr_buf,
        result_writer: writer,
        display_flag,
    }
}

/// Sorts and deduplicates all collected detections, writes them out, and prints the results
/// summary. Exits the process if writing fails.
pub fn output_results(
    detect_infos: &mut [DetectInfo],
    output_writer: &mut OutputWriter,
    stored_static: &StoredStatic,
    result_state: &mut ResultOutputState,
) {
    let ret = output_results_inner(detect_infos, output_writer, stored_static, result_state);
    if ret.is_err() {
        handle_output_error(Box::new(ret.err().unwrap()));
    }
}

pub(crate) fn handle_output_error(err: Box<dyn Error>) {
    AlertMessage::alert(&format!("Failed to write CSV. {err}")).ok();
    process::exit(1);
}

fn output_results_inner(
    detect_infos: &mut [DetectInfo],
    output_writer: &mut OutputWriter,
    stored_static: &StoredStatic,
    result_state: &mut ResultOutputState,
) -> io::Result<()> {
    if output_writer.display_flag {
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
        output_writer,
        result_state,
    )?;

    // Calculate the statistics for the results summary.
    calc_statistic_info(
        detect_infos,
        &duplicate_indices,
        result_state,
        stored_static,
    );
    output_writer.disp_wtr_buf.clear();

    output_result_summary(stored_static, output_writer, result_state);

    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs::{read_to_string, remove_file};
    use std::path::Path;

    use chrono::NaiveDateTime;
    use chrono::{DateTime, Local, TimeZone, Utc};
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use serde_json::Value;

    use crate::detections::configs::Action;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::DisableAbbreviationsOption;
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
    use crate::results::_print_unique_results;
    use crate::results::ResultOutputState;
    use crate::results::close_unterminated_quote;
    use crate::results::format_time;
    use crate::results::get_duplicate_indices;
    use crate::results::html_escape_value;
    use crate::results::init_writer;
    use crate::results::json_scalar;
    use crate::results::json_string;
    use crate::results::output_results_inner;
    use crate::results::sort_detect_info;

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
        let mut result_state = ResultOutputState::default();
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);

        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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
        let mut result_state = ResultOutputState::default();
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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

    /// Regression guard for the escaping / control-char behaviour that moved from the deleted
    /// `_convert_valid_json_str` into `json_scalar`/`json_string` + `close_unterminated_quote`.
    /// As of #1849 real `\n`/`\r`/`\t` are kept in field values and escaped by serde_json (a value
    /// containing a newline now serializes to the JSON escape `\n`, not the old visible `\\n`).
    #[test]
    fn test_json_scalar_and_quote_quirk() {
        use serde_json::json;
        // Real control chars are escaped by serde_json: a `\n` value serializes to a JSON `\n`.
        assert_eq!(json_scalar("a\nb"), json!("a\nb"));
        assert_eq!(json_scalar("a\tb"), json!("a\tb"));
        assert_eq!(json_string("x\ry"), json!("x\ry"));
        // close_unterminated_quote leaves ordinary text untouched.
        assert_eq!(close_unterminated_quote("plain"), "plain");
        assert_eq!(close_unterminated_quote("C:\\path"), "C:\\path");
        // Leading-quote quirk: a value starting with a quote but not ending with one gets a
        // closing quote appended (preserved for byte-identical data).
        assert_eq!(close_unterminated_quote("\"C:\\a\" x"), "\"C:\\a\" x\"");
        assert_eq!(close_unterminated_quote("\"quoted\""), "\"quoted\"");
        // json_scalar type-guessing: ints/bools unquoted, everything else a string.
        assert_eq!(json_scalar("1111"), json!(1111));
        assert_eq!(json_scalar("-5"), json!(-5));
        assert_eq!(json_scalar("true"), json!(true));
        assert_eq!(json_scalar("false"), json!(false));
        assert_eq!(json_scalar("007"), json!(7));
        assert_eq!(json_scalar("1.5"), json!("1.5"));
        assert_eq!(json_scalar("hello"), json!("hello"));
        // json_string never type-guesses (array elements are always strings).
        assert_eq!(json_string("1111"), json!("1111"));
        // A quote-prefixed value serializes to well-formed JSON that round-trips.
        let serialized = serde_json::to_string(&json_scalar("\"weird")).unwrap();
        assert_eq!(
            serde_json::from_str::<String>(&serialized).unwrap(),
            "\"weird\""
        );
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
        let mut result_state = ResultOutputState::default();
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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
        let mut result_state = ResultOutputState::default();
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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
        let mut result_state = ResultOutputState::default();
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
            disable_abbreviations_opt: DisableAbbreviationsOption {
                disable_abbreviations: false,
            },
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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
        let mut result_state = ResultOutputState::default();
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

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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
        let mut result_state = ResultOutputState::default();
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
            "\"Timestamp\":\"1996-02-27 01:05:01.000 +00:00\",",
            "\"Computer\":\"testcomputer\",",
            "\"Channel\":\"Sec\",",
            "\"Level\":\"high\",",
            "\"EventID\":1111,",
            "\"MitreAttack\":[\"execution/txxxx.yyy\"],",
            "\"RecordID\":11111,",
            "\"RuleTitle\":\"test_title\",",
            "\"Details\":\"pokepoke\",",
            "\"RecordInformation\":{\"CommandRLine\":\"hoge\"},",
            "\"RuleFile\":\"test-rule.yml\",",
            "\"EvtxFile\":\"test.evtx\",",
            "\"Tags\":[\"execution/txxxx.yyy\"]",
        ];

        result_state.record_cnt = 1;
        result_state.recover_record_cnt = 0;
        result_state.timeline_start_time = Some(expect_tz);
        result_state.timeline_end_time = Some(expect_tz);
        let mut writer = init_writer(&stored_static);
        assert!(
            output_results_inner(
                &mut detect_infos,
                &mut writer,
                &stored_static,
                &mut result_state,
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

use crate::detections::configs::{
    Action, OutputOption, StoredStatic, CONTROL_CHAT_REPLACE_MAP, CURRENT_EXE_PATH, GEOIP_DB_PARSER,
};
use crate::detections::message::{AlertMessage, DetectInfo, COMPUTER_MITRE_ATTCK_MAP, LEVEL_FULL};
use crate::detections::utils::{
    self, format_time, get_writable_color, output_and_data_stack_for_html, write_color_buffer,
};
use crate::options::htmlreport;
use crate::options::profile::Profile;
use crate::yaml::ParseYaml;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use chrono::{DateTime, Local, TimeZone, Utc};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use compact_str::CompactString;
use hashbrown::hash_map::RawEntryMut;
use terminal_size::terminal_size;

use csv::{QuoteStyle, WriterBuilder};
use itertools::Itertools;
use krapslog::{build_sparkline, build_time_markers};
use nested::Nested;
use std::path::Path;
use std::str::FromStr;
use yaml_rust::YamlLoader;

use comfy_table::*;
use hashbrown::{HashMap, HashSet};
use num_format::{Locale, ToFormattedString};
use std::cmp::{self, min, Ordering};
use std::error::Error;

use std::io::{self, BufWriter, Write};

use lazy_static::lazy_static;
use std::fs::File;
use std::process;
use termcolor::{Buffer, BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use terminal_size::Width;

lazy_static! {
    // ここで字句解析するときに使う正規表現の一覧を定義する。
    // ここはSigmaのGithubレポジトリにある、toos/sigma/parser/condition.pyのSigmaConditionTokenizerのtokendefsを参考にしています。
    pub static ref LEVEL_MAP: HashMap<String, u128> = HashMap::from([
        ("INFORMATIONAL".to_string(), 1),
        ("LOW".to_string(), 2),
        ("MEDIUM".to_string(), 3),
        ("HIGH".to_string(), 4),
        ("CRITICAL".to_string(), 5),
    ]);
}

#[derive(Debug)]
pub struct Colors {
    pub output_color: termcolor::Color,
    pub table_color: comfy_table::Color,
}

pub struct AfterfactInfo {
    pub detect_infos: Vec<DetectInfo>,
    pub tl_starttime: Option<DateTime<Utc>>,
    pub tl_endtime: Option<DateTime<Utc>>,
    pub record_cnt: u128,
    pub recover_record_cnt: u128,
    pub detected_record_idset: HashSet<CompactString>,
    pub total_detect_counts_by_level: Vec<u128>,
    pub unique_detect_counts_by_level: Vec<u128>,
    pub detect_counts_by_date_and_level: HashMap<CompactString, HashMap<CompactString, i128>>,
    pub detect_counts_by_computer_and_level: HashMap<CompactString, HashMap<CompactString, i128>>,
    pub detect_counts_by_rule_and_level: HashMap<CompactString, HashMap<CompactString, i128>>,
    pub detect_rule_authors: HashMap<CompactString, CompactString>,
    pub rule_title_path_map: HashMap<CompactString, CompactString>,
    pub rule_author_counter: HashMap<CompactString, i128>,
    pub timestamps: Vec<i64>,
}

struct InitLevelMapResult(
    HashMap<CompactString, HashMap<CompactString, i128>>,
    HashMap<CompactString, HashMap<CompactString, i128>>,
    HashMap<CompactString, HashMap<CompactString, i128>>,
);

impl AfterfactInfo {
    pub fn sort_detect_info(&mut self) {
        self.detect_infos.sort_unstable_by(|a, b| {
            let cmp_time = a.detected_time.cmp(&b.detected_time);
            if cmp_time != Ordering::Equal {
                return cmp_time;
            }

            let a_level = get_level_suffix(a.level.as_str());
            let b_level = get_level_suffix(b.level.as_str());
            let level_cmp = a_level.cmp(&b_level);
            if level_cmp != Ordering::Equal {
                return level_cmp;
            }

            let event_id_cmp = a.eventid.cmp(&b.eventid);
            if event_id_cmp != Ordering::Equal {
                return event_id_cmp;
            }

            let rulepath_cmp = a.rulepath.cmp(&b.rulepath);
            if rulepath_cmp != Ordering::Equal {
                return rulepath_cmp;
            }

            a.computername.cmp(&b.computername)
        });
    }

    pub fn removed_duplicate_detect_infos(&mut self) {
        // https://qiita.com/quasardtm/items/b54a48c1accd675e0bf1
        let mut tmp_detect_infos = vec![];
        std::mem::swap(&mut self.detect_infos, &mut tmp_detect_infos);

        // filtet duplicate event
        let mut filtered_detect_infos: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        {
            let mut prev_detect_infos = HashSet::new();
            for (i, detect_info) in tmp_detect_infos.iter().enumerate() {
                if i == 0 {
                    filtered_detect_infos.insert(i);
                    continue;
                }

                let prev_detect_info = &tmp_detect_infos[i - 1];
                if prev_detect_info
                    .detected_time
                    .cmp(&detect_info.detected_time)
                    != Ordering::Equal
                {
                    filtered_detect_infos.insert(i);
                    prev_detect_infos.clear();
                    continue;
                }

                let fields: Vec<&(CompactString, Profile)> = detect_info
                    .ext_field
                    .iter()
                    .filter(|(_, profile)| !matches!(profile, Profile::EvtxFile(_)))
                    .collect();
                if prev_detect_infos.get(&fields).is_some() {
                    continue;
                }
                prev_detect_infos.insert(fields);
                filtered_detect_infos.insert(i);
            }
        }

        tmp_detect_infos = tmp_detect_infos
            .into_iter()
            .enumerate()
            .filter_map(|(i, detect_info)| {
                if filtered_detect_infos.contains(&i) {
                    Some(detect_info)
                } else {
                    Option::None
                }
            })
            .collect();

        std::mem::swap(&mut self.detect_infos, &mut tmp_detect_infos);
    }
}

impl Default for AfterfactInfo {
    fn default() -> Self {
        let InitLevelMapResult(
            detect_counts_by_date_and_level,
            detect_counts_by_computer_and_level,
            detect_counts_by_rule_and_level,
        ) = {
            let levels = ["crit", "high", "med ", "low ", "info", "undefined"];
            let mut detect_counts_by_date_and_level: HashMap<
                CompactString,
                HashMap<CompactString, i128>,
            > = HashMap::new();
            let mut detect_counts_by_computer_and_level: HashMap<
                CompactString,
                HashMap<CompactString, i128>,
            > = HashMap::new();
            let mut detect_counts_by_rule_and_level: HashMap<
                CompactString,
                HashMap<CompactString, i128>,
            > = HashMap::new();
            // レベル別、日ごとの集計用変数の初期化
            for level_init in levels {
                detect_counts_by_date_and_level
                    .insert(CompactString::from(level_init), HashMap::new());
                detect_counts_by_computer_and_level
                    .insert(CompactString::from(level_init), HashMap::new());
                detect_counts_by_rule_and_level
                    .insert(CompactString::from(level_init), HashMap::new());
            }

            InitLevelMapResult(
                detect_counts_by_date_and_level,
                detect_counts_by_computer_and_level,
                detect_counts_by_rule_and_level,
            )
        };
        AfterfactInfo {
            detect_infos: vec![],
            tl_starttime: Option::None,
            tl_endtime: Option::None,
            record_cnt: 0,
            recover_record_cnt: 0,
            detected_record_idset: HashSet::new(),
            total_detect_counts_by_level: vec![0; 6],
            unique_detect_counts_by_level: vec![0; 6],
            detect_counts_by_date_and_level,
            detect_counts_by_computer_and_level,
            detect_counts_by_rule_and_level,
            detect_rule_authors: HashMap::new(),
            rule_title_path_map: HashMap::new(),
            rule_author_counter: HashMap::new(),
            timestamps: vec![],
        }
    }
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn create_output_color_map(no_color_flag: bool) -> HashMap<CompactString, Colors> {
    let read_result = utils::read_csv(
        utils::check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "config/level_color.txt",
            true,
        )
        .unwrap()
        .to_str()
        .unwrap(),
    );
    let mut color_map: HashMap<CompactString, Colors> = HashMap::new();
    if no_color_flag {
        return color_map;
    }
    let color_map_contents = match read_result {
        Ok(c) => c,
        Err(e) => {
            // color情報がない場合は通常の白色の出力が出てくるのみで動作への影響を与えない為warnとして処理する
            AlertMessage::warn(&e).ok();
            return color_map;
        }
    };
    color_map_contents.iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }
        let empty = &"".to_string();
        let level = CompactString::new(line.first().unwrap_or(empty).to_lowercase());
        let convert_color_result = hex::decode(line.get(1).unwrap_or(empty).trim());
        if convert_color_result.is_err() {
            AlertMessage::warn(&format!(
                "Failed hex convert in level_color.txt. Color output is disabled. Input Line: {}",
                line.join(",")
            ))
            .ok();
            return;
        }
        let color_code = convert_color_result.unwrap();
        if level.is_empty() || color_code.len() < 3 {
            return;
        }
        color_map.insert(
            level,
            Colors {
                output_color: termcolor::Color::Rgb(color_code[0], color_code[1], color_code[2]),
                table_color: comfy_table::Color::Rgb {
                    r: color_code[0],
                    g: color_code[1],
                    b: color_code[2],
                },
            },
        );
    });
    color_map
}

fn _get_output_color(color_map: &HashMap<CompactString, Colors>, level: &str) -> Option<Color> {
    let mut color = None;
    if let Some(c) = color_map.get(&CompactString::from(level.to_lowercase())) {
        color = Some(c.output_color);
    }
    color
}

fn _get_table_color(
    color_map: &HashMap<CompactString, Colors>,
    level: &str,
) -> Option<comfy_table::Color> {
    let mut color = None;
    if let Some(c) = color_map.get(&CompactString::from(level.to_lowercase())) {
        color = Some(c.table_color);
    }
    color
}

/// print timeline histogram
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

pub fn after_fact(stored_static: &StoredStatic, afterfact_info: AfterfactInfo) {
    let fn_output_afterfact_err = |err: Box<dyn Error>| {
        AlertMessage::alert(&format!("Failed to write CSV. {err}")).ok();
        process::exit(1);
    };

    let mut displayflag = false;
    let mut target: Box<dyn io::Write> = if let Some(path) = &stored_static.output_path {
        // output to file
        match File::create(path) {
            Ok(file) => Box::new(BufWriter::new(file)),
            Err(err) => {
                AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                process::exit(1);
            }
        }
    } else {
        displayflag = true;
        // stdoutput (termcolor crate color output is not csv writer)
        Box::new(BufWriter::new(io::stdout()))
    };

    if let Err(err) = output_afterfact(
        &mut target,
        displayflag,
        stored_static.profiles.as_ref().unwrap(),
        stored_static,
        afterfact_info,
    ) {
        fn_output_afterfact_err(Box::new(err));
    }
}

fn get_level_suffix(level_str: &str) -> usize {
    *LEVEL_MAP
        .get(
            LEVEL_FULL
                .get(level_str)
                .unwrap_or(&"undefined")
                .to_uppercase()
                .as_str(),
        )
        .unwrap_or(&0) as usize
}

struct AfterfactWriter {
    disp_wtr: BufferWriter,
    disp_wtr_buf: Buffer,
}

fn init_writer() -> AfterfactWriter {
    let disp_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut disp_wtr_buf = disp_wtr.buffer();

    disp_wtr_buf.set_color(ColorSpec::new().set_fg(None)).ok();

    // emit csv
    AfterfactWriter {
        disp_wtr,
        disp_wtr_buf,
    }
}

fn output_afterfact<W: std::io::Write>(
    writer: &mut W,
    displayflag: bool,
    profile: &[(CompactString, Profile)],
    stored_static: &StoredStatic,
    mut afterfact_info: AfterfactInfo,
) -> io::Result<()> {
    let mut artifact_writer = init_writer();
    if displayflag {
        println!();
    }

    // sort and filter detect infos
    afterfact_info.sort_detect_info();
    if stored_static
        .output_option
        .as_ref()
        .unwrap()
        .remove_duplicate_detections
    {
        afterfact_info.removed_duplicate_detect_infos();
    }

    emit_csv(
        stored_static,
        &artifact_writer,
        writer,
        &afterfact_info,
        profile,
        displayflag,
    )?;

    // calculate statistic information
    afterfact_info = calc_statistic_info(afterfact_info, stored_static);

    artifact_writer.disp_wtr_buf.clear();

    output_additional_afterfact(stored_static, artifact_writer, &afterfact_info);

    Ok(())
}

fn emit_csv<W: std::io::Write>(
    stored_static: &StoredStatic,
    artifact_writer: &AfterfactWriter,
    writer: &mut W,
    afterfact_info: &AfterfactInfo,
    profile: &[(CompactString, Profile)],
    displayflag: bool,
) -> io::Result<()> {
    let output_replaced_maps: HashMap<&str, &str> =
        HashMap::from_iter(vec![("🛂r", "\r"), ("🛂n", "\n"), ("🛂t", "\t")]);
    let mut removed_replaced_maps: HashMap<&str, &str> =
        HashMap::from_iter(vec![("\n", " "), ("\r", " "), ("\t", " ")]);
    if stored_static.multiline_flag {
        removed_replaced_maps.insert("🛂🛂", "\r\n");
        removed_replaced_maps.insert(" ¦ ", "\r\n");
    }
    let output_replacer = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(output_replaced_maps.keys())
        .unwrap();
    let output_remover = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(removed_replaced_maps.keys())
        .unwrap();

    let mut plus_header = true;
    // remove duplicate dataのための前レコード分の情報を保持する変数
    let mut prev_message: HashMap<CompactString, Profile> = HashMap::new();
    let mut prev_details_convert_map: HashMap<CompactString, Vec<CompactString>> = HashMap::new();
    let color_map = create_output_color_map(stored_static.common_options.no_color);
    let (json_output_flag, jsonl_output_flag, remove_duplicate_data, wtr) =
        match &stored_static.config.action.as_ref().unwrap() {
            Action::JsonTimeline(option) => (
                true,
                option.jsonl_timeline,
                option.output_options.remove_duplicate_data,
                Some(
                    WriterBuilder::new()
                        .delimiter(b'\n')
                        .double_quote(false)
                        .quote_style(QuoteStyle::Never)
                        .from_writer(writer),
                ),
            ),
            Action::CsvTimeline(option) => (
                false,
                false,
                option.output_options.remove_duplicate_data,
                Some(
                    WriterBuilder::new()
                        .delimiter(b'\n')
                        .double_quote(false)
                        .quote_style(QuoteStyle::Never)
                        .from_writer(writer),
                ),
            ),
            _ => (false, false, false, None),
        };
    if wtr.is_none() {
        return Ok(());
    }

    let mut wtr = wtr.unwrap();
    for detect_info in afterfact_info.detect_infos.iter() {
        if displayflag && !(json_output_flag || jsonl_output_flag) {
            // 標準出力の場合
            if plus_header {
                // ヘッダーのみを出力
                _get_serialized_disp_output(
                    &artifact_writer.disp_wtr,
                    profile,
                    true,
                    (&output_replacer, &output_replaced_maps),
                    (&output_remover, &removed_replaced_maps),
                    stored_static.common_options.no_color,
                    get_writable_color(
                        _get_output_color(
                            &color_map,
                            LEVEL_FULL.get(detect_info.level.as_str()).unwrap_or(&""),
                        ),
                        stored_static.common_options.no_color,
                    ),
                );
                plus_header = false;
            }
            _get_serialized_disp_output(
                &artifact_writer.disp_wtr,
                &detect_info.ext_field,
                false,
                (&output_replacer, &output_replaced_maps),
                (&output_remover, &removed_replaced_maps),
                stored_static.common_options.no_color,
                get_writable_color(
                    _get_output_color(
                        &color_map,
                        LEVEL_FULL.get(detect_info.level.as_str()).unwrap_or(&""),
                    ),
                    stored_static.common_options.no_color,
                ),
            );
        } else if jsonl_output_flag {
            // JSONL output format
            let result = output_json_str(
                &detect_info.ext_field,
                prev_message,
                jsonl_output_flag,
                GEOIP_DB_PARSER.read().unwrap().is_some(),
                remove_duplicate_data,
                detect_info.is_condition,
                &[&detect_info.details_convert_map, &prev_details_convert_map],
            );
            prev_message = result.1;
            prev_details_convert_map = detect_info.details_convert_map.clone();
            if displayflag {
                write_color_buffer(
                    &artifact_writer.disp_wtr,
                    None,
                    &format!("{{ {} }}", &result.0),
                    true,
                )
                .ok();
            } else {
                wtr.write_field(format!("{{ {} }}", &result.0))?;
            }
        } else if json_output_flag {
            // JSON output
            let result = output_json_str(
                &detect_info.ext_field,
                prev_message,
                jsonl_output_flag,
                GEOIP_DB_PARSER.read().unwrap().is_some(),
                remove_duplicate_data,
                detect_info.is_condition,
                &[&detect_info.details_convert_map, &prev_details_convert_map],
            );
            prev_message = result.1;
            prev_details_convert_map = detect_info.details_convert_map.clone();
            if displayflag {
                write_color_buffer(
                    &artifact_writer.disp_wtr,
                    None,
                    &format!("{{\n{}\n}}", &result.0),
                    true,
                )
                .ok();
            } else {
                wtr.write_field("{")?;
                wtr.write_field(&result.0)?;
                wtr.write_field("}")?;
            }
        } else {
            // csv output format
            if plus_header {
                wtr.write_record(detect_info.ext_field.iter().map(|x| x.0.trim()))?;
                plus_header = false;
            }
            wtr.write_record(detect_info.ext_field.iter().map(|x| {
                match x.1 {
                    Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                        let ret = if remove_duplicate_data
                            && x.1.to_value()
                                == prev_message
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
                        prev_message.insert(x.0.clone(), x.1.clone());
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

    if displayflag {
        println!();
    } else {
        wtr.flush()?;
    }

    Ok(())
}

fn calc_statistic_info(
    mut afterfact_info: AfterfactInfo,
    stored_static: &StoredStatic,
) -> AfterfactInfo {
    let mut detected_rule_files: HashSet<CompactString> = HashSet::new();
    let mut detected_rule_ids: HashSet<CompactString> = HashSet::new();
    let mut detected_computer_and_rule_names: HashSet<CompactString> = HashSet::new();
    let mut author_list_cache: HashMap<CompactString, Nested<String>> = HashMap::new();
    let output_option = stored_static.output_option.as_ref().unwrap();
    for detect_info in afterfact_info.detect_infos.iter() {
        if !detect_info.is_condition {
            afterfact_info
                .detected_record_idset
                .insert(CompactString::from(format!(
                    "{}_{}",
                    detect_info.detected_time, detect_info.eventid
                )));
        }

        if !output_option.no_summary {
            let level_suffix = get_level_suffix(detect_info.level.as_str());
            let author_list = author_list_cache
                .entry(detect_info.rulepath.clone())
                .or_insert_with(|| extract_author_name(&detect_info.rulepath))
                .clone();
            let author_str = author_list.iter().join(", ");
            afterfact_info
                .detect_rule_authors
                .insert(detect_info.rulepath.to_owned(), author_str.into());

            if !detected_rule_files.contains(&detect_info.rulepath) {
                detected_rule_files.insert(detect_info.rulepath.to_owned());
                for author in author_list.iter() {
                    *afterfact_info
                        .rule_author_counter
                        .entry(CompactString::from(author))
                        .or_insert(0) += 1;
                }
            }
            if !detected_rule_ids.contains(&detect_info.ruleid) {
                detected_rule_ids.insert(detect_info.ruleid.to_owned());
                afterfact_info.unique_detect_counts_by_level[level_suffix] += 1;
            }

            let computer_rule_check_key = CompactString::from(format!(
                "{}|{}",
                &detect_info.computername, &detect_info.rulepath
            ));
            if !detected_computer_and_rule_names.contains(&computer_rule_check_key) {
                detected_computer_and_rule_names.insert(computer_rule_check_key);
                countup_aggregation(
                    &mut afterfact_info.detect_counts_by_computer_and_level,
                    &detect_info.level,
                    &detect_info.computername,
                );
            }
            afterfact_info.rule_title_path_map.insert(
                detect_info.ruletitle.to_owned(),
                detect_info.rulepath.to_owned(),
            );

            countup_aggregation(
                &mut afterfact_info.detect_counts_by_date_and_level,
                &detect_info.level,
                &format_time(&detect_info.detected_time, true, output_option),
            );
            countup_aggregation(
                &mut afterfact_info.detect_counts_by_rule_and_level,
                &detect_info.level,
                &detect_info.ruletitle,
            );
            afterfact_info.total_detect_counts_by_level[level_suffix] += 1;
        }
    }
    afterfact_info
}

fn output_additional_afterfact(
    stored_static: &StoredStatic,
    mut afterfact_writer: AfterfactWriter,
    afterfact_info: &AfterfactInfo,
) {
    let terminal_width = match terminal_size() {
        Some((Width(w), _)) => w as usize,
        None => 100,
    };
    let level_abbr: Nested<Vec<CompactString>> = Nested::from_iter(
        [
            [CompactString::from("critical"), CompactString::from("crit")].to_vec(),
            [CompactString::from("high"), CompactString::from("high")].to_vec(),
            [CompactString::from("medium"), CompactString::from("med ")].to_vec(),
            [CompactString::from("low"), CompactString::from("low ")].to_vec(),
            [
                CompactString::from("informational"),
                CompactString::from("info"),
            ]
            .to_vec(),
        ]
        .iter(),
    );
    let output_option = stored_static.output_option.as_ref().unwrap();
    if !output_option.no_summary && !afterfact_info.rule_author_counter.is_empty() {
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Rule Authors:",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
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
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Results Summary:\n",
            true,
        )
        .ok();

        if afterfact_info.tl_starttime.is_some() {
            output_and_data_stack_for_html(
                &format!(
                    "First Timestamp: {}",
                    utils::format_time(
                        &afterfact_info.tl_starttime.unwrap(),
                        false,
                        stored_static.output_option.as_ref().unwrap()
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
        }
        if afterfact_info.tl_endtime.is_some() {
            output_and_data_stack_for_html(
                &format!(
                    "Last Timestamp: {}",
                    utils::format_time(
                        &afterfact_info.tl_endtime.unwrap(),
                        false,
                        stored_static.output_option.as_ref().unwrap()
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
            println!();
        }

        let reducted_record_cnt: u128 =
            afterfact_info.record_cnt - afterfact_info.detected_record_idset.len() as u128;
        let reducted_percent = if afterfact_info.record_cnt == 0 {
            0 as f64
        } else {
            (reducted_record_cnt as f64) / (afterfact_info.record_cnt as f64) * 100.0
        };
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Events with hits",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            "Total events",
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(None, stored_static.common_options.no_color),
            ": ",
            false,
        )
        .ok();
        let saved_alerts_output =
            (afterfact_info.record_cnt - reducted_record_cnt).to_formatted_string(&Locale::en);
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &saved_alerts_output,
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();

        let all_record_output = afterfact_info.record_cnt.to_formatted_string(&Locale::en);
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            &all_record_output,
            false,
        )
        .ok();
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(None, stored_static.common_options.no_color),
            " (",
            false,
        )
        .ok();
        let reduction_output = format!(
            "Data reduction: {} events ({:.2}%)",
            reducted_record_cnt.to_formatted_string(&Locale::en),
            reducted_percent
        );
        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &reduction_output,
            false,
        )
        .ok();

        write_color_buffer(
            &afterfact_writer.disp_wtr,
            get_writable_color(None, stored_static.common_options.no_color),
            ")",
            true,
        )
        .ok();
        if stored_static.enable_recover_records {
            write_color_buffer(
                &afterfact_writer.disp_wtr,
                get_writable_color(
                    Some(Color::Rgb(0, 255, 255)),
                    stored_static.common_options.no_color,
                ),
                "Recovered records",
                false,
            )
            .ok();
            write_color_buffer(
                &afterfact_writer.disp_wtr,
                get_writable_color(None, stored_static.common_options.no_color),
                ": ",
                false,
            )
            .ok();
            let recovered_record_output = afterfact_info
                .recover_record_cnt
                .to_formatted_string(&Locale::en);
            write_color_buffer(
                &afterfact_writer.disp_wtr,
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
            &level_abbr,
            &mut html_output_stock,
            stored_static.html_report_flag,
        );
        println!();

        _print_detection_summary_by_date(
            &afterfact_info.detect_counts_by_date_and_level,
            &color_map,
            &level_abbr,
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
            &level_abbr,
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
            &level_abbr,
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

fn countup_aggregation(
    count_map: &mut HashMap<CompactString, HashMap<CompactString, i128>>,
    key: &str,
    entry_key: &str,
) {
    let compact_lowercase_key = CompactString::from(key.to_lowercase());
    let mut detect_counts_by_rules = count_map
        .get(&compact_lowercase_key)
        .unwrap_or_else(|| count_map.get("undefined").unwrap())
        .to_owned();
    *detect_counts_by_rules.entry(entry_key.into()).or_insert(0) += 1;
    count_map.insert(compact_lowercase_key, detect_counts_by_rules);
}

/// columnt position. in cell
/// First: |<str> |
/// Last: | <str>|
/// Othre: | <str> |
enum ColPos {
    First,
    Last,
    Other,
}

fn _get_serialized_disp_output(
    disp_wtr: &BufferWriter,
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
            disp_wtr,
            get_writable_color(None, no_color),
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
                    output_str_char_pair
                }
                _ => {
                    vec![vec![(display_contents, None)]]
                }
            };

            let col_cnt = output_color_and_contents.len();
            for (field_idx, col_contents) in output_color_and_contents.iter().enumerate() {
                for (c, color) in col_contents {
                    write_color_buffer(disp_wtr, *color, c, false).ok();
                }
                if field_idx != col_cnt - 1 {
                    write_color_buffer(disp_wtr, None, "¦", false).ok();
                }
            }

            if i != data_length - 1 {
                write_color_buffer(
                    disp_wtr,
                    get_writable_color(Some(Color::Rgb(255, 158, 61)), no_color),
                    "·",
                    false,
                )
                .ok();
            } else {
                //1レコード分の最後の要素の改行
                println!();
                println!();
            }
        }
    }
}

/// return str position in output file
fn _format_cellpos(colval: &str, column: ColPos) -> String {
    match column {
        ColPos::First => format!("{colval} "),
        ColPos::Last => format!(" {colval}"),
        ColPos::Other => format!(" {colval} "),
    }
}

/// output info which unique detection count and all detection count information(separated by level and total) to stdout.
fn _print_unique_results(
    counts_by_level: &[u128],
    unique_counts_by_level: &[u128],
    head_and_tail_word: (CompactString, CompactString),
    color_map: &HashMap<CompactString, Colors>,
    level_abbr: &Nested<Vec<CompactString>>,
    html_output_stock: &mut Nested<String>,
    html_output_flag: bool,
) {
    // the order in which are registered and the order of levels to be displayed are reversed
    let mut counts_by_level_rev = counts_by_level.iter().rev();
    let mut unique_counts_by_level_rev = unique_counts_by_level.iter().rev();

    let total_count = counts_by_level.iter().sum::<u128>();
    let unique_total_count = unique_counts_by_level.iter().sum::<u128>();
    // output total results
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

    for (i, level_name) in level_abbr.iter().enumerate() {
        let count_by_level = *counts_by_level_rev.next().unwrap();
        let unique_count_by_level = *unique_counts_by_level_rev.next().unwrap();
        if "undefined" == level_name[0] {
            continue;
        }
        let percent = if total_count == 0 {
            0 as f64
        } else {
            (count_by_level as f64) / (total_count as f64) * 100.0
        };
        let unique_percent = if unique_total_count == 0 {
            0 as f64
        } else {
            (unique_counts_by_level[i] as f64) / (unique_total_count as f64) * 100.0
        };
        if html_output_flag {
            total_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name[0],
                count_by_level.to_formatted_string(&Locale::en),
                percent
            ));
            unique_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name[0],
                unique_count_by_level.to_formatted_string(&Locale::en),
                unique_percent
            ));
        }
        let output_raw_str = format!(
            "{} {} {}: {} ({:.2}%) | {} ({:.2}%)",
            head_and_tail_word.0,
            level_name[0],
            head_and_tail_word.1,
            count_by_level.to_formatted_string(&Locale::en),
            percent,
            unique_count_by_level.to_formatted_string(&Locale::en),
            unique_percent
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            _get_output_color(color_map, &level_name[0]),
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

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_date(
    detect_counts_by_date: &HashMap<CompactString, HashMap<CompactString, i128>>,
    color_map: &HashMap<CompactString, Colors>,
    level_abbr: &Nested<Vec<CompactString>>,
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
    for (idx, level) in level_abbr.iter().enumerate() {
        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_day = detect_counts_by_date.get(&level[1]).unwrap();
        let mut max_detect_str = CompactString::default();
        let mut tmp_cnt: i128 = 0;
        let mut exist_max_data = false;
        for (date, cnt) in detections_by_day {
            if cnt > &tmp_cnt {
                exist_max_data = true;
                max_detect_str =
                    format!("{} ({})", date, cnt.to_formatted_string(&Locale::en)).into();
                tmp_cnt = *cnt;
            }
        }
        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(
            color_map,
            LEVEL_FULL.get(level[1].as_str()).unwrap(),
        )))
        .ok();
        if !exist_max_data {
            max_detect_str = "n/a".into();
        }
        let output_str = format!(
            "{}: {}",
            LEVEL_FULL.get(level[1].as_str()).unwrap(),
            &max_detect_str
        );
        write!(wtr, "{output_str}").ok();
        if idx != level_abbr.len() - 1 {
            wtr.set_color(ColorSpec::new().set_fg(None)).ok();
            write!(wtr, ", ").ok();
        }
        if stored_static.html_report_flag {
            html_output_stock.push(format!("    - {output_str}"));
        }
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベル毎で最も高い検知数を出したコンピュータ名を出力する
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: &HashMap<CompactString, HashMap<CompactString, i128>>,
    color_map: &HashMap<CompactString, Colors>,
    level_abbr: &Nested<Vec<CompactString>>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    writeln!(wtr, "Top 5 computers with most unique detections:").ok();
    for level in level_abbr.iter() {
        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_computer = detect_counts_by_computer.get(&level[1]).unwrap();
        let mut result_vec = Nested::<String>::new();
        //computer nameで-となっているものは除外して集計する
        let mut sorted_detections: Vec<(&CompactString, &i128)> = detections_by_computer
            .iter()
            .filter(|a| a.0.as_str() != "-")
            .collect();

        sorted_detections.sort_by(|a, b| (-a.1).cmp(&(-b.1)));

        // html出力は各種すべてのコンピュータ名を表示するようにする
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### Computers with most unique {} detections: {{#computers_with_most_unique_{}_detections}}",
                LEVEL_FULL.get(level[1].as_str()).unwrap(),
                LEVEL_FULL.get(level[1].as_str()).unwrap()
            ));
            for x in sorted_detections.iter() {
                html_output_stock.push(format!(
                    "- {} ({})",
                    x.0,
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

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(
            color_map,
            LEVEL_FULL.get(level[1].as_str()).unwrap(),
        )))
        .ok();
        writeln!(
            wtr,
            "{}: {}",
            LEVEL_FULL.get(level[1].as_str()).unwrap(),
            &result_str
        )
        .ok();
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベルごとで検出数が多かったルールを表形式で出力する関数
fn _print_detection_summary_tables(
    detect_counts_by_rule_and_level: &HashMap<CompactString, HashMap<CompactString, i128>>,
    color_map: &HashMap<CompactString, Colors>,
    (rule_title_path_map, rule_detect_author_map): (
        &HashMap<CompactString, CompactString>,
        &HashMap<CompactString, CompactString>,
    ),
    level_abbr: &Nested<Vec<CompactString>>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
    limit_num: usize,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let mut output = vec![];
    let mut col_color = vec![];
    for level in level_abbr.iter() {
        let mut col_output: Nested<String> = Nested::<String>::new();
        col_output.push(format!(
            "Top {} alerts:",
            LEVEL_FULL.get(level[1].as_str()).unwrap()
        ));

        col_color.push(_get_table_color(
            color_map,
            LEVEL_FULL.get(level[1].as_str()).unwrap(),
        ));

        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_computer = detect_counts_by_rule_and_level.get(&level[1]).unwrap();
        let mut sorted_detections: Vec<(&CompactString, &i128)> =
            detections_by_computer.iter().collect();

        sorted_detections.sort_by(|a, b| (-a.1).cmp(&(-b.1)));

        // html出力の場合はすべての内容を出力するようにする
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### All {} alerts: {{#all_{}_alerts}}",
                LEVEL_FULL.get(level[1].as_str()).unwrap(),
                LEVEL_FULL.get(level[1].as_str()).unwrap()
            ));
            for x in sorted_detections.iter() {
                let not_found_str = CompactString::from_str("<Not Found Path>").unwrap();
                let rule_path = rule_title_path_map.get(x.0).unwrap_or(&not_found_str);
                html_output_stock.push(format!(
                    "- [{}]({}) ({}) - {}",
                    x.0,
                    &rule_path.replace('\\', "/"),
                    x.1.to_formatted_string(&Locale::en),
                    rule_detect_author_map
                        .get(rule_path)
                        .unwrap_or(&not_found_str)
                ));
            }
            html_output_stock.push("");
        }

        let take_cnt = if "informational" == *LEVEL_FULL.get(level[1].as_str()).unwrap_or(&"-") {
            10
        } else {
            5
        };
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
    let hlch = tb.style(TableComponent::HorizontalLines).unwrap();
    let tbch = tb.style(TableComponent::TopBorder).unwrap();
    for x in 0..output.len() / 2 {
        tb.add_row(vec![
            Cell::new(&output[2 * x][0]).fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(&output[2 * x + 1][0])
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ])
        .set_style(TableComponent::MiddleIntersections, hlch)
        .set_style(TableComponent::TopBorderIntersections, tbch)
        .set_style(TableComponent::BottomBorderIntersections, hlch);

        tb.add_row(vec![
            Cell::new(output[2 * x].iter().skip(1).join("\n"))
                .fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(output[2 * x + 1].iter().skip(1).join("\n"))
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ]);
    }

    let odd_col = &mut output[4].iter().skip(1).take(5);
    let even_col = &mut output[4].iter().skip(6).take(5);
    tb.add_row(vec![
        Cell::new(&output[4][0]).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
        Cell::new(""),
    ]);
    tb.add_row(vec![
        Cell::new(odd_col.join("\n")).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
        Cell::new(even_col.join("\n")).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
    ]);
    println!("{tb}");
}

/// get timestamp to input datetime.
fn _get_timestamp(output_option: &OutputOption, time: &DateTime<Utc>) -> i64 {
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

/// json出力の際に配列として対応させるdetails,MitreTactics,MitreTags,OtherTagsに該当する場合に配列を返す関数
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

/// JSONの出力フォーマットに合わせた文字列を出力する関数
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
                if let Some(c) = CONTROL_CHAT_REPLACE_MAP.get(&x) {
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
                if let Some(c) = CONTROL_CHAT_REPLACE_MAP.get(&x) {
                    c.to_string()
                } else {
                    String::from(x)
                }
            })
            .collect::<CompactString>()
    };
    // 4 space is json indent.
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
                    if let Some(c) = CONTROL_CHAT_REPLACE_MAP.get(&x) {
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
                    if let Some(c) = CONTROL_CHAT_REPLACE_MAP.get(&x) {
                        c.to_string()
                    } else {
                        String::from(x)
                    }
                })
                .collect::<CompactString>()
        )
    }
}

/// JSONの値に対して文字列の出力形式をJSON出力でエラーにならないようにするための変換を行う関数
fn _convert_valid_json_str(input: &[&str], concat_flag: bool) -> String {
    let con_cal = if input.len() == 1 {
        input[0].to_string()
    } else if concat_flag {
        input.join(": ")
    } else {
        input[1..].join(": ")
    };
    let char_cnt = con_cal.char_indices().count();
    if char_cnt == 0 {
        con_cal
    } else if con_cal.starts_with('\"') {
        let addition_header = if !con_cal.starts_with('\"') { "\"" } else { "" };
        let addition_quote = if !con_cal.ends_with('\"') && concat_flag {
            "\""
        } else if !con_cal.ends_with('\"') {
            "\\\""
        } else {
            ""
        };
        [
            addition_header,
            &con_cal
                .replace('🛂', "\\")
                .replace('\\', "\\\\")
                .replace('\"', "\\\""),
            addition_quote,
        ]
        .join("")
    } else {
        con_cal
            .replace('🛂', "\\")
            .replace('\\', "\\\\")
            .replace('\"', "\\\"")
    }
}

/// JSONに出力する1検知分のオブジェクトの文字列を出力する関数
pub fn output_json_str(
    ext_field: &[(CompactString, Profile)],
    prev_message: HashMap<CompactString, Profile>,
    jsonl_output_flag: bool,
    is_included_geo_ip: bool,
    remove_duplicate_flag: bool,
    is_condition: bool,
    details_infos: &[&HashMap<CompactString, Vec<CompactString>>],
) -> (String, HashMap<CompactString, Profile>) {
    let mut target: Vec<String> = vec![];
    let mut target_ext_field = Vec::new();
    let ext_field_map: HashMap<CompactString, Profile> = HashMap::from_iter(ext_field.to_owned());
    let mut next_prev_message = prev_message.clone();
    if remove_duplicate_flag {
        for (field_name, profile) in ext_field.iter() {
            match profile {
                Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                    let details_key = match profile {
                        Profile::Details(_) => "Details",
                        Profile::AllFieldInfo(_) => "AllFieldInfo",
                        Profile::ExtraFieldInfo(_) => "ExtraFieldInfo",
                        _ => "",
                    };

                    let empty = vec![];
                    let now = details_infos[0]
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let prev = details_infos[1]
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let dup_flag = (!profile.to_value().is_empty()
                        && prev_message
                            .get(field_name)
                            .unwrap_or(&Profile::Literal("".into()))
                            .to_value()
                            == profile.to_value())
                        || (!&now.is_empty() && !&prev.is_empty() && now == prev);
                    if dup_flag {
                        // 合致する場合は前回レコード分のメッセージを更新する合致している場合は出力用のフィールドマップの内容を変更する。
                        // 合致しているので前回分のメッセージは更新しない
                        //DUPという通常の文字列を出すためにProfile::Literalを使用する
                        target_ext_field.push((field_name.clone(), Profile::Literal("DUP".into())));
                    } else {
                        // 合致しない場合は前回レコード分のメッセージを更新する
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
        target_ext_field = ext_field.to_owned();
    }
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
        let vec_data = _get_json_vec(profile, &val.to_string());
        if (!key_add_to_details.contains(&key.as_str())
            && !matches!(
                profile,
                Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_)
            ))
            && vec_data.is_empty()
        {
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
                // process GeoIP profile in details sections to include GeoIP data in details section.
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
                    let details_target_stocks =
                        details_infos[0].get(&CompactString::from(format!("#{details_key}")));
                    if details_target_stocks.is_none() {
                        continue;
                    }
                    let details_target_stock = details_target_stocks.unwrap();
                    // aggregation conditionの場合は分解せずにそのまま出力する
                    if is_condition {
                        let details_val =
                            if details_target_stock.is_empty() || details_target_stock[0] == "-" {
                                "-".into()
                            } else {
                                details_target_stock[0].clone()
                            };
                        output_stock.push(_create_json_output_format(
                            key,
                            &details_val,
                            key.starts_with('\"'),
                            details_val.starts_with('\"'),
                            4,
                        ));
                        if jsonl_output_flag {
                            target.push(output_stock.join(""));
                        } else {
                            target.push(output_stock.join("\n"));
                        }
                        continue;
                    } else {
                        output_stock.push(format!("    \"{key}\": {{"));
                    };
                    let mut children_output_stock: HashMap<CompactString, Vec<CompactString>> =
                        HashMap::new();
                    let mut children_output_order = vec![];
                    for contents in details_target_stock.iter() {
                        let (key, value) = contents.split_once(':').unwrap_or_default();
                        let output_key = _convert_valid_json_str(&[key.trim()], false);
                        let fmted_val = _convert_valid_json_str(&[value.trim()], false);
                        if let RawEntryMut::Vacant(_) = children_output_stock
                            .raw_entry_mut()
                            .from_key(output_key.as_str())
                        {
                            children_output_order.push(output_key.clone());
                        }
                        children_output_stock
                            .entry(output_key.into())
                            .or_insert(vec![])
                            .push(fmted_val.into());
                    }
                    // ルール内での表示順に合わせた表示順を戻した配列
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
                            let last_contents_end =
                                if is_included_geo_ip && !valid_key_add_to_details.is_empty() {
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
                    if is_included_geo_ip {
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

/// output detected rule author name function.
fn output_detected_rule_authors(
    rule_author_counter: &HashMap<CompactString, i128>,
    table_column_num: usize,
) {
    let mut sorted_authors: Vec<(&CompactString, &i128)> = rule_author_counter.iter().collect();

    sorted_authors.sort_by(|a, b| (-a.1).cmp(&(-b.1)));
    let div = if sorted_authors.len() % 4 != 0 {
        sorted_authors.len() / table_column_num + 1
    } else {
        sorted_authors.len() / table_column_num
    };

    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    let mut stored_by_column = vec![];
    let hlch = tb.style(TableComponent::HorizontalLines).unwrap();
    let tbch = tb.style(TableComponent::TopBorder).unwrap();
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
            .set_style(TableComponent::MiddleIntersections, hlch)
            .set_style(TableComponent::TopBorderIntersections, tbch)
            .set_style(TableComponent::BottomBorderIntersections, hlch);
    }
    println!("{tb}");
}

/// 与えられたyaml_pathからauthorの名前を抽出して配列で返却する関数
fn extract_author_name(yaml_path: &str) -> Nested<String> {
    let contents = match ParseYaml::read_file(Path::new(&yaml_path).to_path_buf()) {
        Ok(yaml) => Some(yaml),
        Err(e) => {
            AlertMessage::alert(&e).ok();
            None
        }
    };
    if contents.is_none() {
        // 対象のファイルが存在しなかった場合は空配列を返す(検知しているルールに対して行うため、ここは通る想定はないが、ファイルが検知途中で削除された場合などを考慮して追加)
        return Nested::new();
    }
    for yaml in YamlLoader::load_from_str(&contents.unwrap())
        .unwrap_or_default()
        .into_iter()
    {
        if let Some(author) = yaml["author"].as_str() {
            let mut ret = Nested::<String>::new();
            for author in author.split(',').map(|s| {
                // 各要素の括弧以降の記載は名前としないためtmpの一番最初の要素のみを参照する
                // データの中にdouble quote と single quoteが入っているためここで除外する
                s.split('(').next().unwrap_or_default().to_string()
            }) {
                ret.extend(author.split(';'));
            }

            return ret
                .iter()
                .map(|r| {
                    r.split('/')
                        .map(|p| p.trim().replace(['"', '\''], ""))
                        .collect::<String>()
                })
                .collect();
        };
    }
    // ここまで来た場合は要素がない場合なので空配列を返す
    Nested::new()
}

///MITRE ATTCKのTacticsの属性を持つルールに検知したコンピュータ名をhtml出力するための文字列をhtml_output_stockに追加する関数
fn _output_html_computer_by_mitre_attck(html_output_stock: &mut Nested<String>) {
    html_output_stock.push("### MITRE ATT&CK Tactics:{#computers_with_mitre_attck_detections}");
    if COMPUTER_MITRE_ATTCK_MAP.is_empty() {
        html_output_stock.push("- No computers were detected with MITRE ATT&CK Tactics.<br>Make sure you run Hayabusa with a profile that includes %MitreTactics% in order to get this info.<br>");
    }
    for (idx, sorted_output_map) in COMPUTER_MITRE_ATTCK_MAP
        .iter()
        .sorted_by(|a, b| {
            Ord::cmp(
                &format!("{}-{}", &b.value()[b.value().len() - 1], b.key()),
                &format!("{}-{}", &a.value()[a.value().len() - 1], a.key()),
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
            sorted_output_map.key(),
            sorted_output_map.value().join("<br>")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::create_output_color_map;
    use crate::afterfact::format_time;
    use crate::afterfact::output_afterfact;
    use crate::afterfact::AfterfactInfo;
    use crate::afterfact::Colors;
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::configs::Action;
    use crate::detections::configs::CommonOptions;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::DetectCommonOption;
    use crate::detections::configs::InputOption;
    use crate::detections::configs::JSONOutputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::detections::message;
    use crate::detections::message::DetectInfo;
    use crate::detections::utils;
    use crate::options::profile::{load_profile, Profile};
    use chrono::NaiveDateTime;
    use chrono::{Local, TimeZone, Utc};
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use serde_json::Value;
    use std::fs::File;
    use std::fs::{read_to_string, remove_file};
    use std::io;
    use std::path::Path;

    #[test]
    fn test_emit_csv_output() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: false,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
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
                + test_level
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
                + test_rulepath
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
                + test_level
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
                + test_rulepath
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n";
        let mut file: Box<dyn io::Write> = Box::new(File::create("./test_emit_csv.csv").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
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
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: Some("verbose-2".to_string()),
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv_multiline.csv").to_path_buf()),
            multiline: true,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: Some("verbose-2".to_string()),
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                ("AllFieldInfo", Profile::AllFieldInfo(test_recinfo.into())),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
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
                + test_level
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
                + test_level
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
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_multiline.csv").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
        match read_to_string("./test_emit_csv_multiline.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv_multiline.csv").is_ok());
    }

    #[test]
    fn test_emit_csv_output_with_remove_duplicate_opt() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: true,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv_remove_duplicate.csv").to_path_buf()),
            multiline: false,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, false),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
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
                + test_level
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
                + test_rulepath
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
                + test_level
                + "\","
                + test_eventid
                + ",\""
                + test_attack
                + "\","
                + test_record_id
                + ",\""
                + test_title
                + "\",\"DUP\",\"DUP\",\""
                + test_rulepath
                + "\",\""
                + test_filepath
                + "\",\""
                + test_attack
                + "\"\n";
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_remove_duplicate.csv").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
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
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: true,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv_remove_duplicate.json").to_path_buf()),
            jsonl_timeline: false,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: true,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map,
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
            *profile_converter.get_mut("Computer").unwrap() =
                Profile::Computer(test_computername.into());

            let detect_info2 = message::create_message(
                &event,
                CompactString::new(output),
                DetectInfo {
                    detected_time: expect_time,
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map: HashMap::default(),
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info2);
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
                    CompactString::from("\"".to_string() + test_level + "\""),
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
                    CompactString::from("\"".to_string() + test_rulepath + "\""),
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
                    CompactString::from("\"".to_string() + test_level + "\""),
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
                    CompactString::from("\"".to_string() + test_rulepath + "\""),
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

        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_remove_duplicate.json").unwrap());
        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
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
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: true,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_multiple_data_in_details.json").to_path_buf()),
            jsonl_timeline: false,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: true,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map,
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(detect_info);
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
                    CompactString::from("\"".to_string() + test_level + "\""),
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
                    CompactString::from("{\n        \"CommandRLine\": \"hoge\",\n        \"Data\": [\"xxx\", \"yyy\"]\n    }"),
                ),
                (
                    "RuleFile",
                    CompactString::from("\"".to_string() + test_rulepath + "\""),
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

        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_multiple_data_in_details.json").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
        match read_to_string("./test_multiple_data_in_details.json") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect_str);
            }
        };
        assert!(remove_file("./test_multiple_data_in_details.json").is_ok());
    }

    fn check_hashmap_data(
        target: HashMap<CompactString, Colors>,
        expected: HashMap<CompactString, Colors>,
    ) {
        assert_eq!(target.len(), expected.len());
        for (k, v) in target {
            assert!(expected.get(&k).is_some());
            assert_eq!(format!("{v:?}"), format!("{:?}", expected.get(&k).unwrap()));
        }
    }

    #[test]
    /// To confirm that empty character color mapping data is returned when the no_color flag is given.
    fn test_set_output_color_no_color_flag() {
        let expect: HashMap<CompactString, Colors> = HashMap::new();
        check_hashmap_data(create_output_color_map(true), expect);
    }

    #[test]
    fn test_emit_csv_json_output() {
        let mut additional_afterfact = AfterfactInfo::default();
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv_json.json").to_path_buf()),
            jsonl_timeline: false,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: true,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map,
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(message_detect_info);
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
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_json.json").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
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
        let mock_ch_filter = message::create_output_filter_config(
            "test_files/config/channel_abbreviations.txt",
            true,
        );
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_rule_id: &str = "00000000-0000-0000-0000-000000000000";
        let test_title = "test_title";
        let test_level = "high";
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv_jsonl.jsonl").to_path_buf()),
            jsonl_timeline: true,
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
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: true,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
            };
            let ch = mock_ch_filter
                .get(&CompactString::from("security"))
                .unwrap_or(&CompactString::default())
                .clone();
            let mut profile_converter: HashMap<&str, Profile> = HashMap::from([
                (
                    "Timestamp",
                    Profile::Timestamp(format_time(&expect_time, false, &output_option).into()),
                ),
                ("Computer", Profile::Computer(test_computername2.into())),
                ("Channel", Profile::Channel(ch.into())),
                ("Level", Profile::Level(test_level.into())),
                ("EventID", Profile::EventID(test_eventid.into())),
                ("MitreAttack", Profile::MitreTactics(test_attack.into())),
                ("RecordID", Profile::RecordID(test_record_id.into())),
                ("RuleTitle", Profile::RuleTitle(test_title.into())),
                (
                    "RecordInformation",
                    Profile::AllFieldInfo(test_recinfo.into()),
                ),
                ("RuleFile", Profile::RuleFile(test_rulepath.into())),
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
                    rulepath: CompactString::from(test_rulepath),
                    ruleid: test_rule_id.into(),
                    ruletitle: CompactString::from(test_title),
                    level: CompactString::from(test_level),
                    computername: CompactString::from(test_computername2),
                    eventid: CompactString::from(test_eventid),
                    detail: CompactString::default(),
                    ext_field: output_profile.to_owned(),
                    is_condition: false,
                    details_convert_map,
                },
                &profile_converter,
                (false, true),
                (&eventkey_alias, &FieldDataMapKey::default(), &None),
            );
            additional_afterfact.detect_infos.push(message_detect_info);
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
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_jsonl.jsonl").unwrap());

        additional_afterfact.record_cnt = 1;
        additional_afterfact.recover_record_cnt = 0;
        additional_afterfact.tl_starttime = Some(expect_tz);
        additional_afterfact.tl_endtime = Some(expect_tz);
        assert!(output_afterfact(
            &mut file,
            false,
            &output_profile,
            &stored_static,
            additional_afterfact,
        )
        .is_ok());
        match read_to_string("./test_emit_csv_jsonl.jsonl") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, format!("{} }}", expect.join("")));
            }
        };
        assert!(remove_file("./test_emit_csv_jsonl.jsonl").is_ok());
    }
}

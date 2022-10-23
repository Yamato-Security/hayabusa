use crate::detections::configs::{self, CURRENT_EXE_PATH, TERM_SIZE};
use crate::detections::message::{self, AlertMessage, LEVEL_ABBR, LEVEL_FULL};
use crate::detections::utils::{self, format_time, get_writable_color, write_color_buffer};
use crate::options::htmlreport::{self, HTML_REPORT_FLAG};
use crate::options::profile::PROFILES;
use crate::yaml::ParseYaml;
use chrono::{DateTime, Local, TimeZone, Utc};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;

use csv::{QuoteStyle, WriterBuilder};
use itertools::Itertools;
use krapslog::{build_sparkline, build_time_markers};
use lazy_static::lazy_static;
use linked_hash_map::LinkedHashMap;
use std::path::Path;
use std::str::FromStr;
use yaml_rust::YamlLoader;

use comfy_table::*;
use hashbrown::{HashMap, HashSet};
use num_format::{Locale, ToFormattedString};
use std::cmp::min;
use std::error::Error;

use std::io::{self, BufWriter, Write};

use std::fs::File;
use std::process;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use terminal_size::Width;

lazy_static! {
    pub static ref OUTPUT_COLOR: HashMap<String, Colors> = set_output_color();
}

pub struct Colors {
    pub output_color: termcolor::Color,
    pub table_color: comfy_table::Color,
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn set_output_color() -> HashMap<String, Colors> {
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
    let mut color_map: HashMap<String, Colors> = HashMap::new();
    if configs::CONFIG.read().unwrap().args.no_color {
        return color_map;
    }
    if read_result.is_err() {
        // color情報がない場合は通常の白色の出力が出てくるのみで動作への影響を与えない為warnとして処理する
        AlertMessage::warn(read_result.as_ref().unwrap_err()).ok();
        return color_map;
    }
    read_result.unwrap().into_iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }
        let empty = &"".to_string();
        let level = line.get(0).unwrap_or(empty);
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
            level.to_lowercase(),
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

fn _get_output_color(color_map: &HashMap<String, Colors>, level: &str) -> Option<Color> {
    let mut color = None;
    if let Some(c) = color_map.get(&level.to_lowercase()) {
        color = Some(c.output_color.to_owned());
    }
    color
}

fn _get_table_color(
    color_map: &HashMap<String, Colors>,
    level: &str,
) -> Option<comfy_table::Color> {
    let mut color = None;
    if let Some(c) = color_map.get(&level.to_lowercase()) {
        color = Some(c.table_color.to_owned());
    }
    color
}

/// print timeline histogram
fn _print_timeline_hist(timestamps: Vec<i64>, length: usize, side_margin_size: usize) {
    if timestamps.is_empty() {
        return;
    }

    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    if timestamps.len() < 5 {
        writeln!(
            wtr,
            "Event Frequency Timeline could not be displayed as there needs to be more than 5 events.",
        )
        .ok();
        buf_wtr.print(&wtr).ok();
        return;
    }

    let title = "Event Frequency Timeline";
    let header_row_space = (length - title.len()) / 2;
    writeln!(wtr, "{}{}", " ".repeat(header_row_space), title).ok();
    println!();

    let timestamp_marker_max = if timestamps.len() < 2 {
        0
    } else {
        timestamps.len() - 2
    };
    let marker_num = min(timestamp_marker_max, 10);

    let (header_raw, footer_raw) =
        build_time_markers(&timestamps, marker_num, length - (side_margin_size * 2));
    let sparkline = build_sparkline(&timestamps, length - (side_margin_size * 2));
    for header_str in header_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), header_str).ok();
    }
    writeln!(
        wtr,
        "{}{}",
        " ".repeat(side_margin_size - 1),
        sparkline.unwrap_or_default()
    )
    .ok();
    for footer_str in footer_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), footer_str).ok();
    }

    buf_wtr.print(&wtr).ok();
}

pub fn after_fact(all_record_cnt: usize) {
    let fn_emit_csv_err = |err: Box<dyn Error>| {
        AlertMessage::alert(&format!("Failed to write CSV. {}", err)).ok();
        process::exit(1);
    };

    let mut displayflag = false;
    let mut target: Box<dyn io::Write> =
        if let Some(csv_path) = &configs::CONFIG.read().unwrap().args.output {
            // output to file
            match File::create(csv_path) {
                Ok(file) => Box::new(BufWriter::new(file)),
                Err(err) => {
                    AlertMessage::alert(&format!("Failed to open file. {}", err)).ok();
                    process::exit(1);
                }
            }
        } else {
            displayflag = true;
            // stdoutput (termcolor crate color output is not csv writer)
            Box::new(BufWriter::new(io::stdout()))
        };
    let color_map = set_output_color();
    if let Err(err) = emit_csv(
        &mut target,
        displayflag,
        color_map,
        all_record_cnt as u128,
        PROFILES.clone().unwrap_or_default(),
    ) {
        fn_emit_csv_err(Box::new(err));
    }
}

fn emit_csv<W: std::io::Write>(
    writer: &mut W,
    displayflag: bool,
    color_map: HashMap<String, Colors>,
    all_record_cnt: u128,
    profile: LinkedHashMap<String, String>,
) -> io::Result<()> {
    let mut html_output_stock: Vec<String> = vec![];
    let html_output_flag = *HTML_REPORT_FLAG;
    let disp_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut disp_wtr_buf = disp_wtr.buffer();
    let json_output_flag = configs::CONFIG.read().unwrap().args.json_timeline;
    let jsonl_output_flag = configs::CONFIG.read().unwrap().args.jsonl_timeline;

    let mut wtr = if json_output_flag || jsonl_output_flag {
        WriterBuilder::new()
            .delimiter(b'\n')
            .double_quote(false)
            .quote_style(QuoteStyle::Never)
            .from_writer(writer)
    } else {
        WriterBuilder::new().from_writer(writer)
    };

    disp_wtr_buf.set_color(ColorSpec::new().set_fg(None)).ok();

    // level is devided by "Critical","High","Medium","Low","Informational","Undefined".
    let mut total_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut unique_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut detected_rule_files: HashSet<String> = HashSet::new();
    let mut detected_computer_and_rule_names: HashSet<String> = HashSet::new();
    let mut detect_counts_by_date_and_level: HashMap<String, HashMap<String, u128>> =
        HashMap::new();
    let mut detect_counts_by_computer_and_level: HashMap<String, HashMap<String, i128>> =
        HashMap::new();
    let mut detect_counts_by_rule_and_level: HashMap<String, HashMap<String, i128>> =
        HashMap::new();
    let mut rule_title_path_map: HashMap<String, String> = HashMap::new();
    let mut rule_author_counter: HashMap<String, i128> = HashMap::new();

    let levels = Vec::from(["crit", "high", "med ", "low ", "info", "undefined"]);
    // レベル別、日ごとの集計用変数の初期化
    for level_init in levels {
        detect_counts_by_date_and_level.insert(level_init.to_string(), HashMap::new());
        detect_counts_by_computer_and_level.insert(level_init.to_string(), HashMap::new());
        detect_counts_by_rule_and_level.insert(level_init.to_string(), HashMap::new());
    }
    if displayflag {
        println!();
    }
    let mut timestamps: Vec<i64> = Vec::new();
    let mut plus_header = true;
    let mut detected_record_idset: HashSet<String> = HashSet::new();

    for (_, time) in message::MESSAGES
        .clone()
        .into_read_only()
        .keys()
        .sorted()
        .enumerate()
    {
        let multi = message::MESSAGES.get(time).unwrap();
        let (_, detect_infos) = multi.pair();
        timestamps.push(_get_timestamp(time));
        for (_, detect_info) in detect_infos.iter().enumerate() {
            if !detect_info.detail.starts_with("[condition]") {
                detected_record_idset.insert(format!("{}_{}", time, detect_info.eventid));
            }
            if displayflag {
                //ヘッダーのみを出力
                if plus_header {
                    write_color_buffer(
                        &disp_wtr,
                        get_writable_color(None),
                        &_get_serialized_disp_output(&profile, true),
                        false,
                    )
                    .ok();
                    plus_header = false;
                }
                write_color_buffer(
                    &disp_wtr,
                    get_writable_color(_get_output_color(
                        &color_map,
                        LEVEL_FULL
                            .get(&detect_info.level)
                            .unwrap_or(&String::default()),
                    )),
                    &_get_serialized_disp_output(&detect_info.ext_field, false),
                    false,
                )
                .ok();
            } else if json_output_flag {
                // JSON output
                wtr.write_field("{")?;
                wtr.write_field(&output_json_str(
                    &detect_info.ext_field,
                    &profile,
                    jsonl_output_flag,
                ))?;
                wtr.write_field("}")?;
            } else if jsonl_output_flag {
                // JSONL output format
                wtr.write_field(format!(
                    "{{ {} }}",
                    &output_json_str(&detect_info.ext_field, &profile, jsonl_output_flag)
                ))?;
            } else {
                // csv output format
                if plus_header {
                    wtr.write_record(detect_info.ext_field.keys().map(|x| x.trim()))?;
                    plus_header = false;
                }
                wtr.write_record(detect_info.ext_field.values().map(|x| x.trim()))?;
            }

            let level_suffix = *configs::LEVELMAP
                .get(
                    &LEVEL_FULL
                        .get(&detect_info.level)
                        .unwrap_or(&"undefined".to_string())
                        .to_uppercase(),
                )
                .unwrap_or(&0) as usize;
            let time_str_date = format_time(time, true);

            let mut detect_counts_by_date = detect_counts_by_date_and_level
                .get(&detect_info.level.to_lowercase())
                .unwrap_or_else(|| detect_counts_by_date_and_level.get("undefined").unwrap())
                .clone();
            *detect_counts_by_date
                .entry(time_str_date.to_string())
                .or_insert(0) += 1;
            if !detected_rule_files.contains(&detect_info.rulepath) {
                detected_rule_files.insert(detect_info.rulepath.clone());
                for author in extract_author_name(detect_info.rulepath.clone()) {
                    *rule_author_counter.entry(author).or_insert(1) += 1;
                }
                unique_detect_counts_by_level[level_suffix] += 1;
            }

            let computer_rule_check_key =
                format!("{}|{}", &detect_info.computername, &detect_info.rulepath);
            if !detected_computer_and_rule_names.contains(&computer_rule_check_key) {
                detected_computer_and_rule_names.insert(computer_rule_check_key);
                let mut detect_counts_by_computer = detect_counts_by_computer_and_level
                    .get(&detect_info.level.to_lowercase())
                    .unwrap_or_else(|| {
                        detect_counts_by_computer_and_level
                            .get("undefined")
                            .unwrap()
                    })
                    .clone();
                *detect_counts_by_computer
                    .entry(Clone::clone(&detect_info.computername))
                    .or_insert(0) += 1;
                detect_counts_by_computer_and_level
                    .insert(detect_info.level.to_lowercase(), detect_counts_by_computer);
            }

            let mut detect_counts_by_rules = detect_counts_by_rule_and_level
                .get(&detect_info.level.to_lowercase())
                .unwrap_or_else(|| {
                    detect_counts_by_computer_and_level
                        .get("undefined")
                        .unwrap()
                })
                .clone();
            rule_title_path_map.insert(detect_info.ruletitle.clone(), detect_info.rulepath.clone());
            *detect_counts_by_rules
                .entry(Clone::clone(&detect_info.ruletitle))
                .or_insert(0) += 1;
            detect_counts_by_rule_and_level
                .insert(detect_info.level.to_lowercase(), detect_counts_by_rules);

            total_detect_counts_by_level[level_suffix] += 1;
            detect_counts_by_date_and_level
                .insert(detect_info.level.to_lowercase(), detect_counts_by_date);
        }
    }

    if displayflag {
        println!();
    } else {
        wtr.flush()?;
    }

    disp_wtr_buf.clear();
    write_color_buffer(
        &disp_wtr,
        get_writable_color(Some(Color::Rgb(0, 255, 0))),
        "Rule Authors:",
        false,
    )
    .ok();
    write_color_buffer(&disp_wtr, get_writable_color(None), " ", true).ok();

    println!();
    output_detected_rule_authors(rule_author_counter);
    println!();

    if !configs::CONFIG.read().unwrap().args.no_summary {
        disp_wtr_buf.clear();
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(0, 255, 0))),
            "Results Summary:",
            true,
        )
        .ok();

        let terminal_width = match *TERM_SIZE {
            Some((Width(w), _)) => w as usize,
            None => 100,
        };
        println!();

        if configs::CONFIG.read().unwrap().args.visualize_timeline {
            _print_timeline_hist(timestamps, terminal_width, 3);
            println!();
        }
        let reducted_record_cnt: u128 = all_record_cnt - detected_record_idset.len() as u128;
        let reducted_percent = if all_record_cnt == 0 {
            0 as f64
        } else {
            (reducted_record_cnt as f64) / (all_record_cnt as f64) * 100.0
        };
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(255, 255, 0))),
            "Events with hits",
            false,
        )
        .ok();
        write_color_buffer(&disp_wtr, get_writable_color(None), " / ", false).ok();
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(0, 255, 255))),
            "Total events",
            false,
        )
        .ok();
        write_color_buffer(&disp_wtr, get_writable_color(None), ": ", false).ok();
        let saved_alerts_output =
            (all_record_cnt - reducted_record_cnt).to_formatted_string(&Locale::en);
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(255, 255, 0))),
            &saved_alerts_output,
            false,
        )
        .ok();
        write_color_buffer(&disp_wtr, get_writable_color(None), " / ", false).ok();

        let all_record_output = all_record_cnt.to_formatted_string(&Locale::en);
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(0, 255, 255))),
            &all_record_output,
            false,
        )
        .ok();
        write_color_buffer(&disp_wtr, get_writable_color(None), " (", false).ok();
        let reduction_output = format!(
            "Data reduction: {} events ({:.2}%)",
            reducted_record_cnt.to_formatted_string(&Locale::en),
            reducted_percent
        );
        write_color_buffer(
            &disp_wtr,
            get_writable_color(Some(Color::Rgb(0, 255, 0))),
            &reduction_output,
            false,
        )
        .ok();

        write_color_buffer(&disp_wtr, get_writable_color(None), ")", false).ok();
        println!();
        println!();

        if html_output_flag {
            html_output_stock.push(format!("- Events with hits: {}", &saved_alerts_output));
            html_output_stock.push(format!("- Total events analyzed: {}", &all_record_output));
            html_output_stock.push(format!("- {}", reduction_output));
        }

        _print_unique_results(
            total_detect_counts_by_level,
            unique_detect_counts_by_level,
            "Total | Unique".to_string(),
            "detections".to_string(),
            &color_map,
            &mut html_output_stock,
        );
        println!();

        _print_detection_summary_by_date(
            detect_counts_by_date_and_level,
            &color_map,
            &mut html_output_stock,
        );
        println!();
        println!();
        if html_output_flag {
            html_output_stock.push("".to_string());
        }

        _print_detection_summary_by_computer(
            detect_counts_by_computer_and_level,
            &color_map,
            &mut html_output_stock,
        );
        println!();
        if html_output_flag {
            html_output_stock.push("".to_string());
        }

        _print_detection_summary_tables(
            detect_counts_by_rule_and_level,
            &color_map,
            rule_title_path_map,
            &mut html_output_stock,
        );
        println!();
        if html_output_flag {
            html_output_stock.push("".to_string());
        }
    }
    if html_output_flag {
        htmlreport::add_md_data(
            "Results Summary {#results_summary}".to_string(),
            html_output_stock,
        );
    }
    Ok(())
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

fn _get_serialized_disp_output(data: &LinkedHashMap<String, String>, header: bool) -> String {
    let data_length = &data.len();
    let mut ret: Vec<String> = vec![];
    if header {
        for (i, k) in data.keys().enumerate() {
            if i == 0 {
                ret.push(_format_cellpos(k, ColPos::First))
            } else if i == data_length - 1 {
                ret.push(_format_cellpos(k, ColPos::Last))
            } else {
                ret.push(_format_cellpos(k, ColPos::Other))
            }
        }
    } else {
        for (i, (_, v)) in data.iter().enumerate() {
            if i == 0 {
                ret.push(_format_cellpos(v, ColPos::First).replace('|', "🦅"))
            } else if i == data_length - 1 {
                ret.push(_format_cellpos(v, ColPos::Last).replace('|', "🦅"))
            } else {
                ret.push(_format_cellpos(v, ColPos::Other).replace('|', "🦅"))
            }
        }
    }
    let mut disp_serializer = WriterBuilder::new()
        .double_quote(false)
        .quote_style(QuoteStyle::Never)
        .delimiter(b'|')
        .has_headers(false)
        .from_writer(vec![]);

    disp_serializer.write_record(ret).ok();
    String::from_utf8(disp_serializer.into_inner().unwrap_or_default())
        .unwrap_or_default()
        .replace('|', "‖")
        .replace('🦅', "|")
}

/// return str position in output file
fn _format_cellpos(colval: &str, column: ColPos) -> String {
    match column {
        ColPos::First => format!("{} ", colval),
        ColPos::Last => format!(" {}", colval),
        ColPos::Other => format!(" {} ", colval),
    }
}

/// output info which unique detection count and all detection count information(separated by level and total) to stdout.
fn _print_unique_results(
    mut counts_by_level: Vec<u128>,
    mut unique_counts_by_level: Vec<u128>,
    head_word: String,
    tail_word: String,
    color_map: &HashMap<String, Colors>,
    html_output_stock: &mut Vec<String>,
) {
    // the order in which are registered and the order of levels to be displayed are reversed
    counts_by_level.reverse();
    unique_counts_by_level.reverse();

    let total_count = counts_by_level.iter().sum::<u128>();
    let unique_total_count = unique_counts_by_level.iter().sum::<u128>();
    // output total results
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        None,
        &format!(
            "{} {}: {} | {}",
            head_word,
            tail_word,
            total_count.to_formatted_string(&Locale::en),
            unique_total_count.to_formatted_string(&Locale::en)
        ),
        true,
    )
    .ok();

    let mut total_detect_md = vec!["- Total detections:".to_string()];
    let mut unique_detect_md = vec!["- Unique detecions:".to_string()];

    for (i, level_name) in LEVEL_ABBR.keys().enumerate() {
        if "undefined" == *level_name {
            continue;
        }
        let percent = if total_count == 0 {
            0 as f64
        } else {
            (counts_by_level[i] as f64) / (total_count as f64) * 100.0
        };
        let unique_percent = if unique_total_count == 0 {
            0 as f64
        } else {
            (unique_counts_by_level[i] as f64) / (unique_total_count as f64) * 100.0
        };
        if configs::CONFIG.read().unwrap().args.html_report.is_some() {
            total_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name,
                counts_by_level[i].to_formatted_string(&Locale::en),
                percent
            ));
            unique_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name,
                unique_counts_by_level[i].to_formatted_string(&Locale::en),
                unique_percent
            ));
        }
        let output_raw_str = format!(
            "{} {} {}: {} ({:.2}%) | {} ({:.2}%)",
            head_word,
            level_name,
            tail_word,
            counts_by_level[i].to_formatted_string(&Locale::en),
            percent,
            unique_counts_by_level[i].to_formatted_string(&Locale::en),
            unique_percent
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            _get_output_color(color_map, level_name),
            &output_raw_str,
            true,
        )
        .ok();
    }
    if configs::CONFIG.read().unwrap().args.html_report.is_some() {
        html_output_stock.append(&mut total_detect_md);
        html_output_stock.append(&mut unique_detect_md);
    }
}

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_date(
    detect_counts_by_date: HashMap<String, HashMap<String, u128>>,
    color_map: &HashMap<String, Colors>,
    html_output_stock: &mut Vec<String>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let output_header = "Dates with most total detections:";
    writeln!(wtr, "{}", output_header).ok();
    if *HTML_REPORT_FLAG {
        html_output_stock.push(format!("- {}", output_header));
    }
    for (idx, level) in LEVEL_ABBR.values().enumerate() {
        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_day = detect_counts_by_date.get(level).unwrap();
        let mut max_detect_str = String::default();
        let mut tmp_cnt: u128 = 0;
        let mut exist_max_data = false;
        for (date, cnt) in detections_by_day {
            if cnt > &tmp_cnt {
                exist_max_data = true;
                max_detect_str = format!("{} ({})", date, cnt.to_formatted_string(&Locale::en));
                tmp_cnt = *cnt;
            }
        }
        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(
            color_map,
            LEVEL_FULL.get(level.as_str()).unwrap(),
        )))
        .ok();
        if !exist_max_data {
            max_detect_str = "n/a".to_string();
        }
        let output_str = format!(
            "{}: {}",
            LEVEL_FULL.get(level.as_str()).unwrap(),
            &max_detect_str
        );
        write!(wtr, "{}", output_str).ok();
        if idx != LEVEL_ABBR.len() - 1 {
            wtr.set_color(ColorSpec::new().set_fg(None)).ok();
            write!(wtr, ", ").ok();
        }
        if *HTML_REPORT_FLAG {
            html_output_stock.push(format!("    - {}", output_str));
        }
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベル毎で最も高い検知数を出したコンピュータ名を出力する
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: HashMap<String, HashMap<String, i128>>,
    color_map: &HashMap<String, Colors>,
    html_output_stock: &mut Vec<String>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    writeln!(wtr, "Top 5 computers with most unique detections:").ok();
    for level in LEVEL_ABBR.values() {
        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_computer = detect_counts_by_computer.get(level).unwrap();
        let mut result_vec: Vec<String> = Vec::new();
        //computer nameで-となっているものは除外して集計する
        let mut sorted_detections: Vec<(&String, &i128)> = detections_by_computer
            .iter()
            .filter(|a| a.0 != "-")
            .collect();

        sorted_detections.sort_by(|a, b| (-a.1).cmp(&(-b.1)));

        // html出力は各種すべてのコンピュータ名を表示するようにする
        if *HTML_REPORT_FLAG {
            html_output_stock.push(format!(
                "### Computers with most unique {} detections: {{#computers_with_most_unique_{}_detections}}",
                LEVEL_FULL.get(level.as_str()).unwrap(),
                LEVEL_FULL.get(level.as_str()).unwrap()
            ));
            for x in sorted_detections.iter() {
                html_output_stock.push(format!(
                    "- {} ({})",
                    x.0,
                    x.1.to_formatted_string(&Locale::en)
                ));
            }
            html_output_stock.push("".to_string());
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
            result_vec.join(", ")
        };

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(
            color_map,
            LEVEL_FULL.get(level.as_str()).unwrap(),
        )))
        .ok();
        writeln!(
            wtr,
            "{}: {}",
            LEVEL_FULL.get(level.as_str()).unwrap(),
            &result_str
        )
        .ok();
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベルごとで検出数が多かったルールを表形式で出力する関数
fn _print_detection_summary_tables(
    detect_counts_by_rule_and_level: HashMap<String, HashMap<String, i128>>,
    color_map: &HashMap<String, Colors>,
    rule_title_path_map: HashMap<String, String>,
    html_output_stock: &mut Vec<String>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let mut output = vec![];
    let mut col_color = vec![];
    for level in LEVEL_ABBR.values() {
        let mut col_output: Vec<String> = vec![];
        col_output.push(format!(
            "Top {} alerts:",
            LEVEL_FULL.get(level.as_str()).unwrap()
        ));

        col_color.push(_get_table_color(
            color_map,
            LEVEL_FULL.get(level.as_str()).unwrap(),
        ));

        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_computer = detect_counts_by_rule_and_level.get(level).unwrap();
        let mut sorted_detections: Vec<(&String, &i128)> = detections_by_computer.iter().collect();

        sorted_detections.sort_by(|a, b| (-a.1).cmp(&(-b.1)));

        // html出力の場合はすべての内容を出力するようにする
        if *HTML_REPORT_FLAG {
            html_output_stock.push(format!(
                "### Top {} alerts: {{#top_{}_alerts}}",
                LEVEL_FULL.get(level.as_str()).unwrap(),
                LEVEL_FULL.get(level.as_str()).unwrap()
            ));
            for x in sorted_detections.iter() {
                html_output_stock.push(format!(
                    "- [{}]({}) ({})",
                    x.0,
                    rule_title_path_map
                        .get(x.0)
                        .unwrap_or(&"<Not Found Path>".to_string())
                        .replace('\\', "/"),
                    x.1.to_formatted_string(&Locale::en)
                ));
            }
            html_output_stock.push("".to_string());
        }

        let take_cnt =
            if LEVEL_FULL.get(level.as_str()).unwrap_or(&"-".to_string()) == "informational" {
                10
            } else {
                5
            };
        for x in sorted_detections.iter().take(take_cnt) {
            col_output.push(format!(
                "{} ({})",
                x.0,
                x.1.to_formatted_string(&Locale::en)
            ));
        }
        let na_cnt = if sorted_detections.len() > take_cnt {
            0
        } else {
            take_cnt - sorted_detections.len()
        };
        for _x in 0..na_cnt {
            col_output.push("n/a".to_string());
        }
        output.push(col_output);
    }

    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    for x in 0..output.len() / 2 {
        let hlch = tb.style(TableComponent::HorizontalLines).unwrap();
        let tbch = tb.style(TableComponent::TopBorder).unwrap();

        tb.add_row(vec![
            Cell::new(&output[2 * x][0]).fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(&output[2 * x + 1][0])
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ])
        .set_style(TableComponent::MiddleIntersections, hlch)
        .set_style(TableComponent::TopBorderIntersections, tbch)
        .set_style(TableComponent::BottomBorderIntersections, hlch);

        tb.add_row(vec![
            Cell::new(&output[2 * x][1..].join("\n"))
                .fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(&output[2 * x + 1][1..].join("\n"))
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ]);
    }

    let odd_row = &output[4][1..6];
    let even_row = &output[4][6..11];
    tb.add_row(vec![
        Cell::new(&output[4][0]).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
        Cell::new(""),
    ]);
    tb.add_row(vec![
        Cell::new(odd_row.join("\n")).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
        Cell::new(even_row.join("\n")).fg(col_color[4].unwrap_or(comfy_table::Color::Reset)),
    ]);
    println!("{tb}");
}

/// get timestamp to input datetime.
fn _get_timestamp(time: &DateTime<Utc>) -> i64 {
    if configs::CONFIG.read().unwrap().args.utc {
        time.timestamp()
    } else {
        let offset_sec = Local.timestamp(0, 0).offset().local_minus_utc();
        offset_sec as i64 + time.with_timezone(&Local).timestamp()
    }
}

/// json出力の際に配列として対応させるdetails,MitreTactics,MitreTags,OtherTagsに該当する場合に配列を返す関数
fn _get_json_vec(target_alias_context: &str, target_data: &String) -> Vec<String> {
    if target_alias_context.contains("%MitreTactics%")
        || target_alias_context.contains("%OtherTags%")
        || target_alias_context.contains("%MitreTags%")
    {
        let ret: Vec<String> = target_data
            .to_owned()
            .split(": ")
            .map(|x| x.to_string())
            .collect();
        ret
    } else if target_alias_context.contains("%Details%") || target_alias_context.contains("%AllFieldInfo%") {
        let ret: Vec<String> = target_data
            .to_owned()
            .split(" ¦ ")
            .map(|x| x.to_string())
            .collect();
        if target_data == &ret[0] && !target_data.contains(": ") {
            vec![]
        } else {
            ret
        }
    } else {
        vec![]
    }
}

/// JSONの出力フォーマットに合わせた文字列を出力する関数
fn _create_json_output_format(
    key: &String,
    value: &str,
    key_quote_exclude_flag: bool,
    concat_flag: bool,
    space_cnt: usize,
) -> String {
    let head = if key_quote_exclude_flag {
        key.to_string()
    } else {
        format!("\"{}\"", key)
    };
    // 4 space is json indent.
    if let Ok(i) = i64::from_str(value) {
        format!("{}{}: {}", " ".repeat(space_cnt), head, i)
    } else if let Ok(b) = bool::from_str(value) {
        format!("{}{}: {}", " ".repeat(space_cnt), head, b)
    } else if concat_flag {
        format!("{}{}: {}", " ".repeat(space_cnt), head, value)
    } else {
        format!("{}{}: \"{}\"", " ".repeat(space_cnt), head, value)
    }
}

/// JSONの値に対して文字列の出力形式をJSON出力でエラーにならないようにするための変換を行う関数
fn _convert_valid_json_str(input: &[&str], concat_flag: bool) -> String {
    let tmp = if input.len() == 1 {
        input[0].to_string()
    } else if concat_flag {
        input.join(": ")
    } else {
        input[1..].join(": ")
    };
    let char_cnt = tmp.char_indices().count();
    let con_val = tmp.as_str();
    if char_cnt == 0 {
        tmp
    } else if con_val.starts_with('\"') {
        let addition_header = if !con_val.starts_with('\"') { "\"" } else { "" };
        let addition_quote = if !con_val.ends_with('\"') && concat_flag {
            "\""
        } else if !con_val.ends_with('\"') {
            "\\\""
        } else {
            ""
        };
        [
            addition_header,
            con_val
                .to_string()
                .replace('\\', "\\\\")
                .replace('\"', "\\\"")
                .trim(),
            addition_quote,
        ]
        .join("")
    } else {
        con_val
            .replace('\\', "\\\\")
            .replace('\"', "\\\"")
            .trim()
            .to_string()
    }
}

/// JSONに出力する1検知分のオブジェクトの文字列を出力する関数
fn output_json_str(
    ext_field: &LinkedHashMap<String, String>,
    profile: &LinkedHashMap<String, String>,
    jsonl_output_flag: bool,
) -> String {
    let mut target: Vec<String> = vec![];
    for (k, v) in ext_field.iter() {
        let output_value_fmt = profile.get(k).unwrap();
        let vec_data = _get_json_vec(output_value_fmt, v);
        if vec_data.is_empty() {
            let tmp_val: Vec<&str> = v.split(": ").collect();
            let output_val =
                _convert_valid_json_str(&tmp_val, output_value_fmt.contains("%AllFieldInfo%"));
            target.push(_create_json_output_format(
                k,
                &output_val,
                k.starts_with('\"'),
                output_val.starts_with('\"'),
                4,
            ));
        } else if output_value_fmt.contains("%Details%") || output_value_fmt.contains("%AllFieldInfo%") {
            let mut output_stock: Vec<String> = vec![];
            output_stock.push(format!("    \"{}\": {{", k));
            let mut stocked_value = vec![];
            let mut key_index_stock = vec![];
            for detail_contents in vec_data.iter() {
                // 分解してキーとなりえる箇所を抽出する
                let space_split: Vec<&str> = detail_contents.split(' ').collect();
                let mut tmp_stock = vec![];
                for sp in space_split.iter() {
                    if sp.ends_with(':') && sp.len() > 2 {
                        stocked_value.push(tmp_stock);
                        tmp_stock = vec![];
                        key_index_stock.push(sp.replace(':', "").to_owned());
                    } else {
                        tmp_stock.push(sp.to_owned());
                    }
                }
                stocked_value.push(tmp_stock);
            }
            let mut key_idx = 0;
            let mut output_value_stock = String::default();
            for (value_idx, value) in stocked_value.iter().enumerate() {
                let mut tmp = if key_idx >= key_index_stock.len() {
                    String::default()
                } else if value_idx == 0 && !value.is_empty() {
                    k.to_string()
                } else {
                    key_index_stock[key_idx].to_string()
                };
                if !output_value_stock.is_empty() {
                    output_value_stock.push_str(" | ");
                }
                output_value_stock.push_str(&value.join(" "));
                //``1つまえのキーの段階で以降にvalueの配列で区切りとなる空の配列が存在しているかを確認する
                let is_remain_split_stock = if key_idx == key_index_stock.len() - 2
                    && value_idx < stocked_value.len() - 1
                    && !output_value_stock.is_empty()
                {
                    let mut ret = true;
                    for remain_value in stocked_value[value_idx + 1..].iter() {
                        if remain_value.is_empty() {
                            ret = false;
                            break;
                        }
                    }
                    ret
                } else {
                    false
                };
                let prefix_flag = output_value_fmt.contains("%AllFieldInfo%");
                if (value_idx < stocked_value.len() - 1 && stocked_value[value_idx + 1].is_empty())
                    || is_remain_split_stock
                {
                    // 次の要素を確認して、存在しないもしくは、キーが入っているとなった場合現在ストックしている内容が出力していいことが確定するので出力処理を行う
                    let output_tmp = format!("{}: {}", tmp, output_value_stock);
                    let output: Vec<&str> = output_tmp.split(": ").collect();
                    let key = if prefix_flag{
                        format!("HBFI-{}", _convert_valid_json_str(&[output[0]], false))
                    } else {
                        _convert_valid_json_str(&[output[0]], false)
                    };
                    let fmted_val = _convert_valid_json_str(&output, false);
                    output_stock.push(format!(
                        "{},",
                        _create_json_output_format(
                            &key,
                            &fmted_val,
                            key.starts_with('\"'),
                            fmted_val.starts_with('\"'),
                            8
                        )
                    ));
                    output_value_stock.clear();
                    tmp = String::default();
                    key_idx += 1;
                }
                if value_idx == stocked_value.len() - 1 {
                    let output_tmp = format!("{}: {}", tmp, output_value_stock);
                    let output: Vec<&str> = output_tmp.split(": ").collect();
                    let key = if prefix_flag{
                        format!("HBFI-{}", _convert_valid_json_str(&[output[0]], false))
                    } else {
                        _convert_valid_json_str(&[output[0]], false)
                    };
                    let fmted_val = _convert_valid_json_str(&output, false);
                    output_stock.push(_create_json_output_format(
                        &key,
                        &fmted_val,
                        key.starts_with('\"'),
                        fmted_val.starts_with('\"'),
                        8,
                    ));
                    key_idx += 1;
                }
            }
            output_stock.push("    }".to_string());
            target.push(output_stock.join("\n"));
        } else if output_value_fmt.contains("%MitreTags%")
            || output_value_fmt.contains("%MitreTactics%")
            || output_value_fmt.contains("%OtherTags%")
        {
            let tmp_val: Vec<&str> = v.split(": ").collect();

            let key = _convert_valid_json_str(&[k.as_str()], false);
            let values: Vec<&&str> = tmp_val.iter().filter(|x| x.trim() != "").collect();
            let mut value: Vec<String> = vec![];

            if values.is_empty() {
                continue;
            }
            for (idx, tag_val) in values.iter().enumerate() {
                if idx == 0 {
                    value.push("[\n".to_string());
                }
                let insert_val = format!("        \"{}\"", tag_val.trim());
                value.push(insert_val);
                if idx != values.len() - 1 {
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
                &fmted_val,
                key.starts_with('\"'),
                true,
                4,
            ));
        }
    }
    if jsonl_output_flag {
        // JSONL output
        target.into_iter().map(|x| x.replace("  ", "")).join(",")
    } else {
        // JSON format output
        target.join(",\n")
    }
}

/// output detected rule author name function.
fn output_detected_rule_authors(rule_author_counter: HashMap<String, i128>) {
    let mut sorted_authors: Vec<(&String, &i128)> = rule_author_counter.iter().collect();

    sorted_authors.sort_by(|a, b| (-a.1).cmp(&(-b.1)));
    let mut output = Vec::new();
    let div = if sorted_authors.len() % 4 != 0 {
        sorted_authors.len() / 4 + 1
    } else {
        sorted_authors.len() / 4
    };

    for x in 0..4 {
        let mut tmp = Vec::new();
        for y in 0..div {
            if y * 4 + x < sorted_authors.len() {
                let filter_author = if sorted_authors[y * 4 + x].0.len() <= 40 {
                    sorted_authors[y * 4 + x].0.to_string()
                } else {
                    format!("{}...", &sorted_authors[y * 4 + x].0[0..37])
                };
                tmp.push(format!(
                    "{} ({})",
                    filter_author,
                    sorted_authors[y * 4 + x].1
                ));
            }
        }
        output.push(tmp);
    }
    let mut tbrows = vec![];
    for c in output.iter() {
        tbrows.push(Cell::new(c.join("\n")).fg(comfy_table::Color::Reset));
    }
    let mut tb = Table::new();
    let hlch = tb.style(TableComponent::HorizontalLines).unwrap();
    let tbch = tb.style(TableComponent::TopBorder).unwrap();

    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    tb.add_row(tbrows)
        .set_style(TableComponent::MiddleIntersections, hlch)
        .set_style(TableComponent::TopBorderIntersections, tbch)
        .set_style(TableComponent::BottomBorderIntersections, hlch);
    println!("{tb}");
}

/// 与えられたyaml_pathからauthorの名前を抽出して配列で返却する関数
fn extract_author_name(yaml_path: String) -> Vec<String> {
    let parser = ParseYaml::new();
    let contents = match parser.read_file(Path::new(&yaml_path).to_path_buf()) {
        Ok(yaml) => Some(yaml),
        Err(e) => {
            AlertMessage::alert(&e).ok();
            None
        }
    };
    if contents.is_none() {
        // 対象のファイルが存在しなかった場合は空配列を返す(検知しているルールに対して行うため、ここは通る想定はないが、ファイルが検知途中で削除された場合などを考慮して追加)
        return vec![];
    }
    for yaml in YamlLoader::load_from_str(&contents.unwrap())
        .unwrap_or_default()
        .into_iter()
    {
        if let Some(author) = yaml["author"].as_str() {
            let authors_vec: Vec<String> = author
                .to_string()
                .split(',')
                .into_iter()
                .map(|s| {
                    // 各要素の括弧以降の記載は名前としないためtmpの一番最初の要素のみを参照する
                    let tmp: Vec<&str> = s.split('(').collect();
                    // データの中にdouble quote と single quoteが入っているためここで除外する
                    tmp[0].to_string()
                })
                .collect();
            let mut ret: Vec<&str> = Vec::new();
            for author in &authors_vec {
                ret.extend(author.split(';'));
            }

            return ret
                .iter()
                .map(|r| {
                    r.split('/')
                        .map(|p| {
                            p.to_string()
                                .replace('"', "")
                                .replace('\'', "")
                                .trim()
                                .to_owned()
                        })
                        .collect()
                })
                .collect();
        };
    }
    // ここまで来た場合は要素がない場合なので空配列を返す
    vec![]
}

#[cfg(test)]
mod tests {
    use crate::afterfact::_get_serialized_disp_output;
    use crate::afterfact::emit_csv;
    use crate::afterfact::format_time;
    use crate::detections::message;
    use crate::detections::message::DetectInfo;
    use crate::options::profile::load_profile;
    use chrono::{Local, TimeZone, Utc};
    use hashbrown::HashMap;
    use linked_hash_map::LinkedHashMap;
    use serde_json::Value;
    use std::fs::File;
    use std::fs::{read_to_string, remove_file};
    use std::io;

    #[test]
    fn test_emit_csv_output() {
        let mock_ch_filter =
            message::create_output_filter_config("test_files/config/channel_abbreviations.txt");
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let test_title = "test_title";
        let test_level = "high";
        let test_computername = "testcomputer";
        let test_eventid = "1111";
        let test_channel = "Sec";
        let output = "pokepoke";
        let test_attack = "execution/txxxx.yyy";
        let test_recinfo = "record_infoinfo11";
        let test_record_id = "11111";
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let output_profile: LinkedHashMap<String, String> = load_profile(
            "test_files/config/default_profile.yaml",
            "test_files/config/profiles.yaml",
        )
        .unwrap();
        {
            let messages = &message::MESSAGES;
            messages.clear();
            let val = r##"
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
            "##;
            let event: Value = serde_json::from_str(val).unwrap();
            let mut profile_converter: HashMap<String, String> = HashMap::from([
                ("%Timestamp%".to_owned(), format_time(&expect_time, false)),
                ("%Computer%".to_owned(), test_computername.to_string()),
                (
                    "%Channel%".to_owned(),
                    mock_ch_filter
                        .get(&"Security".to_ascii_lowercase())
                        .unwrap_or(&String::default())
                        .to_string(),
                ),
                ("%Level%".to_owned(), test_level.to_string()),
                ("%EventID%".to_owned(), test_eventid.to_string()),
                ("%MitreAttack%".to_owned(), test_attack.to_string()),
                ("%RecordID%".to_owned(), test_record_id.to_string()),
                ("%RuleTitle%".to_owned(), test_title.to_owned()),
                ("%AllFieldInfo%".to_owned(), test_recinfo.to_owned()),
                ("%RuleFile%".to_owned(), test_rulepath.to_string()),
                ("%EvtxFile%".to_owned(), test_filepath.to_string()),
                ("%Tags%".to_owned(), test_attack.to_string()),
            ]);
            message::insert(
                &event,
                output.to_string(),
                DetectInfo {
                    rulepath: test_rulepath.to_string(),
                    ruletitle: test_title.to_string(),
                    level: test_level.to_string(),
                    computername: test_computername.to_string(),
                    eventid: test_eventid.to_string(),
                    detail: String::default(),
                    record_information: Option::Some(test_recinfo.to_string()),
                    ext_field: output_profile.clone(),
                },
                expect_time,
                &mut profile_converter,
                false,
            );
        }
        let expect =
            "Timestamp,Computer,Channel,Level,EventID,MitreAttack,RecordID,RuleTitle,Details,RecordInformation,RuleFile,EvtxFile,Tags\n"
                .to_string()
                + &expect_tz
                    .clone()
                    .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                    .to_string()
                + ","
                + test_computername
                + ","
                + test_channel
                + ","
                + test_level
                + ","
                + test_eventid
                + ","
                + test_attack
                + ","
                + test_record_id
                + ","
                + test_title
                + ","
                + output
                + ","
                + test_recinfo
                + ","
                + test_rulepath
                + ","
                + test_filepath
                + ","
                + test_attack
                + "\n";
        let mut file: Box<dyn io::Write> = Box::new(File::create("./test_emit_csv.csv").unwrap());
        assert!(emit_csv(&mut file, false, HashMap::new(), 1, output_profile).is_ok());
        match read_to_string("./test_emit_csv.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv.csv").is_ok());
    }

    #[test]
    fn test_emit_csv_display() {
        let test_title = "test_title2";
        let test_level = "medium";
        let test_computername = "testcomputer2";
        let test_eventid = "2222";
        let test_channel = "Sysmon";
        let output = "displaytest";
        let test_recinfo = "testinfo";
        let test_recid = "22222";

        let test_timestamp = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_header = "Timestamp ‖ Computer ‖ Channel ‖ EventID ‖ Level ‖ RecordID ‖ RuleTitle ‖ Details ‖ RecordInformation\n";
        let expect_tz = test_timestamp.with_timezone(&Local);

        let expect_no_header = expect_tz
            .clone()
            .format("%Y-%m-%d %H:%M:%S%.3f %:z")
            .to_string()
            + " ‖ "
            + test_computername
            + " ‖ "
            + test_channel
            + " ‖ "
            + test_eventid
            + " ‖ "
            + test_level
            + " ‖ "
            + test_recid
            + " ‖ "
            + test_title
            + " ‖ "
            + output
            + " ‖ "
            + test_recinfo
            + "\n";
        let mut data: LinkedHashMap<String, String> = LinkedHashMap::new();
        data.insert("Timestamp".to_owned(), format_time(&test_timestamp, false));
        data.insert("Computer".to_owned(), test_computername.to_owned());
        data.insert("Channel".to_owned(), test_channel.to_owned());
        data.insert("EventID".to_owned(), test_eventid.to_owned());
        data.insert("Level".to_owned(), test_level.to_owned());
        data.insert("RecordID".to_owned(), test_recid.to_owned());
        data.insert("RuleTitle".to_owned(), test_title.to_owned());
        data.insert("Details".to_owned(), output.to_owned());
        data.insert("RecordInformation".to_owned(), test_recinfo.to_owned());

        assert_eq!(_get_serialized_disp_output(&data, true), expect_header);
        assert_eq!(_get_serialized_disp_output(&data, false), expect_no_header);
    }
}

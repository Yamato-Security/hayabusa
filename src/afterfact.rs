use crate::detections::configs;
use crate::detections::configs::{CURRENT_EXE_PATH, TERM_SIZE};
use crate::detections::message::{self, LEVEL_ABBR};
use crate::detections::message::{AlertMessage, LEVEL_FULL};
use crate::detections::utils::{self, format_time};
use crate::detections::utils::{get_writable_color, write_color_buffer};
use crate::options::profile::PROFILES;
use bytesize::ByteSize;
use chrono::{DateTime, Local, TimeZone, Utc};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use csv::QuoteStyle;
use itertools::Itertools;
use krapslog::{build_sparkline, build_time_markers};
use lazy_static::lazy_static;
use linked_hash_map::LinkedHashMap;

use comfy_table::*;
use hashbrown::{HashMap, HashSet};
use num_format::{Locale, ToFormattedString};
use std::cmp::min;
use std::error::Error;

use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;

use std::fs;
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
    if let Err(err) = emit_csv(&mut target, displayflag, color_map, all_record_cnt as u128) {
        fn_emit_csv_err(Box::new(err));
    }
}

fn emit_csv<W: std::io::Write>(
    writer: &mut W,
    displayflag: bool,
    color_map: HashMap<String, Colors>,
    all_record_cnt: u128,
) -> io::Result<()> {
    let disp_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut disp_wtr_buf = disp_wtr.buffer();
    let mut wtr = csv::WriterBuilder::new().from_writer(writer);

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
    for time in message::MESSAGES.clone().into_read_only().keys().sorted() {
        let multi = message::MESSAGES.get(time).unwrap();
        let (_, detect_infos) = multi.pair();
        timestamps.push(_get_timestamp(time));
        for detect_info in detect_infos {
            if !detect_info.detail.starts_with("[condition]") {
                detected_record_idset.insert(format!("{}_{}", time, detect_info.eventid));
            }
            if displayflag {
                //ヘッダーのみを出力
                if plus_header {
                    write_color_buffer(
                        &disp_wtr,
                        get_writable_color(None),
                        &_get_serialized_disp_output(PROFILES.as_ref().unwrap(), true),
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

    let output_path = &configs::CONFIG.read().unwrap().args.output;
    if let Some(path) = output_path {
        if let Ok(metadata) = fs::metadata(path) {
            println!(
                "Saved file: {} ({})",
                configs::CONFIG
                    .read()
                    .unwrap()
                    .args
                    .output
                    .as_ref()
                    .unwrap()
                    .display(),
                ByteSize::b(metadata.len()).to_string_as(false)
            );
            println!();
        }
    };

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
            get_writable_color(None),
            &format!(
                "Saved alerts and events / Total events analyzed: {} / {} (Data reduction: {} events ({:.2}%))",
                (all_record_cnt - reducted_record_cnt).to_formatted_string(&Locale::en),
                all_record_cnt.to_formatted_string(&Locale::en),
                reducted_record_cnt.to_formatted_string(&Locale::en),
                reducted_percent
            ),
            true,
        )
        .ok();
        println!();

        _print_unique_results(
            total_detect_counts_by_level,
            unique_detect_counts_by_level,
            "Total | Unique".to_string(),
            "detections".to_string(),
            &color_map,
        );
        println!();

        _print_detection_summary_by_date(detect_counts_by_date_and_level, &color_map);
        println!();
        println!();

        _print_detection_summary_by_computer(detect_counts_by_computer_and_level, &color_map);
        println!();

        _print_detection_summary_tables(detect_counts_by_rule_and_level, &color_map);
        println!();
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
        for k in data.keys() {
            ret.push(k.to_owned());
        }
    } else {
        for (i, (_, v)) in data.iter().enumerate() {
            if i == 0 {
                ret.push(_format_cellpos(v, ColPos::First))
            } else if i == data_length - 1 {
                ret.push(_format_cellpos(v, ColPos::Last))
            } else {
                ret.push(_format_cellpos(v, ColPos::Other))
            }
        }
    }
    let mut disp_serializer = csv::WriterBuilder::new()
        .double_quote(false)
        .quote_style(QuoteStyle::Never)
        .delimiter(b'|')
        .has_headers(false)
        .from_writer(vec![]);

    disp_serializer.write_record(ret).ok();
    String::from_utf8(disp_serializer.into_inner().unwrap_or_default()).unwrap_or_default()
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
}

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_date(
    detect_counts_by_date: HashMap<String, HashMap<String, u128>>,
    color_map: &HashMap<String, Colors>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    writeln!(wtr, "Dates with most total detections:").ok();

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
        write!(
            wtr,
            "{}: {}",
            LEVEL_FULL.get(level.as_str()).unwrap(),
            &max_detect_str
        )
        .ok();
        if idx != LEVEL_ABBR.len() - 1 {
            wtr.set_color(ColorSpec::new().set_fg(None)).ok();

            write!(wtr, ", ").ok();
        }
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: HashMap<String, HashMap<String, i128>>,
    color_map: &HashMap<String, Colors>,
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
                ("%RecordInformation%".to_owned(), test_recinfo.to_owned()),
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
                    ext_field: output_profile,
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
        assert!(emit_csv(&mut file, false, HashMap::new(), 1).is_ok());
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
        let expect_header = "Timestamp|Computer|Channel|EventID|Level|RecordID|RuleTitle|Details|RecordInformation\n";
        let expect_tz = test_timestamp.with_timezone(&Local);

        let expect_no_header = expect_tz
            .clone()
            .format("%Y-%m-%d %H:%M:%S%.3f %:z")
            .to_string()
            + " | "
            + test_computername
            + " | "
            + test_channel
            + " | "
            + test_eventid
            + " | "
            + test_level
            + " | "
            + test_recid
            + " | "
            + test_title
            + " | "
            + output
            + " | "
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

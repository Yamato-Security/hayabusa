use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use crate::detections::utils::write_color_buffer;
use chrono::{DateTime, Local, TimeZone, Utc};
use csv::QuoteStyle;
use hashbrown::HashMap;
use hashbrown::HashSet;
use krapslog::{build_sparkline, build_time_markers};
use lazy_static::lazy_static;
use serde::Serialize;
use std::cmp::min;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::process;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use terminal_size::{terminal_size, Width};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    timestamp: &'a str,
    computer: &'a str,
    channel: &'a str,
    event_i_d: &'a str,
    level: &'a str,
    mitre_attack: &'a str,
    rule_title: &'a str,
    details: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_i_d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_information: Option<&'a str>,
    rule_path: &'a str,
    file_path: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisplayFormat<'a> {
    timestamp: &'a str,
    pub computer: &'a str,
    pub channel: &'a str,
    pub event_i_d: &'a str,
    pub level: &'a str,
    pub rule_title: &'a str,
    pub details: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_i_d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_information: Option<&'a str>,
}

lazy_static! {
    pub static ref OUTPUT_COLOR: HashMap<String, Color> = set_output_color();
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn set_output_color() -> HashMap<String, Color> {
    let read_result = utils::read_csv("config/level_color.txt");
    let mut color_map: HashMap<String, Color> = HashMap::new();
    if configs::CONFIG.read().unwrap().args.is_present("no-color") {
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
            Color::Rgb(color_code[0], color_code[1], color_code[2]),
        );
    });
    color_map
}

fn _get_output_color(color_map: &HashMap<String, Color>, level: &str) -> Option<Color> {
    let mut color = None;
    if let Some(c) = color_map.get(&level.to_lowercase()) {
        color = Some(c.to_owned());
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
    println!();
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
        if let Some(csv_path) = configs::CONFIG.read().unwrap().args.value_of("output") {
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
    color_map: HashMap<String, Color>,
    all_record_cnt: u128,
) -> io::Result<()> {
    let disp_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut disp_wtr_buf = disp_wtr.buffer();

    let mut wtr = csv::WriterBuilder::new().from_writer(writer);

    let messages = print::MESSAGES.lock().unwrap();
    // level is devided by "Critical","High","Medium","Low","Informational","Undefined".
    let mut total_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut unique_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut detected_rule_files: HashSet<String> = HashSet::new();
    let mut detected_computer_and_rule_names: HashSet<String> = HashSet::new();
    let mut detect_counts_by_date_and_level: HashMap<String, HashMap<String, u128>> =
        HashMap::new();
    let mut detect_counts_by_computer_and_level: HashMap<String, HashMap<String, i128>> =
        HashMap::new();

    let levels = Vec::from([
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "undefined",
    ]);
    // レベル別、日ごとの集計用変数の初期化
    for level_init in levels {
        detect_counts_by_date_and_level.insert(level_init.to_string(), HashMap::new());
        detect_counts_by_computer_and_level.insert(level_init.to_string(), HashMap::new());
    }

    println!();
    let mut timestamps: Vec<i64> = Vec::new();
    let mut plus_header = true;
    let mut detected_record_idset: HashSet<String> = HashSet::new();
    for (time, detect_infos) in messages.iter() {
        timestamps.push(_get_timestamp(time));
        for detect_info in detect_infos {
            detected_record_idset.insert(format!("{}_{}", time, detect_info.eventid));
            let mut level = detect_info.level.to_string();
            if level == "informational" {
                level = "info".to_string();
            }
            let time_str = format_time(time);
            if displayflag {
                let record_id = detect_info
                    .record_id
                    .as_ref()
                    .map(|recinfo| _format_cellpos(recinfo, ColPos::Other));
                let recinfo = detect_info
                    .record_information
                    .as_ref()
                    .map(|recinfo| _format_cellpos(recinfo, ColPos::Last));
                let details = detect_info
                    .detail
                    .chars()
                    .filter(|&c| !c.is_control())
                    .collect::<String>();

                let dispformat = DisplayFormat {
                    timestamp: &_format_cellpos(&time_str, ColPos::First),
                    level: &_format_cellpos(&level, ColPos::Other),
                    computer: &_format_cellpos(&detect_info.computername, ColPos::Other),
                    event_i_d: &_format_cellpos(&detect_info.eventid, ColPos::Other),
                    channel: &_format_cellpos(&detect_info.channel, ColPos::Other),
                    rule_title: &_format_cellpos(&detect_info.alert, ColPos::Other),
                    details: &_format_cellpos(&details, ColPos::Other),
                    record_information: recinfo.as_deref(),
                    record_i_d: record_id.as_deref(),
                };

                disp_wtr_buf
                    .set_color(
                        ColorSpec::new().set_fg(_get_output_color(&color_map, &detect_info.level)),
                    )
                    .ok();
                write!(
                    disp_wtr_buf,
                    "{}",
                    _get_serialized_disp_output(dispformat, plus_header)
                )
                .ok();
                plus_header = false;
            } else {
                // csv output format
                wtr.serialize(CsvFormat {
                    timestamp: &time_str,
                    level: &level,
                    computer: &detect_info.computername,
                    event_i_d: &detect_info.eventid,
                    channel: &detect_info.channel,
                    mitre_attack: &detect_info.tag_info,
                    rule_title: &detect_info.alert,
                    details: &detect_info.detail,
                    record_information: detect_info.record_information.as_deref(),
                    file_path: &detect_info.filepath,
                    rule_path: &detect_info.rulepath,
                    record_i_d: detect_info.record_id.as_deref(),
                })?;
            }
            let level_suffix = *configs::LEVELMAP
                .get(&detect_info.level.to_uppercase())
                .unwrap_or(&0) as usize;
            let time_str_date = &time_str[0..10];
            let mut detect_counts_by_date = detect_counts_by_date_and_level
                .get(&detect_info.level.to_lowercase())
                .unwrap()
                .clone();
            *detect_counts_by_date
                .entry(time_str_date.to_string())
                .or_insert(0) += 1;
            if !detected_rule_files.contains(&detect_info.rulepath) {
                detected_rule_files.insert(detect_info.rulepath.clone());
                unique_detect_counts_by_level[level_suffix] += 1;
            }
            let computer_rule_check_key =  format!("{}|{}", &detect_info.computername ,&detect_info.rulepath);
            if !detected_computer_and_rule_names.contains(&computer_rule_check_key) {
                detected_computer_and_rule_names.insert(computer_rule_check_key);
                let mut detect_counts_by_computer = detect_counts_by_computer_and_level
                    .get(&detect_info.level.to_lowercase())
                    .unwrap()
                    .clone();
                *detect_counts_by_computer
                    .entry(Clone::clone(&detect_info.computername))
                    .or_insert(0) += 1;
                    detect_counts_by_computer_and_level
                        .insert(detect_info.level.to_lowercase(), detect_counts_by_computer);
            }

            total_detect_counts_by_level[level_suffix] += 1;
            detect_counts_by_date_and_level
                .insert(detect_info.level.to_lowercase(), detect_counts_by_date);

        }
    }
    if displayflag {
        disp_wtr.print(&disp_wtr_buf)?;
    } else {
        wtr.flush()?;
    }
    println!();

    let size = terminal_size();
    let terminal_width = match size {
        Some((Width(w), _)) => w as usize,
        None => 100,
    };

    _print_timeline_hist(timestamps, terminal_width, 3);
    println!();
    let reducted_record_cnt: u128 = all_record_cnt - detected_record_idset.len() as u128;
    let reducted_percent = if all_record_cnt == 0 {
        0 as f64
    } else {
        (reducted_record_cnt as f64) / (all_record_cnt as f64) * 100.0
    };
    println!("Total events: {}", all_record_cnt);
    println!(
        "Data reduction: {} events ({:.2}%)",
        reducted_record_cnt, reducted_percent
    );
    println!();

    _print_detection_summary_by_date(detect_counts_by_date_and_level, &color_map);
    println!();

    _print_detection_summary_by_computer(detect_counts_by_computer_and_level, &color_map);
    println!();

    _print_unique_results(
        total_detect_counts_by_level,
        "Total".to_string(),
        "detections".to_string(),
        &color_map,
    );
    println!();

    _print_unique_results(
        unique_detect_counts_by_level,
        "Unique".to_string(),
        "detections".to_string(),
        &color_map,
    );
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

fn _get_serialized_disp_output(dispformat: DisplayFormat, plus_header: bool) -> String {
    let mut disp_serializer = csv::WriterBuilder::new()
        .double_quote(false)
        .quote_style(QuoteStyle::Never)
        .delimiter(b'|')
        .has_headers(plus_header)
        .from_writer(vec![]);

    disp_serializer.serialize(dispformat).ok();

    String::from_utf8(disp_serializer.into_inner().unwrap_or_default()).unwrap_or_default()
}

/// return str position in output file
fn _format_cellpos(colval: &str, column: ColPos) -> String {
    return match column {
        ColPos::First => format!("{} ", colval),
        ColPos::Last => format!(" {}", colval),
        ColPos::Other => format!(" {} ", colval),
    };
}

/// output info which unique detection count and all detection count information(devided by level and total) to stdout.
fn _print_unique_results(
    mut counts_by_level: Vec<u128>,
    head_word: String,
    tail_word: String,
    color_map: &HashMap<String, Color>,
) {
    let levels = Vec::from([
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "undefined",
    ]);

    // the order in which are registered and the order of levels to be displayed are reversed
    counts_by_level.reverse();

    // output total results
    write_color_buffer(
        BufferWriter::stdout(ColorChoice::Always),
        None,
        &format!(
            "{} {}: {}",
            head_word,
            tail_word,
            counts_by_level.iter().sum::<u128>()
        ),
    )
    .ok();

    for (i, level_name) in levels.iter().enumerate() {
        if "undefined" == *level_name {
            continue;
        }
        let output_raw_str = format!(
            "{} {} {}: {}",
            head_word, level_name, tail_word, counts_by_level[i]
        );
        write_color_buffer(
            BufferWriter::stdout(ColorChoice::Always),
            _get_output_color(color_map, level_name),
            &output_raw_str,
        )
        .ok();
    }
}

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_date(
    detect_counts_by_date: HashMap<String, HashMap<String, u128>>,
    color_map: &HashMap<String, Color>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    let output_levels = Vec::from(["critical", "high", "medium", "low", "informational"]);

    for level in output_levels {
        // output_levelsはlevelsからundefinedを除外した配列であり、各要素は必ず初期化されているのでSomeであることが保証されているのでunwrapをそのまま実施
        let detections_by_day = detect_counts_by_date.get(level).unwrap();
        let mut max_detect_str = String::default();
        let mut tmp_cnt: u128 = 0;
        let mut date_str = String::default();
        for (date, cnt) in detections_by_day {
            if cnt > &tmp_cnt {
                date_str = date.clone();
                max_detect_str = format!("{} (Count: {})", date, cnt);
                tmp_cnt = *cnt;
            }
        }
        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, level)))
            .ok();
        if date_str == String::default() {
            max_detect_str = "-".to_string();
        }
        writeln!(
            wtr,
            "Date with most {} detections: {}",
            level, &max_detect_str
        )
        .ok();
    }
    buf_wtr.print(&wtr).ok();
}

/// 各レベル毎で最も高い検知数を出した日付を出力する
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: HashMap<String, HashMap<String, i128>>,
    color_map: &HashMap<String, Color>,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    let output_levels = Vec::from(["critical", "high", "medium", "low", "informational"]);

    for level in output_levels {
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
            result_vec.push(format!("{} ({})", x.0, x.1));
        }
        let result_str = if result_vec.is_empty() {
            "n/a".to_string()
        } else {
            result_vec.join(", ")
        };

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, level)))
            .ok();
        writeln!(
            wtr,
            "Top 5 computers with most {} detections: {}",
            level, &result_str
        )
        .ok();
    }
    buf_wtr.print(&wtr).ok();
}

fn format_time(time: &DateTime<Utc>) -> String {
    if configs::CONFIG.read().unwrap().args.is_present("utc") {
        format_rfc(time)
    } else {
        format_rfc(&time.with_timezone(&Local))
    }
}

/// get timestamp to input datetime.
fn _get_timestamp(time: &DateTime<Utc>) -> i64 {
    if configs::CONFIG.read().unwrap().args.is_present("utc") {
        time.timestamp()
    } else {
        let offset_sec = Local.timestamp(0, 0).offset().local_minus_utc();
        offset_sec as i64 + time.with_timezone(&Local).timestamp()
    }
}

/// return rfc time format string by option
fn format_rfc<Tz: TimeZone>(time: &DateTime<Tz>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    if configs::CONFIG.read().unwrap().args.is_present("rfc-2822") {
        time.to_rfc2822()
    } else if configs::CONFIG.read().unwrap().args.is_present("rfc-3339") {
        time.to_rfc3339()
    } else {
        time.format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::afterfact::DisplayFormat;
    use crate::afterfact::_get_serialized_disp_output;
    use crate::afterfact::emit_csv;
    use crate::afterfact::format_time;
    use crate::detections::print;
    use crate::detections::print::DetectInfo;
    use crate::detections::print::CH_CONFIG;
    use chrono::{Local, TimeZone, Utc};
    use hashbrown::HashMap;
    use serde_json::Value;
    use std::fs::File;
    use std::fs::{read_to_string, remove_file};
    use std::io;

    #[test]
    fn test_emit_csv() {
        //テストの並列処理によって読み込みの順序が担保できずstatic変数の内容が担保が取れない為、このテストはシーケンシャルで行う
        test_emit_csv_output();
        test_emit_csv_output();
    }

    fn test_emit_csv_output() {
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
        {
            let mut messages = print::MESSAGES.lock().unwrap();
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
            messages.insert(
                &event,
                output.to_string(),
                DetectInfo {
                    filepath: test_filepath.to_string(),
                    rulepath: test_rulepath.to_string(),
                    level: test_level.to_string(),
                    computername: test_computername.to_string(),
                    eventid: test_eventid.to_string(),
                    channel: CH_CONFIG
                        .get("Security")
                        .unwrap_or(&String::default())
                        .to_string(),
                    alert: test_title.to_string(),
                    detail: String::default(),
                    tag_info: test_attack.to_string(),
                    record_information: Option::Some(test_recinfo.to_string()),
                    record_id: Option::Some(test_record_id.to_string()),
                },
            );
        }
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let expect =
            "Timestamp,Computer,Channel,EventID,Level,MitreAttack,RuleTitle,Details,RecordID,RecordInformation,RulePath,FilePath\n"
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
                + test_eventid
                + ","
                + test_level
                + ","
                + test_attack
                + ","
                + test_title
                + ","
                + output
                + ","
                + test_record_id
                + ","
                + test_recinfo
                + ","
                + test_rulepath
                + ","
                + test_filepath
                + "\n";
        let mut file: Box<dyn io::Write> = Box::new(File::create("./test_emit_csv.csv").unwrap());
        assert!(emit_csv(&mut file, false, HashMap::default(), 1).is_ok());
        match read_to_string("./test_emit_csv.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv.csv").is_ok());
        check_emit_csv_display();
    }

    fn check_emit_csv_display() {
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
        let expect_header =
            "Timestamp|Computer|Channel|EventID|Level|RuleTitle|Details|RecordID|RecordInformation\n";
        let expect_tz = test_timestamp.with_timezone(&Local);

        let expect_no_header = expect_tz
            .clone()
            .format("%Y-%m-%d %H:%M:%S%.3f %:z")
            .to_string()
            + "|"
            + test_computername
            + "|"
            + test_channel
            + "|"
            + test_eventid
            + "|"
            + test_level
            + "|"
            + test_title
            + "|"
            + output
            + "|"
            + test_recid
            + "|"
            + test_recinfo
            + "\n";
        let expect_with_header = expect_header.to_string() + &expect_no_header;
        assert_eq!(
            _get_serialized_disp_output(
                DisplayFormat {
                    timestamp: &format_time(&test_timestamp),
                    level: test_level,
                    computer: test_computername,
                    event_i_d: test_eventid,
                    channel: test_channel,
                    rule_title: test_title,
                    details: output,
                    record_information: Some(test_recinfo),
                    record_i_d: Some(test_recid),
                },
                true
            ),
            expect_with_header
        );
        assert_eq!(
            _get_serialized_disp_output(
                DisplayFormat {
                    timestamp: &format_time(&test_timestamp),
                    level: test_level,
                    computer: test_computername,
                    event_i_d: test_eventid,
                    channel: test_channel,
                    rule_title: test_title,
                    details: output,
                    record_information: Some(test_recinfo),
                    record_i_d: Some(test_recid),
                },
                false
            ),
            expect_no_header
        );
    }
}

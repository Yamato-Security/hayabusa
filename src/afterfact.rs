use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, Local, TimeZone, Utc};
use csv::QuoteStyle;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::process;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

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
        AlertMessage::warn(
            &mut BufWriter::new(std::io::stderr().lock()),
            read_result.as_ref().unwrap_err(),
        )
        .ok();
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
            AlertMessage::warn(
                &mut BufWriter::new(std::io::stderr().lock()),
                &format!("Failed hex convert in level_color.txt. Color output is disabled. Input Line: {}",line.join(","))
            )
            .ok();
            return;
        }
        let color_code = convert_color_result.unwrap();
        if level.is_empty() || color_code.len() < 3 {
            return;
        }
        color_map.insert(level.to_lowercase(), Color::Rgb(color_code[0], color_code[1], color_code[2]));
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

pub fn after_fact(all_record_cnt: usize) {
    let fn_emit_csv_err = |err: Box<dyn Error>| {
        AlertMessage::alert(
            &mut BufWriter::new(std::io::stderr().lock()),
            &format!("Failed to write CSV. {}", err),
        )
        .ok();
        process::exit(1);
    };

    let mut displayflag = false;
    let mut target: Box<dyn io::Write> =
        if let Some(csv_path) = configs::CONFIG.read().unwrap().args.value_of("output") {
            // output to file
            match File::create(csv_path) {
                Ok(file) => Box::new(BufWriter::new(file)),
                Err(err) => {
                    AlertMessage::alert(
                        &mut BufWriter::new(std::io::stderr().lock()),
                        &format!("Failed to open file. {}", err),
                    )
                    .ok();
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
    let mut detected_rule_files: Vec<String> = Vec::new();

    println!();
    let mut plus_header = true;
    for (time, detect_infos) in messages.iter() {
        for detect_info in detect_infos {
            let mut level = detect_info.level.to_string();
            if level == "informational" {
                level = "info".to_string();
            }
            if displayflag {
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
                    timestamp: &_format_cellpos(&format_time(time), ColPos::First),
                    level: &_format_cellpos(&level, ColPos::Other),
                    computer: &_format_cellpos(&detect_info.computername, ColPos::Other),
                    event_i_d: &_format_cellpos(&detect_info.eventid, ColPos::Other),
                    channel: &_format_cellpos(&detect_info.channel, ColPos::Other),
                    rule_title: &_format_cellpos(&detect_info.alert, ColPos::Other),
                    details: &_format_cellpos(&details, ColPos::Other),
                    record_information: recinfo.as_deref(),
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
                    timestamp: &format_time(time),
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
                })?;
            }
            let level_suffix = *configs::LEVELMAP
                .get(&detect_info.level.to_uppercase())
                .unwrap_or(&0) as usize;
            if !detected_rule_files.contains(&detect_info.rulepath) {
                detected_rule_files.push(detect_info.rulepath.clone());
                unique_detect_counts_by_level[level_suffix] += 1;
            }
            total_detect_counts_by_level[level_suffix] += 1;
        }
    }
    if displayflag {
        disp_wtr.print(&disp_wtr_buf)?;
    } else {
        wtr.flush()?;
    }
    println!();

    let reducted_record_cnt: u128 =
        all_record_cnt - total_detect_counts_by_level.iter().sum::<u128>();
    let reducted_percent = if all_record_cnt == 0 {
        0 as f64
    } else {
        (reducted_record_cnt as f64) / (all_record_cnt as f64) * 100.0
    };
    println!("Total events: {}", all_record_cnt);
    println!(
        "Data reduction: {}({:.2}%)",
        reducted_record_cnt, reducted_percent
    );
    println!();

    _print_unique_results(
        total_detect_counts_by_level,
        "Total".to_string(),
        "detections".to_string(),
        &color_map,
    );
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
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

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
    writeln!(
        wtr,
        "{} {}: {}",
        head_word,
        tail_word,
        counts_by_level.iter().sum::<u128>()
    )
    .ok();

    for (i, level_name) in levels.iter().enumerate() {
        let output_raw_str = format!(
            "{} {} {}: {}",
            head_word, level_name, tail_word, counts_by_level[i]
        );

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, level_name)))
            .ok();
        writeln!(wtr, "{}", output_raw_str).ok();
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
                },
            );
        }
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let expect =
            "Timestamp,Computer,Channel,EventID,Level,MitreAttack,RuleTitle,Details,RecordInformation,RulePath,FilePath\n"
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

        let test_timestamp = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_header =
            "Timestamp|Computer|Channel|EventID|Level|RuleTitle|Details|RecordInformation\n";
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
                },
                false
            ),
            expect_no_header
        );
    }
}

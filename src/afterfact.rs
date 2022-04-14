use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, Local, TimeZone, Utc};
use colored::*;
use csv::QuoteStyle;
use hashbrown::HashMap;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::process;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    timestamp: &'a str,
    computer: &'a str,
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
    pub event_i_d: &'a str,
    pub level: &'a str,
    pub rule_title: &'a str,
    pub details: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_information: Option<&'a str>,
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn set_output_color() -> Option<HashMap<String, Vec<u8>>> {
    if !configs::CONFIG.read().unwrap().args.is_present("color") {
        return None;
    }
    let read_result = utils::read_csv("config/level_color.txt");
    if read_result.is_err() {
        // color情報がない場合は通常の白色の出力が出てくるのみで動作への影響を与えない為warnとして処理する
        AlertMessage::warn(
            &mut BufWriter::new(std::io::stderr().lock()),
            read_result.as_ref().unwrap_err(),
        )
        .ok();
        return None;
    }
    let mut color_map: HashMap<String, Vec<u8>> = HashMap::new();
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
        color_map.insert(level.to_string(), color_code);
    });
    Some(color_map)
}

pub fn after_fact() {
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
            // ファイル出力する場合
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
            // 標準出力に出力する場合
            Box::new(BufWriter::new(io::stdout()))
        };
    let color_map = set_output_color();
    if let Err(err) = emit_csv(&mut target, displayflag, color_map) {
        fn_emit_csv_err(Box::new(err));
    }
}

fn emit_csv<W: std::io::Write>(
    writer: &mut W,
    displayflag: bool,
    color_map: Option<HashMap<String, Vec<u8>>>,
) -> io::Result<()> {
    let mut wtr = if displayflag {
        csv::WriterBuilder::new()
            .double_quote(false)
            .quote_style(QuoteStyle::Never)
            .delimiter(b'|')
            .from_writer(writer)
    } else {
        csv::WriterBuilder::new().from_writer(writer)
    };

    let messages = print::MESSAGES.lock().unwrap();
    // levelの区分が"Critical","High","Medium","Low","Informational","Undefined"の6つであるため
    let mut total_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut unique_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut detected_rule_files: Vec<String> = Vec::new();

    for (time, detect_infos) in messages.iter() {
        for detect_info in detect_infos {
            let mut level = detect_info.level.to_string();
            if level == "informational" {
                level = "info".to_string();
            }
            if displayflag {
                let colors = color_map
                    .as_ref()
                    .map(|cl_mp| _get_output_color(cl_mp, &detect_info.level));
                let colors = colors.as_ref();

                let recinfo = detect_info
                    .record_information
                    .as_ref()
                    .map(|recinfo| _format_cell(recinfo, ColPos::Last, colors));
                let details = detect_info
                    .detail
                    .chars()
                    .filter(|&c| !c.is_control())
                    .collect::<String>();

                let dispformat = DisplayFormat {
                    timestamp: &_format_cell(&format_time(time), ColPos::First, colors),
                    level: &_format_cell(&level, ColPos::Other, colors),
                    computer: &_format_cell(&detect_info.computername, ColPos::Other, colors),
                    event_i_d: &_format_cell(&detect_info.eventid, ColPos::Other, colors),
                    rule_title: &_format_cell(&detect_info.alert, ColPos::Other, colors),
                    details: &_format_cell(&details, ColPos::Other, colors),
                    record_information: recinfo.as_deref(),
                };
                wtr.serialize(dispformat)?;
            } else {
                // csv出力時フォーマット
                wtr.serialize(CsvFormat {
                    timestamp: &format_time(time),
                    level: &level,
                    computer: &detect_info.computername,
                    event_i_d: &detect_info.eventid,
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
    println!();

    wtr.flush()?;
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

enum ColPos {
    First, // 先頭
    Last,  // 最後
    Other, // それ以外
}

fn _format_cellpos(column: ColPos, colval: &str) -> String {
    return match column {
        ColPos::First => format!("{} ", colval),
        ColPos::Last => format!(" {}", colval),
        ColPos::Other => format!(" {} ", colval),
    };
}

fn _format_cell(word: &str, column: ColPos, output_color: Option<&Vec<u8>>) -> String {
    if let Some(color) = output_color {
        let colval = format!("{}", word.truecolor(color[0], color[1], color[2]));
        _format_cellpos(column, &colval)
    } else {
        _format_cellpos(column, word)
    }
}

/// 与えられたユニークな検知数と全体の検知数の情報(レベル別と総計)を元に結果文を標準出力に表示する関数
fn _print_unique_results(
    mut counts_by_level: Vec<u128>,
    head_word: String,
    tail_word: String,
    color_map: &Option<HashMap<String, Vec<u8>>>,
) {
    let mut wtr = BufWriter::new(io::stdout());
    let levels = Vec::from([
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "undefined",
    ]);

    // configsの登録順番と表示をさせたいlevelの順番が逆であるため
    counts_by_level.reverse();

    // 全体の集計(levelの記載がないためformatの第二引数は空の文字列)
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
        let output_str = if color_map.is_none() {
            output_raw_str
        } else {
            let output_color = _get_output_color(color_map.as_ref().unwrap(), level_name);
            output_raw_str
                .truecolor(output_color[0], output_color[1], output_color[2])
                .to_string()
        };
        writeln!(wtr, "{}", output_str).ok();
    }
    wtr.flush().ok();
}

/// levelに対応したtruecolorの値の配列を返す関数
fn _get_output_color(color_map: &HashMap<String, Vec<u8>>, level: &str) -> Vec<u8> {
    // カラーをつけない場合は255,255,255で出力する
    let mut output_color: Vec<u8> = vec![255, 255, 255];
    let target_color = color_map.get(level);
    if let Some(color) = target_color {
        output_color = color.to_vec();
    }
    output_color
}

fn format_time(time: &DateTime<Utc>) -> String {
    if configs::CONFIG.read().unwrap().args.is_present("utc") {
        format_rfc(time)
    } else {
        format_rfc(&time.with_timezone(&Local))
    }
}

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
    use crate::afterfact::emit_csv;
    use crate::detections::print;
    use crate::detections::print::DetectInfo;
    use chrono::{Local, TimeZone, Utc};
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
        let testfilepath: &str = "test.evtx";
        let testrulepath: &str = "test-rule.yml";
        let test_title = "test_title";
        let test_level = "high";
        let test_computername = "testcomputer";
        let test_eventid = "1111";
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
                    filepath: testfilepath.to_string(),
                    rulepath: testrulepath.to_string(),
                    level: test_level.to_string(),
                    computername: test_computername.to_string(),
                    eventid: test_eventid.to_string(),
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
            "Timestamp,Computer,EventID,Level,MitreAttack,RuleTitle,Details,RecordInformation,RulePath,FilePath\n"
                .to_string()
                + &expect_tz
                    .clone()
                    .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                    .to_string()
                + ","
                + test_computername
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
                + testrulepath
                + ","
                + testfilepath
                + "\n";
        let mut file: Box<dyn io::Write> = Box::new(File::create("./test_emit_csv.csv").unwrap());
        assert!(emit_csv(&mut file, false, None).is_ok());
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
        let testfilepath: &str = "test2.evtx";
        let testrulepath: &str = "test-rule2.yml";
        let test_title = "test_title2";
        let test_level = "medium";
        let test_computername = "testcomputer2";
        let test_eventid = "2222";
        let output = "displaytest";
        let test_attack = "execution/txxxx.zzz";
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
                    filepath: testfilepath.to_string(),
                    rulepath: testrulepath.to_string(),
                    level: test_level.to_string(),
                    computername: test_computername.to_string(),
                    eventid: test_eventid.to_string(),
                    alert: test_title.to_string(),
                    detail: String::default(),
                    tag_info: test_attack.to_string(),
                    record_information: Option::Some(String::default()),
                },
            );
            messages.debug();
        }
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let expect_header =
            "Timestamp|Computer|EventID|Level|RuleTitle|Details|RecordInformation\n";
        let expect_colored = expect_header.to_string()
            + &get_white_color_string(
                &expect_tz
                    .clone()
                    .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                    .to_string(),
            )
            + " | "
            + &get_white_color_string(test_computername)
            + " | "
            + &get_white_color_string(test_eventid)
            + " | "
            + &get_white_color_string(test_level)
            + " | "
            + &get_white_color_string(test_title)
            + " | "
            + &get_white_color_string(output)
            + " | "
            + &get_white_color_string("")
            + "\n";
        let expect_nocoloed = expect_header.to_string()
            + &expect_tz
                .clone()
                .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                .to_string()
            + " | "
            + test_computername
            + " | "
            + test_eventid
            + " | "
            + test_level
            + " | "
            + test_title
            + " | "
            + output
            + " | "
            + ""
            + "\n";

        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_display.txt").unwrap());
        assert!(emit_csv(&mut file, true, None).is_ok());
        match read_to_string("./test_emit_csv_display.txt") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert!(s == expect_colored || s == expect_nocoloed);
            }
        };
        assert!(remove_file("./test_emit_csv_display.txt").is_ok());
    }

    fn get_white_color_string(target: &str) -> String {
        let white_color_header = "\u{1b}[38;2;255;255;255m";
        let white_color_footer = "\u{1b}[0m";

        white_color_header.to_owned() + target + white_color_footer
    }
}

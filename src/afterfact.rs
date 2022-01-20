use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, Local, TimeZone, Utc};
use colored::*;
use hashbrown::HashMap;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::process;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    timestamp: &'a str,
    computer: &'a str,
    event_i_d: &'a str,
    level: &'a str,
    rule_title: &'a str,
    details: &'a str,
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
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn set_output_color() -> Option<HashMap<String, Vec<u8>>> {
    let read_result = utils::read_csv("config/level_color.txt");
    if read_result.is_err() {
        // color情報がない場合は通常の白色の出力が出てくるのみで動作への影響を与えない為warnとして処理する
        AlertMessage::warn(
            &mut BufWriter::new(std::io::stderr().lock()),
            &read_result.as_ref().unwrap_err(),
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
                &"Failed hex convert in level_color.txt. Color output is disabled.".to_string(),
            )
            .ok();
        }
        let color_code = convert_color_result.unwrap();
        if level.len() == 0 || color_code.len() < 3 {
            return;
        }
        color_map.insert(level.to_string(), color_code);
    });
    return Some(color_map);
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
    let mut wtr;
    if displayflag {
        wtr = csv::WriterBuilder::new()
            .delimiter(b'|')
            .from_writer(writer);
    } else {
        wtr = csv::WriterBuilder::new().from_writer(writer);
    }

    let messages = print::MESSAGES.lock().unwrap();
    // levelの区分が"Critical","High","Medium","Low","Informational","Undefined"の6つであるため
    let mut total_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut unique_detect_counts_by_level: Vec<u128> = vec![0; 6];
    let mut detected_rule_files: Vec<String> = Vec::new();

    for (time, detect_infos) in messages.iter() {
        for detect_info in detect_infos {
            if displayflag {
                // カラーをつけない場合は255,255,255で出力する
                let mut output_color: Vec<u8> = vec![255, 255, 255];
                if color_map.is_some() {
                    let target_color = color_map.as_ref().unwrap().get(&detect_info.level);
                    if target_color.is_some() {
                        output_color = target_color.unwrap().to_vec();
                    }
                }
                wtr.serialize(DisplayFormat {
                    timestamp: &format!(
                        "{} ",
                        &format_time(time).truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                    level: &format!(
                        " {} ",
                        &detect_info.level.truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                    computer: &format!(
                        " {} ",
                        &detect_info.computername.truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                    event_i_d: &format!(
                        " {} ",
                        &detect_info.eventid.truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                    rule_title: &format!(
                        " {} ",
                        &detect_info.alert.truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                    details: &format!(
                        " {}",
                        &detect_info.detail.truecolor(
                            output_color[0],
                            output_color[1],
                            output_color[2]
                        )
                    ),
                })?;
            } else {
                // csv出力時フォーマット
                wtr.serialize(CsvFormat {
                    timestamp: &format_time(time),
                    file_path: &detect_info.filepath,
                    rule_path: &detect_info.rulepath,
                    level: &detect_info.level,
                    computer: &detect_info.computername,
                    event_i_d: &detect_info.eventid,
                    rule_title: &detect_info.alert,
                    details: &detect_info.detail,
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
    println!("");

    wtr.flush()?;
    println!("");
    _print_unique_results(
        total_detect_counts_by_level,
        "Total".to_string(),
        "detections".to_string(),
    );
    _print_unique_results(
        unique_detect_counts_by_level,
        "Unique".to_string(),
        "rules".to_string(),
    );
    Ok(())
}

/// 与えられたユニークな検知数と全体の検知数の情報(レベル別と総計)を元に結果文を標準出力に表示する関数
fn _print_unique_results(mut counts_by_level: Vec<u128>, head_word: String, tail_word: String) {
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
    println!(
        "{} {}: {}",
        head_word,
        tail_word,
        counts_by_level.iter().sum::<u128>()
    );
    for (i, level_name) in levels.iter().enumerate() {
        println!(
            "{} {} {}: {}",
            head_word, level_name, tail_word, counts_by_level[i]
        );
    }
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
        return time.to_rfc2822();
    } else if configs::CONFIG.read().unwrap().args.is_present("rfc-3339") {
        return time.to_rfc3339();
    } else {
        return time.format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string();
    }
}

#[cfg(test)]
mod tests {
    use crate::afterfact::emit_csv;
    use crate::detections::print;
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
                testfilepath.to_string(),
                testrulepath.to_string(),
                &event,
                test_level.to_string(),
                test_computername.to_string(),
                test_eventid.to_string(),
                test_title.to_string(),
                output.to_string(),
            );
        }
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let expect = "Timestamp,Computer,EventID,Level,RuleTitle,Details,RulePath,FilePath\n"
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
            + test_title
            + ","
            + output
            + ","
            + testrulepath
            + ","
            + &testfilepath.to_string()
            + "\n";
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv.csv".to_string()).unwrap());
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
                testfilepath.to_string(),
                testrulepath.to_string(),
                &event,
                test_level.to_string(),
                test_computername.to_string(),
                test_eventid.to_string(),
                test_title.to_string(),
                output.to_string(),
            );
            messages.debug();
        }
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let expect_tz = expect_time.with_timezone(&Local);
        let expect = "Timestamp|Computer|EventID|Level|RuleTitle|Details\n".to_string()
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
            + "\n";
        let mut file: Box<dyn io::Write> =
            Box::new(File::create("./test_emit_csv_display.txt".to_string()).unwrap());
        assert!(emit_csv(&mut file, true, None).is_ok());
        match read_to_string("./test_emit_csv_display.txt") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect);
            }
        };
        assert!(remove_file("./test_emit_csv_display.txt").is_ok());
    }
}

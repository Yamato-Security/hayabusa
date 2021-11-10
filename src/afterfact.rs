use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use crate::notify::slack::SlackNotify;
use chrono::{DateTime, Local, TimeZone, Utc};
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::process;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    time: &'a str,
    filepath: &'a str,
    rulepath: &'a str,
    level: &'a str,
    computername: &'a str,
    eventid: &'a str,
    alert: &'a str,
    details: &'a str,
}

pub fn after_fact() {
    let fn_emit_csv_err = |err: Box<dyn Error>| {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        AlertMessage::alert(&mut stdout, format!("Failed to write CSV. {}", err)).ok();
        process::exit(1);
    };

    // slack通知する場合はemit_csvした後に
    if configs::CONFIG.read().unwrap().args.is_present("slack") {
        let mut buf = vec![];
        let mut writer = BufWriter::new(buf);
        if let Err(err) = emit_csv(&mut writer) {
            fn_emit_csv_err(err);
        } else {
            buf = writer.into_inner().unwrap();
            let s = std::str::from_utf8(&buf).unwrap();
            if SlackNotify::notify(s.to_string()).is_err() {
                eprintln!("slack notification failed!!");
            }
            println!("{}", s.to_string());
        }
    } else {
        let mut target: Box<dyn io::Write> = if let Some(csv_path) = configs::CONFIG
            .read()
            .unwrap()
            .args
            .value_of("csv-timeline")
        {
            // ファイル出力する場合
            match File::create(csv_path) {
                Ok(file) => Box::new(file),
                Err(err) => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    AlertMessage::alert(&mut stdout, format!("Failed to open file. {}", err)).ok();
                    process::exit(1);
                }
            }
        } else {
            // 標準出力に出力する場合
            Box::new(io::stdout())
        };

        if let Err(err) = emit_csv(&mut target) {
            fn_emit_csv_err(err);
        }
    }
}

fn emit_csv<W: std::io::Write>(writer: &mut W) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new().from_writer(writer);
    let messages = print::MESSAGES.lock().unwrap();
    let mut detect_count = 0;
    for (time, detect_infos) in messages.iter() {
        for detect_info in detect_infos {
            wtr.serialize(CsvFormat {
                time: &format_time(time),
                filepath: &detect_info.filepath,
                rulepath: &detect_info.rulepath,
                level: &detect_info.level,
                computername: &detect_info.computername,
                eventid: &detect_info.eventid,
                alert: &detect_info.alert,
                details: &detect_info.detail,
            })?;
        }
        detect_count += detect_infos.len();
    }
    println!("");

    wtr.flush()?;
    println!("");
    println!("Events Detected:{:?}", detect_count);
    Ok(())
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
    } else {
        return time.to_rfc3339();
    }
}

#[test]
fn test_emit_csv() {
    use serde_json::Value;
    use std::fs::{read_to_string, remove_file};
    let testfilepath: &str = "test.evtx";
    let testrulepath: &str = "test-rule.yml";
    let test_title = "test_title";
    let test_level = "high";
    let test_computername = "testcomputer";
    let test_eventid = "1111";
    let output = "pokepoke";
    {
        let mut messages = print::MESSAGES.lock().unwrap();

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
    let expect = "Time,Filepath,Rulepath,Level,Computername,Eventid,Alert,Details\n".to_string()
        + &expect_tz.clone().format("%Y-%m-%dT%H:%M:%S%:z").to_string()
        + ","
        + testfilepath
        + ","
        + testrulepath
        + ","
        + test_level
        + ","
        + test_computername
        + ","
        + test_eventid
        + ","
        + test_title
        + ","
        + output
        + "\n";

    let mut file: Box<dyn io::Write> =
        Box::new(File::create("./test_emit_csv.csv".to_string()).unwrap());
    assert!(emit_csv(&mut file).is_ok());

    match read_to_string("./test_emit_csv.csv") {
        Err(_) => panic!("Failed to open file"),
        Ok(s) => {
            assert_eq!(s, expect);
        }
    };
    assert!(remove_file("./test_emit_csv.csv").is_ok());
}

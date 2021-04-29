use crate::detections::configs;
use crate::detections::print;
use crate::detections::print::AlertMessage;
use chrono::{DateTime, Local, TimeZone, Utc};
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io;
use std::process;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    time: &'a str,
    filepath: &'a str,
    title: &'a str,
    message: &'a str,
}

pub fn after_fact() {
    let mut target: Box<dyn io::Write> = if let Some(csv_path) = configs::CONFIG
        .read()
        .unwrap()
        .args
        .value_of("csv-timeline")
    {
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
        Box::new(io::stdout())
    };

    if let Err(err) = emit_csv(&mut target) {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        AlertMessage::alert(&mut stdout, format!("Failed to write CSV. {}", err)).ok();
        process::exit(1);
    }
}

fn emit_csv(writer: &mut Box<dyn io::Write>) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new().from_writer(writer);
    let messages = print::MESSAGES.lock().unwrap();

    for (time, detect_infos) in messages.iter() {
        for detect_info in detect_infos {
            wtr.serialize(CsvFormat {
                time: &format_time(time),
                filepath: &detect_info.filepath,
                title: &detect_info.title,
                message: &detect_info.detail,
            })?;
        }
    }
    wtr.flush()?;
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
    {
        let mut messages = print::MESSAGES.lock().unwrap();

        let val = r##"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "hoge"
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
            "test.evtx".to_string(),
            &event,
            "test".to_string(),
            "pokepoke".to_string(),
        );
    }

    let expect_time = Utc
        .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
        .unwrap();
    let expect_tz = expect_time.with_timezone(&Local);
    let expect = "Time,Filepath,Title,Message\n".to_string()
        + &expect_tz.clone().format("%Y-%m-%dT%H:%M:%S%:z").to_string()
        + ",test,test,pokepoke";

    let mut file: Box<dyn io::Write> =
        Box::new(File::create("./test_emit_csv.csv".to_string()).unwrap());
    assert!(emit_csv(&mut file).is_ok());

    match read_to_string("./test_emit_csv.csv") {
        Err(_) => panic!("Failed to open file"),
        Ok(s) => {
            assert_eq!(&s[0..72], expect);
        }
    };

    assert!(remove_file("./test_emit_csv.csv").is_ok());
}

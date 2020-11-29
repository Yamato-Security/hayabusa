use crate::detections::configs;
use crate::detections::print;
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use std::error::Error;
use std::process;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    time: DateTime<Utc>,
    message: &'a str,
}

pub fn after_fact() {
    if let Some(csv_path) = configs::singleton().args.value_of("csv-timeline") {
        if let Err(err) = emit_csv(csv_path) {
            println!("{}", err);
            process::exit(1);
        }
    }
}

fn emit_csv(path: &str) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    let messages = print::MESSAGES.lock().unwrap();

    for (time, texts) in messages.iter() {
        for text in texts {
            wtr.serialize(CsvFormat {
                time: *time,
                message: text,
            })?;
        }
    }
    wtr.flush()?;
    Ok(())
}

use serde_json::Value;
use std::fs::{read_to_string, remove_file};
use std::io::Read;

#[test]
fn test_emit_csv() {
    {
        let mut messages = print::MESSAGES.lock().unwrap();
        let poke = Utc.ymd(1996, 2, 27).and_hms(1, 5, 1);
        let json_str = r#"
            {
                "Event": {
                    "EventData": {
                        "CommandLine": "hoge"
                    }
                }
            }
        "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        messages.insert(Some(poke), &event_record, Some("pokepoke".to_string()));
    }

    let expect = "Time,Message
1996-02-27T01:05:01Z,pokepoke
";

    assert!(emit_csv(&"./test_emit_csv.csv".to_string()).is_ok());

    match read_to_string("./test_emit_csv.csv") {
        Err(_) => panic!("Failed to open file"),
        Ok(s) => assert_eq!(s, expect),
    };

    assert!(remove_file("./test_emit_csv.csv").is_ok());
}

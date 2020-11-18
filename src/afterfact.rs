use crate::detections::configs;
use crate::detections::print;
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use std::error::Error;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    time: DateTime<Utc>,
    message: &'a str,
}

pub fn after_fact() -> Result<(), Box<dyn Error>> {
    if let Some(csv_path) = configs::singleton().args.value_of("csv-timeline") {
        let mut wtr = csv::Writer::from_path(csv_path)?;
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
    }

    Ok(())
}

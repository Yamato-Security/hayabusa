use crate::detections::configs::StoredStatic;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use crate::detections::utils;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashSet;

#[derive(Default, Debug, Clone)]
pub struct LogMetrics {
    pub filename: String,
    pub computers: HashSet<String>,
    pub event_count: usize,
    pub first_timestamp: Option<DateTime<Utc>>,
    pub last_timestamp: Option<DateTime<Utc>>,
    pub channels: HashSet<String>,
    pub providers: HashSet<String>,
}

impl LogMetrics {
    pub fn new(filename: &str) -> Self {
        Self {
            filename: filename.to_string(),
            ..Default::default()
        }
    }
    pub fn update(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        for record in records {
            if let Some(evttime) = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
                &stored_static.eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
            {
                let timestamp =
                    match NaiveDateTime::parse_from_str(evttime.as_str(), "%Y-%m-%dT%H:%M:%S%.3fZ")
                    {
                        Ok(without_timezone_datetime) => {
                            Some(DateTime::<Utc>::from_naive_utc_and_offset(
                                without_timezone_datetime,
                                Utc,
                            ))
                        }
                        Err(_) => {
                            match NaiveDateTime::parse_from_str(
                                evttime.as_str(),
                                "%Y-%m-%dT%H:%M:%S%.3f%:z",
                            ) {
                                Ok(splunk_json_datetime) => {
                                    Some(DateTime::<Utc>::from_naive_utc_and_offset(
                                        splunk_json_datetime,
                                        Utc,
                                    ))
                                }
                                Err(e) => {
                                    let errmsg = format!(
                                        "Timestamp parse error.\nInput: {evttime}\nError: {e}\n"
                                    );
                                    if stored_static.verbose_flag {
                                        AlertMessage::alert(&errmsg).ok();
                                    }
                                    if !stored_static.quiet_errors_flag {
                                        ERROR_LOG_STACK
                                            .lock()
                                            .unwrap()
                                            .push(format!("[ERROR] {errmsg}"));
                                    }
                                    None
                                }
                            }
                        }
                    };
                if let Some(timestamp) = timestamp {
                    if self.first_timestamp.is_none() || timestamp < self.first_timestamp.unwrap() {
                        self.first_timestamp = Some(timestamp);
                    }
                    if self.last_timestamp.is_none() || timestamp > self.last_timestamp.unwrap() {
                        self.last_timestamp = Some(timestamp);
                    }
                }
            }
            if let Some(computer) =
                utils::get_event_value("Computer", &record.record, &stored_static.eventkey_alias)
            {
                self.computers
                    .insert(computer.to_string().trim_matches('"').to_string());
            }
            if let Some(channel) =
                utils::get_event_value("Channel", &record.record, &stored_static.eventkey_alias)
            {
                self.channels
                    .insert(channel.to_string().trim_matches('"').to_string());
            }
            if let Some(provider) = utils::get_event_value(
                "ProviderName",
                &record.record,
                &stored_static.eventkey_alias,
            ) {
                self.providers
                    .insert(provider.to_string().trim_matches('"').to_string());
            }
            self.event_count += 1;
        }
    }
}

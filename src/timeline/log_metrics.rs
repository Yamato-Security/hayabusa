use crate::detections::configs::StoredStatic;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::utils;
use chrono::{DateTime, Utc};
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
    pub fn update(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) {
        for record in records {
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
        self.first_timestamp = start_time;
        self.last_timestamp = end_time;
    }
}

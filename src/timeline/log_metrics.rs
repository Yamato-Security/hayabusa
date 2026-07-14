use crate::detections::configs::StoredStatic;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashSet;

/// Parses a `log-metrics` event timestamp. Handles the evtx UTC format ("2021-12-23T00:00:00.000Z")
/// and the Splunk JSON export format, which carries an explicit UTC offset
/// ("2021-12-23T00:00:00.000+09:00"). The offset is applied via `with_timezone(&Utc)` so the stored
/// instant is correct; previously the Splunk branch parsed a `NaiveDateTime`, which validates but
/// discards the offset, so the local time was stored as if it were UTC and skewed the
/// First/Last Timestamp columns. (#1820)
fn parse_log_metrics_timestamp(evttime: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    match NaiveDateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.fZ") {
        Ok(naive) => Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)),
        Err(_) => DateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.3f%:z")
            .map(|dt| dt.with_timezone(&Utc)),
    }
}

/// Per-log-file summary statistics collected for the log-metrics command: file path/name/size,
/// event count, first/last event timestamps, and the distinct computer names, channels and
/// providers seen in the file.
#[derive(Default, Debug, Clone)]
pub struct LogMetrics {
    pub filepath: String,
    pub filename: String,
    pub file_size: String,
    pub computers: HashSet<String>,
    pub event_count: usize,
    pub first_timestamp: Option<DateTime<Utc>>,
    pub last_timestamp: Option<DateTime<Utc>>,
    pub channels: HashSet<String>,
    pub providers: HashSet<String>,
}

impl LogMetrics {
    pub fn new(filepath: &str, filename: &str, file_size: String) -> Self {
        Self {
            filepath: filepath.to_string(),
            filename: filename.to_string(),
            file_size,
            ..Default::default()
        }
    }
    /// Folds a batch of records from this log file into the metrics: widens the first/last
    /// timestamp range, collects each record's computer, channel and provider, and increments the
    /// event count.
    pub fn update(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        for record in records {
            if let Some(evttime) = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
                &stored_static.eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
            {
                // Timestamps use the evtx UTC format ("2021-12-23T00:00:00.000Z") or the Splunk
                // JSON export format with an explicit offset ("2021-12-23T00:00:00.000+09:00").
                let timestamp = match parse_log_metrics_timestamp(evttime.as_str()) {
                    Ok(ts) => Some(ts),
                    Err(e) => {
                        let errmsg =
                            format!("Timestamp parse error.\nInput: {evttime}\nError: {e}\n");
                        if stored_static.verbose_flag {
                            AlertMessage::alert(&errmsg).ok();
                        }
                        if !stored_static.quiet_errors_flag {
                            stored_static
                                .error_log_stack
                                .lock()
                                .unwrap()
                                .push(format!("[ERROR] {errmsg}"));
                        }
                        None
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

#[cfg(test)]
mod tests {
    use super::parse_log_metrics_timestamp;
    use chrono::{TimeZone, Utc};

    #[test]
    /// #1820: the Splunk-JSON fallback must apply the explicit UTC offset instead of discarding it.
    fn test_parse_log_metrics_timestamp_applies_offset() {
        // evtx UTC format ("...Z") is stored as-is.
        assert_eq!(
            parse_log_metrics_timestamp("2021-12-23T00:00:00.000Z").unwrap(),
            Utc.with_ymd_and_hms(2021, 12, 23, 0, 0, 0).unwrap()
        );
        // Splunk JSON "+09:00": the same instant is 9 hours earlier in UTC (the previous
        // implementation stored it as 00:00:00Z, skewing First/Last Timestamp by 9 hours).
        assert_eq!(
            parse_log_metrics_timestamp("2021-12-23T00:00:00.000+09:00").unwrap(),
            Utc.with_ymd_and_hms(2021, 12, 22, 15, 0, 0).unwrap()
        );
        // A negative offset is applied too.
        assert_eq!(
            parse_log_metrics_timestamp("2021-12-23T00:00:00.000-05:00").unwrap(),
            Utc.with_ymd_and_hms(2021, 12, 23, 5, 0, 0).unwrap()
        );
        assert!(parse_log_metrics_timestamp("not a timestamp").is_err());
    }
}

use crate::detections::utils::{get_file_size, get_serde_number_to_string};
use crate::detections::{
    configs::{EventKeyAliasConfig, StoredStatic},
    detection::EvtxRecordInfo,
    message::AlertMessage,
    utils,
};
use crate::timeline::log_metrics::LogMetrics;
use crate::timeline::metrics::Channel::{RdsGtw, RdsLsm, Sec};
use bytesize::ByteSize;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use std::path::Path;

/// Grouping key for the logon-summary command. Logon events whose fields below all match are
/// aggregated into a single row. The `dst_*` fields identify the account/computer that was logged
/// on to, and the `src_*`/`source_*` fields identify where the logon came from.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct LoginEvent {
    pub channel: CompactString,
    pub dst_user: CompactString,
    pub dst_domain: CompactString,
    pub hostname: CompactString,
    pub logontype: CompactString,
    pub src_user: CompactString,
    pub src_domain: CompactString,
    pub source_computer: CompactString,
    pub source_ip: CompactString,
}

/// Accumulates statistics over all scanned records. Depending on the command being run, only some
/// of the fields are populated: eid-metrics fills `stats_list`, logon-summary fills
/// `stats_login_list`, computer-metrics fills `stats_computer` (from `computer_metrics.rs`),
/// log-metrics fills `stats_logfile`, and csv-timeline/json-timeline only use the record count and
/// time range kept in `total`/`start_time`/`end_time`.
#[derive(Debug, Clone, Default)]
pub struct EventMetrics {
    // Total number of records scanned.
    pub total: usize,
    // Path of the log file currently being aggregated.
    pub filepath: CompactString,
    // Timestamps of the oldest and newest events seen so far.
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    // eid-metrics: record count keyed by (EventID, Channel), both lowercased.
    pub stats_list: HashMap<(CompactString, CompactString), usize>,
    pub stats_computer: HashMap<
        CompactString, // ComputerName
        (
            CompactString, // OS
            CompactString, // Uptime
            CompactString, // TimeZone
            CompactString, // LastTimestamp
            usize,
        ),
    >,
    // logon-summary: [successful, failed] logon counts per LoginEvent grouping key.
    pub stats_login_list: HashMap<LoginEvent, [usize; 2]>,
    // log-metrics: per-log-file metrics (file size, event count, time range, computers, etc.).
    pub stats_logfile: Vec<LogMetrics>,
    // (EventRecordID, timestamp) pairs that have already been counted. Used by the
    // -X/--remove-duplicate-records option to skip duplicate records.
    pub counted_rec: HashSet<(String, String)>,
}
/**
* Outputs statistics for Windows Event Logs.
*/
impl EventMetrics {
    /// Aggregation entry point for the eid-metrics command: updates the overall record count/time
    /// range and counts records per (EventID, Channel).
    pub fn evt_stats_start(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
        (include_computer, exclude_computer): (&HashSet<CompactString>, &HashSet<CompactString>),
    ) {
        // Get the timestamps of the first and last records and the total number of records in
        // this batch.
        self.stats_time_cnt(records, stored_static);

        // Only output statistics when the metrics option is specified as an argument.
        if !stored_static.metrics_flag {
            return;
        }

        // Aggregate by EventID
        self.stats_eventid(records, stored_static, (include_computer, exclude_computer));
    }

    /// Aggregation entry point for the logon-summary command: updates the overall record
    /// count/time range and counts successful/failed logon events.
    pub fn logon_stats_start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        // Only output statistics when the logon-summary option is specified as an argument.
        if !stored_static.logon_summary_flag {
            return;
        }
        self.stats_time_cnt(records, stored_static);
        self.stats_login_eventid(records, stored_static);
    }

    /// Aggregation entry point for the log-metrics command. Records arrive in batches: if an
    /// entry for the same file that already contains the computer name of the batch's first
    /// record exists, the batch is merged into it; otherwise a new per-file entry is created.
    pub fn logfile_stats_start(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
    ) {
        if !stored_static.log_metrics_flag {
            return;
        }

        self.stats_time_cnt(records, stored_static);
        let path = Path::new(self.filepath.as_str());
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        let file_size = get_file_size(
            path,
            stored_static.verbose_flag,
            stored_static.quiet_errors_flag,
            &stored_static.error_log_stack,
        );
        let file_size = ByteSize::b(file_size).to_string();
        if let Some(existing_lm) = self.stats_logfile.iter_mut().find(|log_metrics| {
            log_metrics.filepath == self.filepath.as_str()
                && log_metrics.filename == file_name
                && log_metrics.computers.contains(
                    get_event_value_as_string(
                        "Computer",
                        &records[0].record,
                        &stored_static.eventkey_alias,
                    )
                    .to_string()
                    .trim_matches('"'),
                )
        }) {
            existing_lm.update(records, stored_static);
        } else {
            let mut log_metrics = LogMetrics::new(self.filepath.as_str(), file_name, file_size);
            log_metrics.update(records, stored_static);
            self.stats_logfile.push(log_metrics);
        }
    }

    /// Updates the total record count and widens the overall start/end time range based on the
    /// given batch of records. Used by all commands that report the scanned time range.
    pub fn stats_time_cnt(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        if records.is_empty() {
            return;
        }
        self.filepath = CompactString::from(records[0].evtx_filepath.as_str());
        // The evtx format was introduced with Windows Vista, released on 2007/1/30. Any timestamp
        // older than that is treated as invalid data (see below).
        let dt: NaiveDateTime = NaiveDate::from_ymd_opt(2007, 1, 30)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let evtx_service_released_date = Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        let mut check_start_end_time = |evttime: &str| {
            // Try the standard evtx UTC format first, then fall back to the timezone-offset
            // format used by Splunk JSON exports.
            let timestamp = match NaiveDateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.fZ") {
                Ok(without_timezone_datetime) => Some(DateTime::<Utc>::from_naive_utc_and_offset(
                    without_timezone_datetime,
                    Utc,
                )),
                Err(_) => {
                    match NaiveDateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.3f%:z") {
                        Ok(splunk_json_datetime) => Some(
                            DateTime::<Utc>::from_naive_utc_and_offset(splunk_json_datetime, Utc),
                        ),
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
                    }
                }
            };
            if timestamp.is_none() {
                return;
            }
            if self.start_time.is_none() || timestamp < self.start_time {
                if timestamp >= evtx_service_released_date {
                    self.start_time = timestamp;
                } else {
                    // Date data before 2007/1/30, when evtx was released, is treated as invalid format data.
                    stored_static.error_log_stack.lock().unwrap().push(format!(
                        "[ERROR] Invalid record found.\nEventFile:{}\nTimestamp:{}\n",
                        self.filepath,
                        timestamp.unwrap()
                    ));
                }
            }
            if self.end_time.is_none() || timestamp > self.end_time {
                self.end_time = timestamp;
            }
        };
        // Records are assumed to be in roughly chronological order, so only the first and last
        // record of the batch are examined instead of every record.
        let first = records.first();
        let last = records.last();
        let rec = [first, last];
        for record in rec.iter().flatten() {
            if let Some(evttime) = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
                &stored_static.eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
            {
                check_start_end_time(&evttime);
            } else if let Some(evttime) = utils::get_event_value(
                "Event.System.@timestamp",
                &record.record,
                &stored_static.eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
            {
                check_start_end_time(&evttime);
            };
        }
        self.total += records.len();
    }

    /// Counts each record per (EventID, Channel) pair, honoring the computer include/exclude
    /// filters and optional duplicate-record removal.
    fn stats_eventid(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
        (include_computer, exclude_computer): (&HashSet<CompactString>, &HashSet<CompactString>),
    ) {
        for record in records.iter() {
            if utils::is_filtered_by_computer_name(
                utils::get_event_value(
                    "Event.System.Computer",
                    &record.record,
                    &stored_static.eventkey_alias,
                ),
                (include_computer, exclude_computer),
            ) {
                continue;
            }
            let channel = if let Some(ch) =
                utils::get_event_value("Channel", &record.record, &stored_static.eventkey_alias)
            {
                ch.as_str().unwrap()
            } else {
                "-"
            };
            if let Some(event_id) =
                utils::get_event_value("EventID", &record.record, &stored_static.eventkey_alias)
            {
                // With -X/--remove-duplicate-records, skip records whose
                // (EventRecordID, timestamp) pair has already been counted.
                if stored_static.metrics_remove_duplication {
                    let event = &record.record["Event"]["System"];
                    let rec_id = event["EventRecordID"].to_string();
                    let evt_time = event["TimeCreated_attributes"]["SystemTime"].to_string();
                    let counted = (rec_id, evt_time);
                    if self.counted_rec.contains(&counted) {
                        continue;
                    }
                    self.counted_rec.insert(counted);
                }

                let count: &mut usize = self
                    .stats_list
                    .entry((
                        event_id.to_string().replace('\"', "").to_lowercase().into(),
                        channel.to_lowercase().into(),
                    ))
                    .or_insert(0);
                *count += 1;
            };
        }
    }
    /// Counts logon events for the logon-summary command: Security 4624 (successful logon),
    /// Security 4625 (failed logon), RDS LocalSessionManager 21 and RDS Gateway 302 (both
    /// counted as successful logons).
    fn stats_login_eventid(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        // Maps the LogonType number to a human-readable label for display.
        let logontype_map: HashMap<&str, &str> = HashMap::from([
            ("0", "0 - System"),
            ("2", "2 - Interactive"),
            ("3", "3 - Network"),
            ("4", "4 - Batch"),
            ("5", "5 - Service"),
            ("7", "7 - Unlock"),
            ("8", "8 - NetworkCleartext"),
            ("9", "9 - NewInteractive"),
            ("10", "10 - RemoteInteractive"),
            ("11", "11 - CachedInteractive"),
            ("12", "12 - CachedRemoteInteractive"),
            ("13", "13 - CachedUnlock"),
        ]);
        for record in records.iter() {
            if let Some(evtid) =
                utils::get_event_value("EventID", &record.record, &stored_static.eventkey_alias)
            {
                let event_id: i64 = if evtid.is_number() {
                    evtid.as_i64().unwrap()
                } else {
                    let rec_id = get_serde_number_to_string(
                        &record.record["Event"]["System"]["EventRecordID"],
                        false,
                    )
                    .unwrap_or("n/a".into());
                    let errmsg = format!(
                        "Failed to parse event ID from event file: {}\nEvent record ID: {}\n",
                        record.evtx_filepath, rec_id
                    );
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
                    continue;
                };

                let channel = get_event_value_as_string(
                    "Channel",
                    &record.record,
                    &stored_static.eventkey_alias,
                );
                if let Some(channel) = is_target_event(event_id, &channel) {
                    let channel_name = match channel {
                        Sec => {
                            if event_id == 4624 {
                                CompactString::from("Sec 4624")
                            } else {
                                CompactString::from("Sec 4625")
                            }
                        }
                        RdsLsm => CompactString::from("RDS-LSM 21"),
                        RdsGtw => CompactString::from("RDS-GTW 302"),
                    };
                    // The RDS events store the account as a single "DOMAIN\user" field, so the
                    // user and domain parts are split out of it below.
                    let dst_user = match channel {
                        Sec => get_event_value_as_string(
                            "TargetUserName",
                            &record.record,
                            &stored_static.eventkey_alias,
                        ),
                        RdsLsm => {
                            let user_with_domain = get_event_value_as_string(
                                "UserDataUser",
                                &record.record,
                                &stored_static.eventkey_alias,
                            );
                            let user = user_with_domain
                                .rsplit('\\')
                                .next()
                                .unwrap_or(&user_with_domain);
                            CompactString::from(user)
                        }
                        RdsGtw => {
                            let user_with_domain = get_event_value_as_string(
                                "RdsGtwUsername",
                                &record.record,
                                &stored_static.eventkey_alias,
                            );
                            let user = user_with_domain
                                .rsplit('\\')
                                .next()
                                .unwrap_or(&user_with_domain);
                            CompactString::from(user)
                        }
                    };

                    let src_user = get_event_value_as_string(
                        "SubjectUserName",
                        &record.record,
                        &stored_static.eventkey_alias,
                    );
                    let dst_domain = match channel {
                        Sec => get_event_value_as_string(
                            "TargetDomainName",
                            &record.record,
                            &stored_static.eventkey_alias,
                        ),
                        RdsLsm => {
                            let user_with_domain = get_event_value_as_string(
                                "UserDataUser",
                                &record.record,
                                &stored_static.eventkey_alias,
                            );
                            let domain = user_with_domain.rsplit_once('\\').map(|x| x.0);
                            CompactString::from(domain.unwrap_or("-"))
                        }
                        RdsGtw => {
                            let user_with_domain = get_event_value_as_string(
                                "RdsGtwUsername",
                                &record.record,
                                &stored_static.eventkey_alias,
                            );
                            let domain = user_with_domain.rsplit_once('\\').map(|x| x.0);
                            CompactString::from(domain.unwrap_or("-"))
                        }
                    };
                    let src_domain = get_event_value_as_string(
                        "SubjectDomainName",
                        &record.record,
                        &stored_static.eventkey_alias,
                    );
                    let logontype = get_event_value_as_string(
                        "LogonType",
                        &record.record,
                        &stored_static.eventkey_alias,
                    );
                    let hostname = get_event_value_as_string(
                        "Computer",
                        &record.record,
                        &stored_static.eventkey_alias,
                    );
                    let source_computer = get_event_value_as_string(
                        "WorkstationName",
                        &record.record,
                        &stored_static.eventkey_alias,
                    );
                    let source_ip = match channel {
                        Sec => get_event_value_as_string(
                            "IpAddress",
                            &record.record,
                            &stored_static.eventkey_alias,
                        ),
                        RdsLsm => get_event_value_as_string(
                            "UserDataAddress",
                            &record.record,
                            &stored_static.eventkey_alias,
                        ),
                        RdsGtw => get_event_value_as_string(
                            "RdsGtwIpAddress",
                            &record.record,
                            &stored_static.eventkey_alias,
                        ),
                    };
                    // With -X/--remove-duplicate-records, skip records whose
                    // (EventRecordID, timestamp) pair has already been counted.
                    if stored_static.metrics_remove_duplication {
                        let event = &record.record["Event"]["System"];
                        let rec_id = event["EventRecordID"].to_string();
                        let evt_time = event["TimeCreated_attributes"]["SystemTime"].to_string();
                        let counted = (rec_id, evt_time);
                        if self.counted_rec.contains(&counted) {
                            continue;
                        }
                        self.counted_rec.insert(counted);
                    }

                    let countlist: [usize; 2] = [0, 0];
                    // Fetch (or initialize) the [successful, failed] counters for this logon
                    // event. At this point the EventID is 4624, 4625, 21 or 302; 4625 counts as a
                    // failed logon and the others as successful logons.
                    let count: &mut [usize; 2] = self
                        .stats_login_list
                        .entry(LoginEvent {
                            channel: channel_name,
                            dst_user,
                            dst_domain,
                            hostname,
                            logontype: CompactString::from(
                                *logontype_map
                                    .get(&logontype.as_str())
                                    .unwrap_or(&logontype.as_str()),
                            ),
                            src_user,
                            src_domain,
                            source_computer,
                            source_ip,
                        })
                        .or_insert(countlist);
                    if event_id == 4624 || event_id == 21 || event_id == 302 {
                        count[0] += 1;
                    } else if event_id == 4625 {
                        count[1] += 1;
                    }
                }
            };
        }
    }
}

/// Looks up `key` in the record (resolving it through eventkey_alias.txt) and returns the value
/// as a string with all double/single quote characters removed, or "-" if the field is missing.
fn get_event_value_as_string(
    key: &str,
    record: &serde_json::Value,
    eventkey_alias: &EventKeyAliasConfig,
) -> CompactString {
    CompactString::from(
        utils::get_serde_number_to_string(
            utils::get_event_value(key, record, eventkey_alias).unwrap_or(&serde_json::Value::Null),
            false,
        )
        .unwrap_or_else(|| "-".into())
        .replace(['"', '\''], ""),
    )
}

/// Event log channels that contain the logon events tracked by the logon-summary command.
enum Channel {
    Sec,    // Security
    RdsLsm, // Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    RdsGtw, // Microsoft-Windows-TerminalServices-Gateway/Operational
}

/// Returns which channel the record's logon event belongs to if its (EventID, Channel) pair is
/// one that the logon summary tracks, or None if the record is not a target logon event.
fn is_target_event(event_id: i64, channel: &str) -> Option<Channel> {
    if (event_id == 4624 || event_id == 4625) && channel == "Security" {
        return Some(Sec);
    }
    if event_id == 21
        && channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    {
        return Some(RdsLsm);
    }
    if event_id == 302 && channel == "Microsoft-Windows-TerminalServices-Gateway/Operational" {
        return Some(RdsGtw);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use compact_str::CompactString;
    use hashbrown::{HashMap, HashSet};
    use nested::Nested;

    use crate::detections::configs::TimeFormatOptions;
    use crate::{
        detections::{
            configs::{
                Action, ClobberOption, CommonOptions, Config, DetectCommonOption, EidMetricsOption,
                InputOption, StoredStatic,
            },
            utils::create_rec_info,
        },
        timeline::timelines::Timeline,
    };

    fn create_dummy_stored_static(action: Action) -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(action),
            debug: false,
        }))
    }

    /// Test for statistics aggregation of the metrics command.
    #[test]
    pub fn test_evt_logon_stats() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::EidMetrics(EidMetricsOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: None,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    json_input: false,
                    validate_checksums: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                },
                output: None,
                clobber_opt: ClobberOption { clobber: false },
                remove_duplicate_detections: false,
            }));

        let mut timeline = Timeline::new();
        // Test 1: When the channel of the record is included in the alias.
        let alias_ch_record_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"HAYABUSA-DESKTOP"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let mut input_records = vec![];
        let alias_ch_record = serde_json::from_str(alias_ch_record_str).unwrap();
        input_records.push(create_rec_info(
            alias_ch_record,
            "testpath".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        // Test 2: When the channel name of the record is not included in the alias.
        let no_alias_ch_record_str = r#"{
            "Event": {"System": {"EventID": 4104, "Channel": "NotExistInAlias", "Computer":"HAYABUSA-DESKTOP"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut expect: HashMap<(CompactString, CompactString), usize> = HashMap::new();
        expect.insert(("4103".into(), "security".into()), 1);
        expect.insert(("4104".into(), "notexistinalias".into()), 1);
        let no_alias_ch_record = serde_json::from_str(no_alias_ch_record_str).unwrap();
        input_records.push(create_rec_info(
            no_alias_ch_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        let include_computer: HashSet<CompactString> = HashSet::new();
        let exclude_computer: HashSet<CompactString> = HashSet::new();
        timeline.stats.evt_stats_start(
            &input_records,
            &dummy_stored_static,
            (&include_computer, &exclude_computer),
        );
        assert_eq!(timeline.stats.stats_list.len(), expect.len());

        for (k, v) in timeline.stats.stats_list {
            assert!(expect.contains_key(&k));
            assert_eq!(expect.get(&k).unwrap(), &v);
        }
    }
}

use crate::detections::message::ERROR_LOG_STACK;
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

#[derive(Debug, Clone, Default)]
pub struct EventMetrics {
    pub total: usize,
    pub filepath: CompactString,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
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
    pub stats_login_list: HashMap<LoginEvent, [usize; 2]>,
    pub stats_logfile: Vec<LogMetrics>,
    pub counted_rec: HashSet<(String, String)>,
}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventMetrics {
    pub fn evt_stats_start(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
        (include_computer, exclude_computer): (&HashSet<CompactString>, &HashSet<CompactString>),
    ) {
        // recordsから、 最初のレコードの時刻と最後のレコードの時刻、レコードの総数を取得する
        self.stats_time_cnt(records, stored_static);

        // 引数でmetricsオプションが指定されている時だけ、統計情報を出力する。
        if !stored_static.metrics_flag {
            return;
        }

        // EventIDで集計
        self.stats_eventid(records, stored_static, (include_computer, exclude_computer));
    }

    pub fn logon_stats_start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        // 引数でlogon-summaryオプションが指定されている時だけ、統計情報を出力する。
        if !stored_static.logon_summary_flag {
            return;
        }
        self.stats_time_cnt(records, stored_static);
        self.stats_login_eventid(records, stored_static);
    }

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
        );
        let file_size = ByteSize::b(file_size).to_string();
        if let Some(existing_lm) = self.stats_logfile.iter_mut().find(|lm| {
            lm.filename == file_name
                && lm.computers.contains(
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
            let mut lm = LogMetrics::new(file_name, file_size);
            lm.update(records, stored_static);
            self.stats_logfile.push(lm);
        }
    }

    pub fn stats_time_cnt(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        if records.is_empty() {
            return;
        }
        self.filepath = CompactString::from(records[0].evtx_filepath.as_str());
        let dt: NaiveDateTime = NaiveDate::from_ymd_opt(2007, 1, 30)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let evtx_service_released_date = Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        let mut check_start_end_time = |evttime: &str| {
            let timestamp = match NaiveDateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.3fZ") {
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
            if timestamp.is_none() {
                return;
            }
            if self.start_time.is_none() || timestamp < self.start_time {
                if timestamp >= evtx_service_released_date {
                    self.start_time = timestamp;
                } else {
                    // evtxがリリースされた2007/1/30以前の日付データは不正な形式データ扱いとする
                    ERROR_LOG_STACK.lock().unwrap().push(format!(
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

    /// EventIDで集計
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
            if let Some(idnum) =
                utils::get_event_value("EventID", &record.record, &stored_static.eventkey_alias)
            {
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
                        idnum.to_string().replace('\"', "").to_lowercase().into(),
                        channel.to_lowercase().into(),
                    ))
                    .or_insert(0);
                *count += 1;
            };
        }
    }
    // Login event
    fn stats_login_eventid(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
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
                let idnum: i64 = if evtid.is_number() {
                    evtid.as_i64().unwrap()
                } else {
                    let rec_id = get_serde_number_to_string(
                        &record.record["Event"]["System"]["EventRecordID"],
                        false,
                    )
                    .unwrap_or("n/a".into());
                    let errmsg = format!(
                        "Failed to parse event ID from event file: {}\nEvent record ID: {}\n",
                        &record.evtx_filepath, rec_id
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
                    continue;
                };

                let channel = get_event_value_as_string(
                    "Channel",
                    &record.record,
                    &stored_static.eventkey_alias,
                );
                if let Some(channel) = is_target_event(idnum, &channel) {
                    let channel_name = match channel {
                        Sec => {
                            if idnum == 4624 {
                                CompactString::from("Sec 4624")
                            } else {
                                CompactString::from("Sec 4625")
                            }
                        }
                        RdsLsm => CompactString::from("RDS-LSM 21"),
                        RdsGtw => CompactString::from("RDS-GTW 302"),
                    };
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
                                "RdsGtwUserName",
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
                    // この段階でEventIDは4624もしくは4625となるのでこの段階で対応するカウンターを取得する
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
                    if idnum == 4624 || idnum == 21 || idnum == 302 {
                        count[0] += 1;
                    } else if idnum == 4625 {
                        count[1] += 1;
                    }
                }
            };
        }
    }
}

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

enum Channel {
    Sec,
    RdsLsm,
    RdsGtw,
}

fn is_target_event(idnum: i64, channel: &str) -> Option<Channel> {
    if (idnum == 4624 || idnum == 4625) && channel == "Security" {
        return Some(Sec);
    }
    if idnum == 21
        && channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    {
        return Some(RdsLsm);
    }
    if idnum == 302 && channel == "Microsoft-Windows-TerminalServices-Gateway/Operational" {
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
                Action, CommonOptions, Config, DetectCommonOption, EidMetricsOption, InputOption,
                StoredStatic,
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

    /// メトリクスコマンドの統計情報集計のテスト。 Testing of statistics aggregation for metrics commands.
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
                clobber: false,
                remove_duplicate_detections: false,
            }));

        let mut timeline = Timeline::new();
        // テスト1: レコードのチャンネルがaliasに含まれている場合
        let alias_ch_record_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"HAYABUSA-DESKTOP"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let mut input_datas = vec![];
        let alias_ch_record = serde_json::from_str(alias_ch_record_str).unwrap();
        input_datas.push(create_rec_info(
            alias_ch_record,
            "testpath".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
        ));

        // テスト2: レコードのチャンネル名がaliasに含まれていない場合
        let no_alias_ch_record_str = r#"{
            "Event": {"System": {"EventID": 4104, "Channel": "NotExistInAlias", "Computer":"HAYABUSA-DESKTOP"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut expect: HashMap<(CompactString, CompactString), usize> = HashMap::new();
        expect.insert(("4103".into(), "security".into()), 1);
        expect.insert(("4104".into(), "notexistinalias".into()), 1);
        let no_alias_ch_record = serde_json::from_str(no_alias_ch_record_str).unwrap();
        input_datas.push(create_rec_info(
            no_alias_ch_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
        ));

        let include_computer: HashSet<CompactString> = HashSet::new();
        let exclude_computer: HashSet<CompactString> = HashSet::new();
        timeline.stats.evt_stats_start(
            &input_datas,
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

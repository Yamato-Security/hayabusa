use crate::detections::message::ERROR_LOG_STACK;
use crate::detections::{
    configs::{EventKeyAliasConfig, StoredStatic},
    detection::EvtxRecordInfo,
    message::AlertMessage,
    utils,
};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct EventMetrics {
    pub total: usize,
    pub filepath: CompactString,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub stats_list: HashMap<(CompactString, CompactString), usize>,
    pub stats_login_list: HashMap<
        (
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
        ),
        [usize; 2],
    >,
}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventMetrics {
    pub fn new(
        total: usize,
        filepath: CompactString,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        stats_list: HashMap<(CompactString, CompactString), usize>,
        stats_login_list: HashMap<
            (
                CompactString,
                CompactString,
                CompactString,
                CompactString,
                CompactString,
            ),
            [usize; 2],
        >,
    ) -> EventMetrics {
        EventMetrics {
            total,
            filepath,
            start_time,
            end_time,
            stats_list,
            stats_login_list,
        }
    }

    pub fn evt_stats_start(
        &mut self,
        records: &[EvtxRecordInfo],
        stored_static: &StoredStatic,
        (include_computer, exclude_computer): (&HashSet<CompactString>, &HashSet<CompactString>),
    ) {
        // recordsから、 最初のレコードの時刻と最後のレコードの時刻、レコードの総数を取得する
        self.stats_time_cnt(records, &stored_static.eventkey_alias);

        // 引数でmetricsオプションが指定されている時だけ、統計情報を出力する。
        if !stored_static.metrics_flag {
            return;
        }

        // EventIDで集計
        self.stats_eventid(records, stored_static, (include_computer, exclude_computer));
    }

    pub fn logon_stats_start(
        &mut self,
        records: &[EvtxRecordInfo],
        logon_summary_flag: bool,
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        // 引数でlogon-summaryオプションが指定されている時だけ、統計情報を出力する。
        if !logon_summary_flag {
            return;
        }

        self.stats_time_cnt(records, eventkey_alias);

        self.stats_login_eventid(records, eventkey_alias);
    }

    fn stats_time_cnt(&mut self, records: &[EvtxRecordInfo], eventkey_alias: &EventKeyAliasConfig) {
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
                            AlertMessage::alert(&format!(
                                "timestamp parse error. input: {evttime} {e}"
                            ))
                            .ok();
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
                        "[ERROR] Invalid record found. EventFile:{} Timestamp:{}",
                        self.filepath,
                        timestamp.unwrap()
                    ));
                }
            }
            if self.end_time.is_none() || timestamp > self.end_time {
                self.end_time = timestamp;
            }
        };
        // sortしなくてもイベントログのTimeframeを取得できるように修正しました。
        // sortしないことにより計算量が改善されています。
        for record in records.iter() {
            if let Some(evttime) = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
                eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
            {
                check_start_end_time(&evttime);
            } else if let Some(evttime) =
                utils::get_event_value("Event.System.@timestamp", &record.record, eventkey_alias)
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
                ch.as_str().unwrap_or_else(|| { "None" })
            } else {
                "-"
            };
            if let Some(idnum) =
                utils::get_event_value("EventID", &record.record, &stored_static.eventkey_alias)
            {
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
    fn stats_login_eventid(
        &mut self,
        records: &[EvtxRecordInfo],
        eventkey_alias: &EventKeyAliasConfig,
    ) {
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
            if let Some(evtid) = utils::get_event_value("EventID", &record.record, eventkey_alias) {
                let idnum: i64 = if evtid.is_number() {
                    evtid.as_i64().unwrap()
                } else {
                    evtid.as_str().unwrap().parse::<i64>().unwrap_or_default()
                };

                if !(idnum == 4624 || idnum == 4625)
                    || utils::get_serde_number_to_string(
                        utils::get_event_value("Channel", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        false,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], "")
                        != "Security"
                {
                    continue;
                }

                let username = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("TargetUserName", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        false,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );
                let logontype = utils::get_serde_number_to_string(
                    utils::get_event_value("LogonType", &record.record, eventkey_alias)
                        .unwrap_or(&serde_json::Value::Null),
                    false,
                )
                .unwrap_or_else(|| "n/a".into())
                .replace(['"', '\''], "");
                let hostname = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("Computer", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        false,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );

                let source_computer = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("WorkstationName", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        false,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );

                let source_ip = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("IpAddress", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        false,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );

                let countlist: [usize; 2] = [0, 0];
                // この段階でEventIDは4624もしくは4625となるのでこの段階で対応するカウンターを取得する
                let count: &mut [usize; 2] = self
                    .stats_login_list
                    .entry((
                        username,
                        hostname,
                        CompactString::from(
                            *logontype_map
                                .get(&logontype.as_str())
                                .unwrap_or(&logontype.as_str()),
                        ),
                        source_computer,
                        source_ip,
                    ))
                    .or_insert(countlist);
                if idnum == 4624 {
                    count[0] += 1;
                } else if idnum == 4625 {
                    count[1] += 1;
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use compact_str::CompactString;
    use hashbrown::{HashMap, HashSet};
    use nested::Nested;

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
                    timeline_offset: None,
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
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                output: None,
                clobber: false,
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

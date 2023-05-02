use crate::detections::{
    configs::{EventKeyAliasConfig, StoredStatic},
    detection::EvtxRecordInfo,
    message::AlertMessage,
    utils,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use compact_str::CompactString;
use hashbrown::HashMap;

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

    pub fn evt_stats_start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        // _recordsから、EventIDを取り出す。
        self.stats_time_cnt(records, &stored_static.eventkey_alias);

        // 引数でmetricsオプションが指定されている時だけ、統計情報を出力する。
        if !stored_static.metrics_flag {
            return;
        }

        // EventIDで集計
        self.stats_eventid(records, stored_static);
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

        let mut check_start_end_time = |evttime: &str| {
            let timestamp = match NaiveDateTime::parse_from_str(evttime, "%Y-%m-%dT%H:%M:%S%.3fZ") {
                Ok(without_timezone_datetime) => {
                    Some(DateTime::<Utc>::from_utc(without_timezone_datetime, Utc))
                }
                Err(e) => {
                    AlertMessage::alert(&format!("timestamp parse error. input: {evttime} {e}"))
                        .ok();
                    None
                }
            };
            if timestamp.is_none() {
                return;
            }
            if self.start_time.is_none() || timestamp < self.start_time {
                self.start_time = timestamp;
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
    fn stats_eventid(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        for record in records.iter() {
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

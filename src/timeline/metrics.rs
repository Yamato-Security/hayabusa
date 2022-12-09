use crate::detections::{configs::EventKeyAliasConfig, detection::EvtxRecordInfo, utils};
use hashbrown::HashMap;

#[derive(Debug, Clone)]
pub struct EventMetrics {
    pub total: usize,
    pub filepath: String,
    pub start_time: String,
    pub end_time: String,
    pub stats_list: HashMap<(String, String), usize>,
    pub stats_login_list: HashMap<String, [usize; 2]>,
}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventMetrics {
    pub fn new(
        total: usize,
        filepath: String,
        start_time: String,
        end_time: String,
        stats_list: HashMap<(String, String), usize>,
        stats_login_list: HashMap<String, [usize; 2]>,
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
        metrics_flag: bool,
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        // 引数でmetricsオプションが指定されている時だけ、統計情報を出力する。
        if !metrics_flag {
            return;
        }

        // _recordsから、EventIDを取り出す。
        self.stats_time_cnt(records, eventkey_alias);

        // EventIDで集計
        self.stats_eventid(records, eventkey_alias);
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
        self.filepath = records[0].evtx_filepath.as_str().to_owned();
        // sortしなくてもイベントログのTimeframeを取得できるように修正しました。
        // sortしないことにより計算量が改善されています。
        for record in records.iter() {
            if let Some(evttime) = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
                eventkey_alias,
            )
            .map(|evt_value| evt_value.to_string())
            {
                if self.start_time.is_empty() || evttime < self.start_time {
                    self.start_time = evttime.to_string();
                }
                if self.end_time.is_empty() || evttime > self.end_time {
                    self.end_time = evttime;
                }
            };
        }
        self.total += records.len();
    }

    /// EventID`で集計
    fn stats_eventid(&mut self, records: &[EvtxRecordInfo], eventkey_alias: &EventKeyAliasConfig) {
        //        let mut evtstat_map = HashMap::new();
        for record in records.iter() {
            let channel = if let Some(ch) =
                utils::get_event_value("Channel", &record.record, eventkey_alias)
            {
                ch.to_string()
            } else {
                "-".to_string()
            };
            if let Some(idnum) = utils::get_event_value("EventID", &record.record, eventkey_alias) {
                let count: &mut usize = self
                    .stats_list
                    .entry((idnum.to_string().replace('\"', ""), channel))
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
        for record in records.iter() {
            if let Some(evtid) = utils::get_event_value("EventID", &record.record, eventkey_alias) {
                let idnum: i64 = if evtid.is_number() {
                    evtid.as_i64().unwrap()
                } else {
                    evtid.as_str().unwrap().parse::<i64>().unwrap_or_default()
                };
                if !(idnum == 4624 || idnum == 4625) {
                    continue;
                }

                let username =
                    utils::get_event_value("TargetUserName", &record.record, eventkey_alias);
                let countlist: [usize; 2] = [0, 0];
                if idnum == 4624 {
                    let count: &mut [usize; 2] = self
                        .stats_login_list
                        .entry(username.unwrap().to_string())
                        .or_insert(countlist);
                    count[0] += 1;
                } else if idnum == 4625 {
                    let count: &mut [usize; 2] = self
                        .stats_login_list
                        .entry(username.unwrap().to_string())
                        .or_insert(countlist);
                    count[1] += 1;
                }
            };
        }
    }
}

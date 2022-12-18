use crate::detections::message::{LOGONSUMMARY_FLAG, METRICS_FLAG};
use crate::detections::{detection::EvtxRecordInfo, utils};
use hashbrown::HashMap;

#[derive(Debug, Clone)]
pub struct EventMetrics {
    pub total: usize,
    pub filepath: String,
    pub start_time: String,
    pub end_time: String,
    pub stats_list: HashMap<(String, String), usize>,
    pub stats_login_list: HashMap<(String, String, String), [usize; 2]>,
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
        stats_login_list: HashMap<(String, String, String), [usize; 2]>,
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

    pub fn evt_stats_start(&mut self, records: &[EvtxRecordInfo]) {
        // 引数でmetricsオプションが指定されている時だけ、統計情報を出力する。
        if !*METRICS_FLAG {
            return;
        }

        //let mut filesize = 0;
        // _recordsから、EventIDを取り出す。
        self.stats_time_cnt(records);

        // EventIDで集計
        //let evtstat_map = HashMap::new();
        self.stats_eventid(records);
    }

    pub fn logon_stats_start(&mut self, records: &[EvtxRecordInfo]) {
        // 引数でlogon-summaryオプションが指定されている時だけ、統計情報を出力する。
        if !*LOGONSUMMARY_FLAG {
            return;
        }

        self.stats_time_cnt(records);

        self.stats_login_eventid(records);
    }

    fn stats_time_cnt(&mut self, records: &[EvtxRecordInfo]) {
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
    fn stats_eventid(&mut self, records: &[EvtxRecordInfo]) {
        //        let mut evtstat_map = HashMap::new();
        for record in records.iter() {
            let channel = if let Some(ch) = utils::get_event_value("Channel", &record.record) {
                ch.to_string()
            } else {
                "-".to_string()
            };
            if let Some(idnum) = utils::get_event_value("EventID", &record.record) {
                let count: &mut usize = self
                    .stats_list
                    .entry((idnum.to_string().replace('\"', ""), channel))
                    .or_insert(0);
                *count += 1;
            };
        }
    }
    // Login event
    fn stats_login_eventid(&mut self, records: &[EvtxRecordInfo]) {
        for record in records.iter() {
            if let Some(evtid) = utils::get_event_value("EventID", &record.record) {
                let idnum: i64 = if evtid.is_number() {
                    evtid.as_i64().unwrap()
                } else {
                    evtid.as_str().unwrap().parse::<i64>().unwrap_or_default()
                };
                if !(idnum == 4624 || idnum == 4625) {
                    continue;
                }

                let username = utils::value_to_string(
                    utils::get_event_value("TargetUserName", &record.record).unwrap(),
                );
                let logontype = utils::value_to_string(
                    utils::get_event_value("LogonType", &record.record).unwrap(),
                );
                let hostname = utils::value_to_string(
                    utils::get_event_value("Computer", &record.record).unwrap(),
                );
                let countlist: [usize; 2] = [0, 0];
                // この段階でEventIDは4624もしくは4625となるのでこの段階で対応するカウンターを取得する
                let count: &mut [usize; 2] = self
                    .stats_login_list
                    .entry((
                        username.unwrap_or_default(),
                        hostname.unwrap_or_default(),
                        logontype.unwrap_or_default(),
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

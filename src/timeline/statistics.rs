use crate::detections::print::{LOGONSUMMARY_FLAG, STATISTICS_FLAG};
use crate::detections::{detection::EvtxRecordInfo, utils};
use hashbrown::HashMap;

#[derive(Debug)]
pub struct EventStatistics {
    pub total: usize,
    pub filepath: String,
    pub start_time: String,
    pub end_time: String,
    pub stats_list: HashMap<String, usize>,
    pub stats_login_list: HashMap<String, [usize; 2]>,
}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventStatistics {
    pub fn new(
        total: usize,
        filepath: String,
        start_time: String,
        end_time: String,
        stats_list: HashMap<String, usize>,
        stats_login_list: HashMap<String, [usize; 2]>,
    ) -> EventStatistics {
        EventStatistics {
            total,
            filepath,
            start_time,
            end_time,
            stats_list,
            stats_login_list,
        }
    }

    pub fn evt_stats_start(&mut self, records: &[EvtxRecordInfo]) {
        // 引数でstatisticsオプションが指定されている時だけ、統計情報を出力する。
        if !*STATISTICS_FLAG {
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
        // もうちょっと感じに書けるといえば書けます。
        for record in records.iter() {
            let evttime = utils::get_event_value(
                "Event.System.TimeCreated_attributes.SystemTime",
                &record.record,
            )
            .map(|evt_value| evt_value.to_string());
            if evttime.is_none() {
                continue;
            }

            let evttime = evttime.unwrap();
            if self.start_time.is_empty() || evttime < self.start_time {
                self.start_time = evttime.to_string();
            }
            if self.end_time.is_empty() || evttime > self.end_time {
                self.end_time = evttime;
            }
        }
        self.total += records.len();
    }

    // EventIDで集計
    fn stats_eventid(&mut self, records: &[EvtxRecordInfo]) {
        //        let mut evtstat_map = HashMap::new();
        for record in records.iter() {
            let evtid = utils::get_event_value("EventID", &record.record);
            if evtid.is_none() {
                continue;
            }

            let idnum = evtid.unwrap();
            let count: &mut usize = self.stats_list.entry(idnum.to_string()).or_insert(0);
            *count += 1;
        }
        //        return evtstat_map;
    }
    // Login event
    fn stats_login_eventid(&mut self, records: &[EvtxRecordInfo]) {
        for record in records.iter() {
            let evtid = utils::get_event_value("EventID", &record.record);
            if evtid.is_none() {
                continue;
            }
            let username = utils::get_event_value("TargetUserName", &record.record);
            let idnum = evtid.unwrap();
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
        }
    }
}

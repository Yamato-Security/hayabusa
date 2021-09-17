use crate::detections::detection::EvtxRecordInfo;

use super::statistics::EventStatistics;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Timeline {
    pub stats: EventStatistics,
}

impl Timeline {
    pub fn new() -> Timeline {
        let totalcnt = "".to_string();
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();

        let statistic = EventStatistics::new(totalcnt, starttm, endtm, statslst);
        return Timeline { stats: statistic };
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) {
        self.stats.start(records);
    }
    pub fn tm_stats_resmsg(&mut self) {
        // 配列不要だったので削除しました。
        println!("{:?}", self.stats.start_time);
        println!("{:?}", self.stats.end_time);
        for (key, val) in &self.stats.stats_list {
            println!("key={},val={}", key, val);
        }
    }
}

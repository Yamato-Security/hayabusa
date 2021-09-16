use crate::detections::detection::EvtxRecordInfo;

use super::statistics::EventStatistics;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Timeline {}

impl Timeline {
    pub fn new() -> Timeline {
        return Timeline {};
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) -> EventStatistics {
        let totalcnt = "".to_string();
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();

        let mut statistic = EventStatistics::new(totalcnt, starttm, endtm, statslst);
        statistic.start(records);
        println!("{:?}", statistic.total.to_string());
        println!("{:?}", statistic.start_time.to_string());
        println!("{:?}", statistic.end_time.to_string());
        println!("{:?}", statistic.stats_list);
        return statistic;
    }
    pub fn tm_stats_resmsg(&mut self, stats_list: &Vec<EventStatistics>) {
        let totalcnt = "".to_string();
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();

        let mut stats_res = EventStatistics::new(totalcnt, starttm, endtm, statslst);
        for statsdata in stats_list.iter() {
            // set start_time
            if (stats_res.start_time == "") || (stats_res.start_time > statsdata.start_time) {
                stats_res.start_time = statsdata.start_time.to_string();
                println!("{:?}", stats_res.start_time);
            }
            // set end_time
            if (stats_res.end_time == "") || (stats_res.end_time < statsdata.end_time) {
                stats_res.end_time = statsdata.end_time.to_string();
                println!("{:?}", stats_res.end_time);
            }
            // mod list
            for (key, val) in &statsdata.stats_list {
                println!("key={},val={}", key, val);
                //                let counter = stats_res.stats_list.entry(key).or_insert(0);
                //                println!("{:?}", *counter);
                //                *counter += val;
                //                println!("{:?}", *counter);
            }
        }
    }
}

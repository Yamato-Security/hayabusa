use crate::detections::detection::EvtxRecordInfo;

use super::statistics::EventStatistics;

#[derive(Debug)]
pub struct Timeline {}

impl Timeline {
    pub fn new() -> Timeline {
        return Timeline {};
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) {
        let mut statistic = EventStatistics::new();
        statistic.start(records);
    }
}

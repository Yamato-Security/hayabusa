use std::path::PathBuf;

use crate::detections::detection::EvtxRecordInfo;

use super::statistics::EventStatistics;

#[derive(Debug)]
pub struct Timeline {}

impl Timeline {
    pub fn new() -> Timeline {
        return Timeline {};
    }

    pub fn start(&mut self, evtx_files: &Vec<PathBuf>, records: &Vec<EvtxRecordInfo>) {
        let mut statistic = EventStatistics::new();
        statistic.start(evtx_files, records);
    }
}

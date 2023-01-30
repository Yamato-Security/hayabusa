use crate::detections::detection::EvtxRecordInfo;
use compact_str::CompactString;
use hashbrown::HashSet;

#[derive(Debug, Clone)]
pub struct EventSearch {
    pub total: usize,
    pub filepath: String,
    search_result: HashSet<(
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
    )>,
}

impl EventSearch {
    pub fn new(
        total: usize,
        filepath: String,
        search_result: HashSet<(
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
        )>,
    ) -> EventSearch {
        EventSearch {
            total,
            filepath,
            search_result,
        }
    }

    pub fn search_start(&mut self, records: &[EvtxRecordInfo], search_flag: bool, keyword: &str) {
        if !search_flag {
            return;
        }
        println!("Search_start");
        self.search_keyword(records, keyword);
    }

    fn search_keyword(&mut self, records: &[EvtxRecordInfo], keyword: &str) {
        if records.is_empty() {
            return;
        }

        for record in records.iter() {
            self.filepath = records[0].evtx_filepath.to_owned();
            // self.start_time = null;
            // self.end_time = null;
            // stats_list = null;
            // stats_login_list = null;
            if record.data_string.contains(keyword) {
                println!("find \"{}\"", keyword);
                println!("{:?}", record.data_string);

                let timestamp = "hoge";
                let computer = "computer";
                let channel = "channel";
                let eventid = "eventid";
                let recordid = "recordid";
                let eventtitle = "eventtitle";
                let allfieldinfo = "allfieldinfo";
                let evtxfile = "evtxfile";

                self.search_result.entry((
                    timestamp.into(),
                    computer.into(),
                    channel.into(),
                    eventid.into(),
                    recordid.into(),
                    eventtitle.into(),
                    allfieldinfo.into(),
                    evtxfile.into(),
                ));
                self.total += 1;
            }
        }
    }
}

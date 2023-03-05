use crate::detections::{configs::EventKeyAliasConfig, detection::EvtxRecordInfo, utils};
use compact_str::CompactString;
use hashbrown::HashSet;

#[derive(Debug, Clone)]
pub struct EventSearch {
    pub total: usize,
    pub filepath: CompactString,
    pub search_result: HashSet<(
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
        filepath: CompactString,
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

    pub fn search_start(
        &mut self,
        records: &[EvtxRecordInfo],
        search_flag: bool,
        keyword: &str,
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        if !search_flag {
            return;
        }
        println!("Search_start");
        self.search_keyword(records, keyword, eventkey_alias);
    }

    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        keyword: &str,
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        if records.is_empty() {
            return;
        }

        for record in records.iter() {
            self.filepath = CompactString::from(records[0].evtx_filepath.as_str());
            if record.data_string.contains(keyword) {
                println!("find \"{}\"", keyword);
                println!("{:?}", record.data_string);

                let timestamp = "hoge";

                let hostname = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("Computer", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );

                let channel = "channel";

                let mut eventid = String::new();
                if let Some(evtid) =
                    utils::get_event_value("EventID", &record.record, eventkey_alias)
                {
                    if evtid.is_number() {
                        eventid.push_str(evtid.as_str().unwrap_or(""));
                    } else {
                        eventid.push('-');
                    };
                }

                let recordid = "recordid";
                let eventtitle = "eventtitle";
                let allfieldinfo = "allfieldinfo";
                let evtxfile = "evtxfile";

                self.search_result.entry((
                    timestamp.into(),
                    hostname,
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

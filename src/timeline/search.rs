use crate::detections::{
    configs::{EventInfoConfig, EventKeyAliasConfig},
    detection::EvtxRecordInfo,
    message::AlertMessage,
    utils,
};
use compact_str::CompactString;
use csv::WriterBuilder;
use downcast_rs::__std::process;
use hashbrown::HashSet;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::PathBuf;

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
        keywords: &Vec<String>,
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        if !search_flag {
            return;
        }

        if !keywords.is_empty() {
            self.search_keyword(records, keywords, eventkey_alias);
        }
    }

    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        keywords: &[String],
        eventkey_alias: &EventKeyAliasConfig,
    ) {
        if records.is_empty() {
            return;
        }

        for record in records.iter() {
            self.filepath = CompactString::from(records[0].evtx_filepath.as_str());
            if record
                .data_string
                .contains(keywords.get(0).unwrap_or(&String::from("SampleMessage")))
            // TODO: fix to search all keywords.
            {
                let timestamp = utils::get_event_value(
                    "Event.System.TimeCreated_attributes.SystemTime",
                    &record.record,
                    eventkey_alias,
                )
                .map(|evt_value| evt_value.to_string().replace("\\\"", "").replace('"', ""))
                .unwrap_or_else(|| "n/a".into())
                .replace(['"', '\''], "");

                let hostname = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("Computer", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        true,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], ""),
                );

                let channel = CompactString::from(
                    utils::get_serde_number_to_string(
                        utils::get_event_value("Channel", &record.record, eventkey_alias)
                            .unwrap_or(&serde_json::Value::Null),
                        true,
                    )
                    .unwrap_or_else(|| "n/a".into())
                    .replace(['"', '\''], "")
                    .to_lowercase(),
                );

                let mut eventid = String::new();
                match utils::get_event_value("EventID", &record.record, eventkey_alias) {
                    Some(evtid) if evtid.is_u64() => {
                        eventid.push_str(evtid.to_string().as_str());
                    }
                    _ => {
                        eventid.push('-');
                    }
                }

                let recordid = match utils::get_serde_number_to_string(
                    &record.record["Event"]["System"]["EventRecordID"],
                    true,
                ) {
                    Some(recid) => recid,
                    _ => CompactString::new("-"),
                };

                let allfieldinfo = match utils::get_serde_number_to_string(
                    &record.record["Event"]["EventData"],
                    true,
                ) {
                    Some(eventdata) => eventdata,
                    _ => CompactString::new("-"),
                };

                self.search_result.insert((
                    timestamp.into(),
                    hostname,
                    channel,
                    eventid.into(),
                    recordid,
                    allfieldinfo,
                    self.filepath.clone(),
                ));
                self.total += 1;
            }
        }
    }
}

pub fn search_result_dsp_msg(
    result_list: &HashSet<(
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
    )>,
    event_timeline_config: &EventInfoConfig,
    output: &Option<PathBuf>,
) {
    let header = vec![
        "Timestamp",
        "Hostname",
        "Channel",
        "Event ID",
        "Record ID",
        "EventTitle",
        "AllFieldInfo",
        "EvtxFile",
    ];
    let target: Box<dyn io::Write> = match output {
        Some(path) => {
            let file_name = path.display().to_string();
            match File::create(file_name) {
                Ok(file) => Box::new(BufWriter::new(file)),
                Err(err) => {
                    AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                    process::exit(1)
                }
            }
        }
        None => Box::new(BufWriter::new(io::stdout())),
    };
    let mut wtr = WriterBuilder::new().from_writer(target);
    // Write header
    wtr.write_record(&header).ok();

    // Write contents
    for (timestamp, hostname, channel, event_id, record_id, all_field_info, evtx_file) in
        result_list
    {
        let event_title = if event_timeline_config
            .get_event_id(channel, event_id)
            .is_some()
        {
            event_timeline_config
                .get_event_id(channel, event_id)
                .unwrap()
                .evttitle
                .as_str()
        } else {
            "-"
        };
        let record_data = vec![
            timestamp.as_str(),
            hostname.as_str(),
            channel.as_str(),
            event_id.as_str(),
            record_id.as_str(),
            event_title,
            all_field_info.as_str(),
            evtx_file.as_str(),
        ];
        wtr.write_record(&record_data).ok();
    }
}

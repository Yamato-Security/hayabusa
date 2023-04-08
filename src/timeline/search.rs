use crate::detections::{
    configs::{EventInfoConfig, EventKeyAliasConfig, StoredStatic},
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
            filepath,
            search_result,
        }
    }

    /// 検索処理を呼び出す関数。keywordsが空の場合は検索処理を行わない
    pub fn search_start(
        &mut self,
        records: &[EvtxRecordInfo],
        search_flag: bool,
        keywords: &Vec<String>,
        filters: &Vec<String>,
        eventkey_alias: &EventKeyAliasConfig,
        stored_static: &StoredStatic,
    ) {
        if !search_flag {
            return;
        }

        if !keywords.is_empty() {
            self.search_keyword(records, keywords, eventkey_alias, stored_static);
        }
    }

    /// イベントレコード内の情報からkeywordに設定した文字列を検索して、構造体に結果を保持する関数
    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        keywords: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        stored_static: &StoredStatic,
    ) {
        if records.is_empty() {
            return;
        }

        for record in records.iter() {
            self.filepath = CompactString::from(record.evtx_filepath.as_str());
            if keywords
                .iter()
                .any(|key| utils::contains_str(&record.data_string, key))
            {
                let timestamp = utils::get_event_value(
                    "Event.System.TimeCreated_attributes.SystemTime",
                    &record.record,
                    eventkey_alias,
                )
                .map(|evt_value| {
                    evt_value
                        .as_str()
                        .unwrap_or_default()
                        .replace("\\\"", "")
                        .replace('"', "")
                })
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

                let ch_str = &utils::get_serde_number_to_string(
                    &record.record["Event"]["System"]["Channel"],
                    false,
                )
                .unwrap_or_default();
                let channel = stored_static
                    .disp_abbr_generic
                    .replace_all(
                        stored_static
                            .ch_config
                            .get(&CompactString::from(ch_str.to_ascii_lowercase()))
                            .unwrap_or(ch_str)
                            .as_str(),
                        &stored_static.disp_abbr_general_values,
                    )
                    .into();
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
            }
        }
    }
}

/// 検索結果を標準出力もしくはcsvファイルに出力する関数
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
        Some(path) => match File::create(path) {
            Ok(file) => Box::new(BufWriter::new(file)),
            Err(err) => {
                AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                process::exit(1)
            }
        },
        None => Box::new(BufWriter::new(io::stdout())),
    };
    let mut wtr = if output.is_none() {
        Some(WriterBuilder::new().from_writer(target))
    } else {
        Some(WriterBuilder::new().delimiter(b',').from_writer(target))
    };

    // Write header
    if output.is_some() {
        wtr.as_mut().unwrap().write_record(&header).ok();
    } else if output.is_none() && !result_list.is_empty() {
        wtr.as_mut().unwrap().write_field(header.join(" ‖ ")).ok();
    }

    // Write contents
    for (timestamp, hostname, channel, event_id, record_id, all_field_info, evtx_file) in
        result_list
    {
        let event_title =
            if let Some(event_info) = event_timeline_config.get_event_id(channel, event_id) {
                event_info.evttitle.as_str()
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
        if wtr.as_ref().is_some() {
            wtr.as_mut().unwrap().write_record(&record_data).ok();
        } else {
            wtr.as_mut()
                .unwrap()
                .write_field(record_data.join(" ‖ "))
                .ok();
        }
    }
}

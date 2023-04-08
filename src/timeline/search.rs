use crate::detections::{
    configs::{EventInfoConfig, EventKeyAliasConfig, StoredStatic},
    detection::EvtxRecordInfo,
    message::AlertMessage,
    utils::{self, write_color_buffer},
};
use compact_str::CompactString;
use csv::WriterBuilder;
use downcast_rs::__std::process;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use nested::Nested;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use termcolor::{BufferWriter, ColorChoice};

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
        keywords: &[String],
        filters: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        stored_static: &StoredStatic,
    ) {
        if !search_flag {
            return;
        }

        if !keywords.is_empty() {
            self.search_keyword(records, keywords, filters, eventkey_alias, stored_static);
        }
    }

    /// イベントレコード内の情報からfilterに設定した情報が存在するかを返す関数
    fn filter_record(
        &mut self,
        record: &EvtxRecordInfo,
        filter_rule: &HashMap<String, Nested<String>>,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> bool {
        filter_rule.iter().all(|(k, v)| {
            let alias_target_val = utils::get_serde_number_to_string(
                utils::get_event_value(k, &record.record, eventkey_alias)
                    .unwrap_or(&serde_json::Value::Null),
                true,
            )
            .unwrap_or_else(|| "n/a".into())
            .replace(['"', '\''], "");

            // aliasでマッチした場合はaliasに登録されていないフィールドを検索する必要がないためtrueを返す
            if v.iter()
                .all(|search_target| utils::contains_str(&alias_target_val, search_target))
            {
                return true;
            }

            // aliasに登録されていないフィールドも検索対象とするため
            let allfieldinfo = match utils::get_serde_number_to_string(
                &record.record["Event"]["EventData"][k],
                true,
            ) {
                Some(eventdata) => eventdata,
                _ => CompactString::new("-"),
            };
            v.iter()
                .all(|search_target| utils::contains_str(&allfieldinfo, search_target))
        })
    }

    /// イベントレコード内の情報からkeywordに設定した文字列を検索して、構造体に結果を保持する関数
    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        keywords: &[String],
        filters: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        stored_static: &StoredStatic,
    ) {
        if records.is_empty() {
            return;
        }

        let filter_rule = filters
            .iter()
            .fold(HashMap::new(), |mut acc, filter_condition| {
                let prefix_trim_condition = filter_condition
                    .strip_prefix('"')
                    .unwrap_or(filter_condition);
                let trimed_condition = prefix_trim_condition
                    .strip_suffix('"')
                    .unwrap_or(prefix_trim_condition);
                let condition = trimed_condition.split(':').map(|x| x.trim()).collect_vec();
                if condition.len() != 1 {
                    let acc_val = acc
                        .entry(condition[0].to_string())
                        .or_insert(Nested::<String>::new());
                    acc_val.push(condition[1..].join(":"));
                }
                acc
            });

        for record in records.iter() {
            // フィルタリングを通過しなければ検索は行わず次のレコードを読み込む
            if !self.filter_record(record, &filter_rule, eventkey_alias) {
                continue;
            }
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
    let mut disp_wtr = None;
    let mut file_wtr = None;
    if let Some(path) = output {
        match File::create(path) {
            Ok(file) => {
                file_wtr = Some(
                    WriterBuilder::new()
                        .delimiter(b',')
                        .from_writer(BufWriter::new(file)),
                )
            }
            Err(err) => {
                AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                process::exit(1)
            }
        }
    };
    if file_wtr.is_none() {
        disp_wtr = Some(BufferWriter::stdout(ColorChoice::Always));
    }

    // Write header
    if output.is_some() {
        file_wtr.as_mut().unwrap().write_record(&header).ok();
    } else if output.is_none() && !result_list.is_empty() {
        write_color_buffer(disp_wtr.as_mut().unwrap(), None, &header.join(" ‖ "), true).ok();
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
        if output.is_some() {
            file_wtr.as_mut().unwrap().write_record(&record_data).ok();
        } else {
            write_color_buffer(
                disp_wtr.as_mut().unwrap(),
                None,
                &record_data.join(" ‖ "),
                true,
            )
            .ok();
        }
    }
}

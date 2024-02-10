use crate::detections::configs::{OutputOption, ALLFIELDINFO_SPECIAL_CHARS};
use crate::detections::field_data_map::FieldDataMapKey;
use crate::detections::message;
use crate::detections::utils::format_time;
use crate::{
    afterfact::output_json_str,
    detections::{
        configs::{Action, EventInfoConfig, EventKeyAliasConfig, StoredStatic},
        detection::EvtxRecordInfo,
        message::AlertMessage,
        utils::{self, write_color_buffer},
    },
    options::profile::Profile,
};
use chrono::{TimeZone, Utc};
use compact_str::CompactString;
use csv::{QuoteStyle, WriterBuilder};
use downcast_rs::__std::process;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use regex::Regex;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use termcolor::{BufferWriter, Color, ColorChoice};
use wildmatch::WildMatch;

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
        keywords: &[String],
        regex: &Option<String>,
        filters: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        stored_static: &StoredStatic,
    ) {
        if !keywords.is_empty() {
            // 大文字小文字を区別しないかどうか、and検索を行うかのフラグを設定
            let (case_insensitive_flag, and_logic_flag) = match &stored_static.config.action {
                Some(Action::Search(opt)) => (opt.ignore_case, opt.and_logic),
                _ => (false, false),
            };
            self.search_keyword(
                records,
                keywords,
                filters,
                eventkey_alias,
                stored_static.output_option.as_ref().unwrap(),
                (case_insensitive_flag, and_logic_flag),
            );
        }
        if let Some(re) = regex {
            self.search_regex(
                records,
                re,
                filters,
                eventkey_alias,
                stored_static.output_option.as_ref().unwrap(),
            );
        }
    }

    /// イベントレコード内の情報からfilterに設定した情報が存在するかを返す関数
    fn filter_record(
        &mut self,
        record: &EvtxRecordInfo,
        filter_rule: &HashMap<String, Vec<WildMatch>>,
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
                .all(|search_target| search_target.matches(&alias_target_val))
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
                .all(|search_target| search_target.matches(&allfieldinfo))
        })
    }

    /// イベントレコード内の情報からkeywordに設定した文字列を検索して、構造体に結果を保持する関数
    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        keywords: &[String],
        filters: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        output_option: &OutputOption,
        (case_insensitive_flag, and_logic_flag): (bool, bool), // 検索時に大文字小文字を区別するかどうか, 検索時にAND条件で検索するかどうか
    ) {
        if records.is_empty() {
            return;
        }

        let filter_rule = create_filter_rule(filters);

        for record in records.iter() {
            // フィルタリングを通過しなければ検索は行わず次のレコードを読み込む
            if !self.filter_record(record, &filter_rule, eventkey_alias) {
                continue;
            }
            let search_target = if case_insensitive_flag {
                record.data_string.to_lowercase()
            } else {
                record.data_string.clone()
            };
            self.filepath = CompactString::from(record.evtx_filepath.as_str());
            let search_condition = |keywords: &[String]| -> bool {
                if and_logic_flag {
                    keywords.iter().all(|key| {
                        let converted_key = if case_insensitive_flag {
                            key.to_lowercase()
                        } else {
                            key.clone()
                        };
                        utils::contains_str(&search_target, &converted_key)
                    })
                } else {
                    keywords.iter().any(|key| {
                        let converted_key = if case_insensitive_flag {
                            key.to_lowercase()
                        } else {
                            key.clone()
                        };
                        utils::contains_str(&search_target, &converted_key)
                    })
                }
            };
            if search_condition(keywords) {
                let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                    extract_search_event_info(record, eventkey_alias, output_option);
                let allfieldinfo_newline_splited = ALLFIELDINFO_SPECIAL_CHARS
                    .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                    .split('🦅')
                    .filter(|x| !x.is_empty())
                    .join(" ");
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    allfieldinfo_newline_splited.into(),
                    self.filepath.clone(),
                ));
            }
        }
    }

    /// イベントレコード内の情報からregexに設定した正規表現を検索して、構造体に結果を保持する関数
    fn search_regex(
        &mut self,
        records: &[EvtxRecordInfo],
        regex: &str,
        filters: &[String],
        eventkey_alias: &EventKeyAliasConfig,
        output_option: &OutputOption,
    ) {
        let re = Regex::new(regex).unwrap_or_else(|err| {
            AlertMessage::alert(&format!("Failed to create regex pattern. \n{err}")).ok();
            process::exit(1);
        });
        if records.is_empty() {
            return;
        }

        let filter_rule = create_filter_rule(filters);

        for record in records.iter() {
            // フィルタリングを通過しなければ検索は行わず次のレコードを読み込む
            if !self.filter_record(record, &filter_rule, eventkey_alias) {
                continue;
            }
            self.filepath = CompactString::from(record.evtx_filepath.as_str());
            if re.is_match(&record.data_string) {
                let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                    extract_search_event_info(record, eventkey_alias, output_option);
                let allfieldinfo_newline_splited = ALLFIELDINFO_SPECIAL_CHARS
                    .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                    .split('🦅')
                    .filter(|x| !x.is_empty())
                    .join(" ");
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    allfieldinfo_newline_splited.into(),
                    self.filepath.clone(),
                ));
            }
        }
    }
}

/// filters からフィルタリング条件を作成する関数
fn create_filter_rule(filters: &[String]) -> HashMap<String, Vec<WildMatch>> {
    filters
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
                let acc_val = acc.entry(condition[0].to_string()).or_insert(vec![]);
                condition[1..]
                    .iter()
                    .for_each(|x| acc_val.push(WildMatch::new(x)));
            }
            acc
        })
}

/// 検索条件に合致したイベントレコードから出力する情報を抽出する関数
fn extract_search_event_info(
    record: &EvtxRecordInfo,
    eventkey_alias: &EventKeyAliasConfig,
    output_option: &OutputOption,
) -> (
    CompactString,
    CompactString,
    CompactString,
    CompactString,
    CompactString,
    CompactString,
) {
    let default_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
    let timestamp_datetime = message::get_event_time(&record.record, false).unwrap_or(default_time);

    let timestamp = format_time(&timestamp_datetime, false, output_option);

    let hostname = CompactString::from(
        utils::get_serde_number_to_string(
            utils::get_event_value("Computer", &record.record, eventkey_alias)
                .unwrap_or(&serde_json::Value::Null),
            true,
        )
        .unwrap_or_else(|| "n/a".into())
        .replace(['"', '\''], ""),
    );

    let channel =
        utils::get_serde_number_to_string(&record.record["Event"]["System"]["Channel"], false)
            .unwrap_or_default();
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

    let datainfo = utils::create_recordinfos(&record.record, &FieldDataMapKey::default(), &None);
    let allfieldinfo = if !datainfo.is_empty() {
        datainfo.join(" ¦ ").into()
    } else {
        CompactString::new("-")
    };

    (
        timestamp,
        hostname,
        channel,
        eventid.into(),
        recordid,
        allfieldinfo,
    )
}

/// 検索結果を標準出力もしくはcsvファイルに出力する関数
pub fn search_result_dsp_msg(
    result_list: HashSet<(
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
    stored_static: &StoredStatic,
    (json_output, jsonl_output): (bool, bool),
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
                if json_output || jsonl_output {
                    file_wtr = Some(
                        WriterBuilder::new()
                            .delimiter(b'\n')
                            .double_quote(false)
                            .quote_style(QuoteStyle::Never)
                            .from_writer(BufWriter::new(file)),
                    )
                } else {
                    file_wtr = Some(
                        WriterBuilder::new()
                            .delimiter(b',')
                            .quote_style(QuoteStyle::NonNumeric)
                            .from_writer(BufWriter::new(file)),
                    )
                }
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
    if output.is_some() && !json_output && !jsonl_output {
        file_wtr.as_mut().unwrap().write_record(&header).ok();
    } else if output.is_none() && !result_list.is_empty() {
        write_color_buffer(disp_wtr.as_mut().unwrap(), None, &header.join(" · "), true).ok();
    }

    // Write contents
    for (timestamp, hostname, channel, event_id, record_id, all_field_info, evtx_file) in
        result_list
            .into_iter()
            .sorted_unstable_by(|a, b| Ord::cmp(&a.0, &b.0))
    {
        let event_title = if let Some(event_info) =
            event_timeline_config.get_event_id(&channel.to_ascii_lowercase(), &event_id)
        {
            CompactString::from(event_info.evttitle.as_str())
        } else {
            "-".into()
        };
        let abbr_channel = stored_static.disp_abbr_generic.replace_all(
            stored_static
                .ch_config
                .get(&CompactString::from(channel.to_ascii_lowercase()))
                .unwrap_or(&channel)
                .as_str(),
            &stored_static.disp_abbr_general_values,
        );
        let get_char_color = |output_char_color: Option<Color>| {
            if stored_static.common_options.no_color {
                None
            } else {
                output_char_color
            }
        };

        let fmted_all_field_info = all_field_info.split_whitespace().join(" ");
        let all_field_info = if output.is_some() && stored_static.multiline_flag {
            fmted_all_field_info.replace(" ¦ ", "\r\n")
        } else {
            fmted_all_field_info
        };
        let record_data = vec![
            timestamp.as_str(),
            hostname.as_str(),
            abbr_channel.as_str(),
            event_id.as_str(),
            record_id.as_str(),
            event_title.as_str(),
            all_field_info.as_str(),
            evtx_file.as_str(),
        ];
        if output.is_some() && !json_output && !jsonl_output {
            file_wtr.as_mut().unwrap().write_record(&record_data).ok();
        } else if output.is_some() && (json_output || jsonl_output) {
            file_wtr.as_mut().unwrap().write_field("{").ok();
            let mut detail_infos: HashMap<CompactString, Vec<CompactString>> = HashMap::default();
            detail_infos.insert(
                CompactString::from("#AllFieldInfo"),
                all_field_info
                    .split('¦')
                    .map(CompactString::from)
                    .collect_vec(),
            );
            let (output_json_str_ret, _) = output_json_str(
                &vec![
                    (
                        "Timestamp".into(),
                        Profile::Timestamp(timestamp.clone().into()),
                    ),
                    (
                        "Hostname".into(),
                        Profile::Computer(hostname.clone().into()),
                    ),
                    (
                        "Channel".into(),
                        Profile::Channel(abbr_channel.clone().into()),
                    ),
                    ("Event ID".into(), Profile::EventID(event_id.clone().into())),
                    (
                        "Record ID".into(),
                        Profile::RecordID(record_id.clone().into()),
                    ),
                    (
                        "EventTitle".into(),
                        Profile::Literal(event_title.clone().into()),
                    ),
                    (
                        "AllFieldInfo".into(),
                        Profile::AllFieldInfo(all_field_info.into()),
                    ),
                    ("EvtxFile".into(), Profile::EvtxFile(evtx_file.into())),
                ],
                HashMap::new(),
                jsonl_output,
                false,
                false,
                false,
                &[&detail_infos, &HashMap::default()],
            );

            file_wtr
                .as_mut()
                .unwrap()
                .write_field(output_json_str_ret)
                .ok();
            file_wtr.as_mut().unwrap().write_field("}").ok();
        } else {
            for (record_field_idx, record_field_data) in record_data.iter().enumerate() {
                let newline_flag = record_field_idx == record_data.len() - 1;
                if record_field_idx == 6 {
                    //AllFieldInfoの列の出力
                    let all_field_sep_info = all_field_info.split('¦').collect::<Vec<&str>>();
                    for (field_idx, fields) in all_field_sep_info.iter().enumerate() {
                        let mut separated_fields_data =
                            fields.split(':').map(|x| x.split_whitespace().join(" "));
                        write_color_buffer(
                            disp_wtr.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(255, 158, 61))),
                            &format!("{}: ", separated_fields_data.next().unwrap()),
                            newline_flag,
                        )
                        .ok();
                        write_color_buffer(
                            disp_wtr.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(0, 255, 255))),
                            separated_fields_data.join(":").trim(),
                            newline_flag,
                        )
                        .ok();
                        if field_idx != all_field_sep_info.len() - 1 {
                            write_color_buffer(
                                disp_wtr.as_mut().unwrap(),
                                None,
                                " ¦ ",
                                newline_flag,
                            )
                            .ok();
                        }
                    }
                } else if record_field_idx == 0 || record_field_idx == 5 {
                    //タイムスタンプとイベントタイトルは同じ色で表示
                    write_color_buffer(
                        disp_wtr.as_mut().unwrap(),
                        get_char_color(Some(Color::Rgb(0, 255, 0))),
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                } else {
                    write_color_buffer(
                        disp_wtr.as_mut().unwrap(),
                        None,
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                }

                if !newline_flag {
                    write_color_buffer(
                        disp_wtr.as_mut().unwrap(),
                        get_char_color(Some(Color::Rgb(238, 102, 97))),
                        " · ",
                        false,
                    )
                    .ok();
                }
            }
        }
    }
}

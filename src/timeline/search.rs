use crate::afterfact::AfterfactInfo;
use crate::detections::configs::{ALLFIELDINFO_SPECIAL_CHARS, OutputOption, SearchOption};
use crate::detections::field_data_map::FieldDataMapKey;
use crate::detections::message::{self, DetectInfo};
use crate::detections::utils::{format_time, get_writable_color};
use crate::{
    afterfact::output_json_str,
    detections::{
        configs::{Action, EventKeyAliasConfig, StoredStatic},
        detection::EvtxRecordInfo,
        message::AlertMessage,
        utils::{self, write_color_buffer},
    },
    options::profile::Profile,
};
use chrono::{TimeZone, Utc};
use compact_str::CompactString;
use csv::{QuoteStyle, Writer, WriterBuilder};
use downcast_rs::__std::process;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use num_format::{Locale, ToFormattedString};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use termcolor::{BufferWriter, Color, ColorChoice};
use wildmatch::WildMatch;
use rayon::prelude::*;

const OUTPUT_HEADERS: [&str; 8] = [
    "Timestamp",
    "EventTitle",
    "Hostname",
    "Channel",
    "Event ID",
    "Record ID",
    "AllFieldInfo",
    "EvtxFile",
];

/// イベントレコード内の情報からfilterに設定した情報が存在するかを返す関数
pub fn filter_record(
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
    pub search_result_cnt: u64,
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
            search_result_cnt: 0,
        }
    }

    /// 検索処理を呼び出す関数。keywordsが空の場合は検索処理を行わない
    pub fn search_start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        let search_option = stored_static.search_option.as_ref().unwrap();
        let default_details_abbr = self.get_default_details_mapping_table(stored_static);
        if search_option
            .keywords
            .as_ref()
            .is_some_and(|keywords| !keywords.is_empty())
        {
            self.search_keyword(
                records,
                search_option,
                stored_static,
                default_details_abbr.clone(),
            );
        }
        if search_option.regex.is_some() {
            self.search_regex(records, search_option, stored_static, default_details_abbr);
        }
    }

    fn get_default_details_mapping_table(
        &self,
        stored_static: &StoredStatic,
    ) -> HashMap<CompactString, HashMap<CompactString, CompactString>> {
        let mut ret: HashMap<CompactString, HashMap<CompactString, CompactString>> = HashMap::new();
        let mut default_details_abbr: HashMap<CompactString, CompactString> = HashMap::new();
        for (k, v) in stored_static.default_details.iter() {
            v.split(" ¦ ").for_each(|x| {
                let abbr_k_v = x.split(": ").collect_vec();
                if abbr_k_v.len() == 2 {
                    let abbr: CompactString = abbr_k_v[0].into();
                    let full: CompactString = abbr_k_v[1].replace("%", "").trim().into();
                    default_details_abbr.insert(full, abbr);
                }
            });
            ret.insert(k.clone(), default_details_abbr.clone());
            default_details_abbr.clear();
        }
        ret
    }

    // check if a record contains the keywords specified in a search command option or not.
    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        search_option: &SearchOption,
        stored_static: &StoredStatic,
        allfield_replace_table: HashMap<CompactString, HashMap<CompactString, CompactString>>,
    ) {
        if !records.is_empty() {
            return;
        }
        if search_option.keywords.is_none() {
            return;
        }
        let keywords = search_option.keywords.as_ref().unwrap();
        if keywords.is_empty() {
            return;
        }

        // create filter rule
        let filter_rule = create_filter_rule(&search_option.filter);
        let mut wtr = ResultWriter::new(search_option);
        let (case_insensitive_flag, and_logic_flag) = match &stored_static.config.action {
            Some(Action::Search(opt)) => (opt.ignore_case, opt.and_logic),
            _ => (false, false),
        };

        // logic for detecting records containing keywords.
        let contain_keywords = |search_target: &String| -> bool {
            if and_logic_flag {
                keywords.iter().all(|key| {
                    let converted_key = if case_insensitive_flag {
                        key.to_lowercase()
                    } else {
                        key.to_string()
                    };
                    utils::contains_str(&search_target, &converted_key)
                })
            } else {
                keywords.iter().any(|key| {
                    let converted_key = if case_insensitive_flag {
                        key.to_lowercase()
                    } else {
                        key.to_string()
                    };
                    utils::contains_str(&search_target, &converted_key)
                })
            }
        };

        // execute keyword search logic in parallel using rayon.
        let hit_records: Vec<&EvtxRecordInfo> = records.par_iter()
            .filter(|record| filter_record(record, &filter_rule, &stored_static.eventkey_alias))
            .filter(|record| {
                return if case_insensitive_flag {
                    contain_keywords(&record.data_string.to_lowercase())
                } else {
                    contain_keywords(&record.data_string)
                }
            })
            .map(|record| {
                return record;
            } )
            .collect();
        if hit_records.is_empty() {
            return;
        }

        // collect hit records and transform them for later use
        self.filepath = CompactString::from(hit_records.first().unwrap().evtx_filepath.as_str());
        for hit_record in hit_records {
            let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                extract_search_event_info(
                    hit_record,
                    &stored_static.eventkey_alias,
                    stored_static.output_option.as_ref().unwrap(),
                );

            let provider_attributes_name = hit_record.record["Event"]["System"]["Provider_attributes"]["Name"]                            .to_string()
                .to_string()
                .replace('\"', "");
            let table_key = format!(
                "{}_{}",
                provider_attributes_name,
                eventid
            );
            let target_all_field_info_abbr_table = allfield_replace_table.get(table_key.as_str());

            let all_field_info_key = ALLFIELDINFO_SPECIAL_CHARS
                .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                .split('🦅')
                .filter(|x| !x.is_empty())
                .join(" ");
            let all_field_info_newline_split = self.replace_all_field_info_abbr(
                all_field_info_key.as_str(),
                target_all_field_info_abbr_table,
            );

            if search_option.sort_events {
                // we cannot sort all the records unless we get all the records; so we just collect the hit record at this code and we'll sort them later.
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    all_field_info_newline_split,
                    self.filepath.clone(),
                ));
                self.search_result_cnt += 1;
            } else {
                // sort_events option is false, the hit record is output on the fly.
                // We don't want to collect the hit record into the memory, if possible, in order to reduce memory usage.
                let record_for_stdout = (
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    all_field_info_newline_split,
                    self.filepath.clone(),
                );
                wtr.write_record(
                    record_for_stdout,
                    search_option,
                    stored_static,
                    self.search_result_cnt == 0,
                );
                self.search_result_cnt += 1;
            }
        }
    }

    // check if a record matches the regex specified in a search command option or not.
    fn search_regex(
        &mut self,
        records: &[EvtxRecordInfo],
        search_option: &SearchOption,
        stored_static: &StoredStatic,
        allfield_replace_table: HashMap<CompactString, HashMap<CompactString, CompactString>>,
    ) {
        let re = Regex::new(search_option.regex.as_ref().unwrap()).unwrap_or_else(|err| {
            AlertMessage::alert(&format!("Failed to create regex pattern. \n{err}")).ok();
            process::exit(1);
        });
        if records.is_empty() {
            return;
        }

        let filter_rule = create_filter_rule(&search_option.filter);
        let mut wtr = ResultWriter::new(search_option);
        for record in records.iter() {
            // we will skip this record if the record is filterd.
            if !filter_record(record, &filter_rule, &stored_static.eventkey_alias) {
                continue;
            }

            // check if the regex matches the record or not.
            self.filepath = CompactString::from(record.evtx_filepath.as_str());
            if !re.is_match(&record.data_string) {
                continue;
            }

            // collect the hit record or output it on the fly
            let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                extract_search_event_info(
                    record,
                    &stored_static.eventkey_alias,
                    stored_static.output_option.as_ref().unwrap(),
                );
            let target_allfieldinfo_abbr_table = allfield_replace_table.get(
                format!(
                    "{}_{}",
                    record.record["Event"]["System"]["Provider_attributes"]["Name"]
                        .to_string()
                        .replace('\"', ""),
                    eventid
                )
                .as_str(),
            );
            let allfieldinfo_newline_split = self.replace_all_field_info_abbr(
                ALLFIELDINFO_SPECIAL_CHARS
                    .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                    .split('🦅')
                    .filter(|x| !x.is_empty())
                    .join(" ")
                    .as_str(),
                target_allfieldinfo_abbr_table,
            );

            if search_option.sort_events {
                // we cannot sort all the records unless we get all the records; so we just collect the hit record at this code and we'll sort them later.
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    allfieldinfo_newline_split,
                    self.filepath.clone(),
                ));
                self.search_result_cnt += 1;
            } else {
                // sort_events option is false, the hit record is output on the fly.
                // We don't want to collect the hit record into the memory, if possible, in order to reduce memory usage.
                let hit_record = (
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    allfieldinfo_newline_split,
                    self.filepath.clone(),
                );
                wtr.write_record(
                    hit_record,
                    search_option,
                    stored_static,
                    self.search_result_cnt == 0,
                );
                self.search_result_cnt += 1;
            }
        }
    }

    /// Replace all the field info abbreviations in the given value with their full names.
    fn replace_all_field_info_abbr(
        &self,
        value: &str,
        all_field_info_abbr: Option<&HashMap<CompactString, CompactString>>,
    ) -> CompactString {
        let mut pairs = if let Some(s) = all_field_info_abbr {
            s.iter().collect::<Vec<_>>()
        } else {
            vec![]
        };
        if pairs.is_empty() {
            return value.into();
        }
        pairs.sort_unstable_by(|a, b| a.0.len().cmp(&b.0.len()));
        let mut all_field_info = value.to_string();
        for (k, v) in pairs {
            all_field_info = all_field_info.replace(k.as_str(), v.as_str());
        }
        all_field_info.into()
    }
}

pub struct ResultWriter {
    pub disp_wtr: Option<BufferWriter>,
    pub file_wtr: Option<Writer<BufWriter<File>>>,
    written_record_num: u64,
}

impl ResultWriter {
    pub fn new(search_option: &SearchOption) -> ResultWriter {
        let mut file_wtr = Option::None;
        if let Some(path) = &search_option.output {
            // create new file if not exist and append if exist.
            match OpenOptions::new().append(true).create(true).open(path) {
                Ok(file) => {
                    if search_option.json_output || search_option.jsonl_output {
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

        let disp_wtr = if file_wtr.is_none() {
            Some(BufferWriter::stdout(ColorChoice::Always))
        } else {
            Option::None
        };

        ResultWriter {
            disp_wtr,
            file_wtr,
            written_record_num: 0,
        }
    }

    fn write_headder(&mut self, search_option: &SearchOption) {
        if search_option.output.is_some()
            && !search_option.json_output
            && !search_option.jsonl_output
        {
            self.file_wtr
                .as_mut()
                .unwrap()
                .write_record(OUTPUT_HEADERS)
                .ok();
        } else if search_option.output.is_none() {
            // TODO hach1yon add logic, **result.isEmpty()**
            write_color_buffer(
                self.disp_wtr.as_mut().unwrap(),
                None,
                &OUTPUT_HEADERS.join(" · "),
                true,
            )
            .ok();
        }
    }

    pub fn write_record(
        &mut self,
        (timestamp, hostname, channel, event_id, record_id, all_field_info, evtx_file): (
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
            CompactString,
        ),
        search_option: &SearchOption,
        stored_static: &StoredStatic,
        is_write_header: bool,
    ) {
        if is_write_header {
            self.write_headder(search_option);
        }
        self.written_record_num += 1;

        let event_title = if let Some(event_info) = stored_static
            .event_timeline_config
            .get_event_id(&channel.to_ascii_lowercase(), &event_id)
        {
            CompactString::from(event_info.evttitle.as_str())
        } else {
            "-".into()
        };
        let abbr_channel = stored_static.disp_abbr_generic.replace_all(
            stored_static
                .ch_config
                .get(&channel.to_ascii_lowercase())
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
        let all_field_info = if search_option.output.is_some() && stored_static.multiline_flag {
            fmted_all_field_info.replace(" ¦ ", "\r\n")
        } else if stored_static.tab_separator_flag {
            fmted_all_field_info.replace(" ¦ ", "\t")
        } else {
            fmted_all_field_info
        };
        let record_data = vec![
            timestamp.as_str(),
            event_title.as_str(),
            hostname.as_str(),
            abbr_channel.as_str(),
            event_id.as_str(),
            record_id.as_str(),
            all_field_info.as_str(),
            evtx_file.as_str(),
        ];
        if search_option.output.is_some()
            && !search_option.json_output
            && !search_option.jsonl_output
        {
            self.file_wtr
                .as_mut()
                .unwrap()
                .write_record(&record_data)
                .ok();
        } else if search_option.output.is_some()
            && (search_option.json_output || search_option.jsonl_output)
        {
            let file_wtr = self.file_wtr.as_mut().unwrap();
            file_wtr.write_field("{").ok();
            let mut detail_infos: HashMap<CompactString, Vec<CompactString>> = HashMap::default();
            detail_infos.insert(
                CompactString::from("#AllFieldInfo"),
                all_field_info
                    .split('¦')
                    .map(CompactString::from)
                    .collect_vec(),
            );
            let mut detect_info = DetectInfo::default();
            detect_info.ext_field.push((
                CompactString::from("Timestamp"),
                Profile::Timestamp(timestamp.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("Hostname"),
                Profile::Computer(hostname.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("Channel"),
                Profile::Channel(abbr_channel.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("Event ID"),
                Profile::EventID(event_id.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("Record ID"),
                Profile::RecordID(record_id.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("EventTitle"),
                Profile::Literal(event_title.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("AllFieldInfo"),
                Profile::AllFieldInfo(all_field_info.into()),
            ));
            detect_info.ext_field.push((
                CompactString::from("EvtxFile"),
                Profile::EvtxFile(evtx_file.into()),
            ));
            detect_info.details_convert_map = detail_infos;
            let mut afterfact_info = AfterfactInfo::default();
            let (output_json_str_ret, _) = output_json_str(
                &detect_info,
                &mut afterfact_info,
                search_option.jsonl_output,
                false,
                false,
            );

            file_wtr.write_field(output_json_str_ret).ok();
            self.file_wtr.as_mut().unwrap().write_field("}").ok();
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
                            self.disp_wtr.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(255, 158, 61))),
                            &format!("{}: ", separated_fields_data.next().unwrap()),
                            newline_flag,
                        )
                        .ok();
                        write_color_buffer(
                            self.disp_wtr.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(0, 255, 255))),
                            separated_fields_data.join(":").trim(),
                            newline_flag,
                        )
                        .ok();
                        if field_idx != all_field_sep_info.len() - 1 {
                            write_color_buffer(
                                self.disp_wtr.as_mut().unwrap(),
                                None,
                                " ¦ ",
                                newline_flag,
                            )
                            .ok();
                        }
                    }
                } else if record_field_idx == 0 || record_field_idx == 1 {
                    //タイムスタンプとイベントタイトルは同じ色で表示
                    write_color_buffer(
                        self.disp_wtr.as_mut().unwrap(),
                        get_char_color(Some(Color::Rgb(0, 255, 0))),
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                } else {
                    write_color_buffer(
                        self.disp_wtr.as_mut().unwrap(),
                        None,
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                }

                if !newline_flag {
                    write_color_buffer(
                        self.disp_wtr.as_mut().unwrap(),
                        get_char_color(Some(Color::Rgb(238, 102, 97))),
                        " · ",
                        false,
                    )
                    .ok();
                }
            }
        }
        if search_option.output.is_none() {
            println!();
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

    let timestamp = format_time(
        &timestamp_datetime,
        false,
        &output_option.time_format_options,
    );

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
    event_search: &EventSearch,
    search_option: &SearchOption,
    stored_static: &StoredStatic,
) {
    let mut wtr = ResultWriter::new(search_option);
    if search_option.sort_events {
        let hit_records = event_search
            .search_result
            .clone()
            .into_iter()
            .sorted_unstable_by(|a, b| {
                Ord::cmp(&a.0, &b.0)
                    .then_with(|| Ord::cmp(&a.4, &b.4))
                    .then_with(|| Ord::cmp(&a.6, &b.6))
            });
        let mut is_firstline = true;
        for (timestamp, hostname, channel, event_id, record_id, all_field_info, evtx_file) in
            hit_records
        {
            wtr.write_record(
                (
                    timestamp,
                    hostname,
                    channel,
                    event_id,
                    record_id,
                    all_field_info,
                    evtx_file,
                ),
                search_option,
                stored_static,
                is_firstline,
            );
            is_firstline = false;
        }
    }

    // if sort_events option is false, search results should have been already output.
    if event_search.search_result_cnt == 0 {
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            Some(Color::Rgb(238, 102, 97)),
            "\nNo matches found.\n",
            true,
        )
        .ok();
    }
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        get_writable_color(
            Some(Color::Rgb(0, 255, 0)),
            stored_static.common_options.no_color,
        ),
        "Total findings: ",
        false,
    )
    .ok();
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        None,
        event_search
            .search_result_cnt
            .to_formatted_string(&Locale::en)
            .as_str(),
        true,
    )
    .ok();
}

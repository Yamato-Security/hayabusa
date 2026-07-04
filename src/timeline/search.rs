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

// Column headers for the search output (CSV header row / terminal column names).
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

/// Runs the `search` command: checks event records against the given keywords or regex and either
/// collects the hits for sorted output or writes them out on the fly.
#[derive(Debug, Clone)]
pub struct EventSearch {
    // Path of the evtx file that the record currently being processed came from.
    pub filepath: CompactString,
    // Hit records collected for later sorting when the sort_events option is set. Tuple layout:
    // (timestamp, hostname, channel, event ID, record ID, all field info, evtx file path).
    pub search_result: HashSet<(
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
        CompactString,
    )>,
    // Total number of hits, counted even when records are written on the fly instead of collected.
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

    /// Entry point of the search process. Runs the keyword search when keywords were given and
    /// the regex search when a regex was given; otherwise does nothing.
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

    /// Returns whether the event record satisfies every filter condition. For each filtered
    /// field, all of its wildcard patterns must match the field value, which is resolved through
    /// the event key aliases first and the raw EventData fields second.
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
            // If matched by alias, there is no need to search fields not registered in the alias, so return true.
            if v.iter()
                .all(|search_target| search_target.matches(&alias_target_val))
            {
                return true;
            }

            // Also search fields not registered in the alias.
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

    /// Builds a per-"Provider_EventID" table that maps full field names to their abbreviations
    /// (e.g. "CommandLine" -> "Cmdline"), parsed from the default_details.txt templates of the
    /// form "Cmdline: %CommandLine% ¦ Proc: %Image% ...". Used to shorten the AllFieldInfo output.
    fn get_default_details_mapping_table(
        &self,
        stored_static: &StoredStatic,
    ) -> HashMap<CompactString, HashMap<CompactString, CompactString>> {
        let mut ret: HashMap<CompactString, HashMap<CompactString, CompactString>> = HashMap::new();
        let mut default_details_abbr: HashMap<CompactString, CompactString> = HashMap::new();
        for (k, v) in stored_static.default_details.iter() {
            v.split(" ¦ ").for_each(|x| {
                let abbr_and_full = x.split(": ").collect_vec();
                if abbr_and_full.len() == 2 {
                    let abbr: CompactString = abbr_and_full[0].into();
                    let full: CompactString = abbr_and_full[1].replace("%", "").trim().into();
                    default_details_abbr.insert(full, abbr);
                }
            });
            ret.insert(k.clone(), default_details_abbr.clone());
            default_details_abbr.clear();
        }
        ret
    }

    /// Checks each record against the keywords given in the search command options and collects
    /// or outputs the matching records.
    fn search_keyword(
        &mut self,
        records: &[EvtxRecordInfo],
        search_option: &SearchOption,
        stored_static: &StoredStatic,
        allfield_replace_table: HashMap<CompactString, HashMap<CompactString, CompactString>>,
    ) {
        if records.is_empty() {
            return;
        }
        if search_option.keywords.is_none() {
            return;
        }
        let keywords = search_option.keywords.as_ref().unwrap();
        if keywords.is_empty() {
            return;
        }

        let filter_rule = create_filter_rule(&search_option.filter);
        let mut wtr = ResultWriter::new(search_option);
        let (case_insensitive_flag, and_logic_flag) = match &stored_static.config.action {
            Some(Action::Search(opt)) => (opt.ignore_case, opt.and_logic),
            _ => (false, false),
        };

        for record in records.iter() {
            // Skip records that do not satisfy the filter conditions.
            if !self.filter_record(record, &filter_rule, &stored_static.eventkey_alias) {
                continue;
            }

            // Check whether the record contains the keywords (all of them when the and_logic
            // option is set, otherwise any of them).
            let search_target = if case_insensitive_flag {
                record.data_string.to_lowercase()
            } else {
                record.data_string.to_string()
            };
            self.filepath = CompactString::from(record.evtx_filepath.as_str());

            let contain_keywords = |keywords: &[String]| -> bool {
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
            if !contain_keywords(keywords) {
                continue;
            }

            // Collect the hit record, or output it on the fly.
            let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                extract_search_event_info(
                    record,
                    &stored_static.eventkey_alias,
                    stored_static.output_option.as_ref().unwrap(),
                );
            // Look up the field-name abbreviation table for this record's provider and event ID.
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
            // Replace the 🛂r/🛂n/🛂t placeholders (substituted for \r, \n and \t by
            // utils::remove_sp_char) with a 🦅 sentinel, re-join the pieces with single spaces,
            // and shorten full field names to their abbreviations.
            let abbreviated_all_field_info = self.replace_all_field_info_abbr(
                ALLFIELDINFO_SPECIAL_CHARS
                    .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                    .split('🦅')
                    .filter(|x| !x.is_empty())
                    .join(" ")
                    .as_str(),
                target_allfieldinfo_abbr_table,
            );

            if search_option.sort_events {
                // We cannot sort the results until every record has been processed, so we just
                // collect the hit records here and sort them later.
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    abbreviated_all_field_info,
                    self.filepath.clone(),
                ));
                self.search_result_cnt += 1;
            } else {
                // The sort_events option is false, so the hit record is output on the fly.
                // We avoid collecting hit records in memory whenever possible in order to reduce
                // memory usage.
                let hit_record = (
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    abbreviated_all_field_info,
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

    /// Checks each record against the regex given in the search command options and collects or
    /// outputs the matching records.
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
            // Skip this record if it does not satisfy the filter conditions.
            if !self.filter_record(record, &filter_rule, &stored_static.eventkey_alias) {
                continue;
            }

            // Check whether the regex matches the record.
            self.filepath = CompactString::from(record.evtx_filepath.as_str());
            if !re.is_match(&record.data_string) {
                continue;
            }

            // Collect the hit record, or output it on the fly.
            let (timestamp, hostname, channel, eventid, recordid, allfieldinfo) =
                extract_search_event_info(
                    record,
                    &stored_static.eventkey_alias,
                    stored_static.output_option.as_ref().unwrap(),
                );
            // Look up the field-name abbreviation table for this record's provider and event ID.
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
            // Replace the 🛂r/🛂n/🛂t placeholders (substituted for \r, \n and \t by
            // utils::remove_sp_char) with a 🦅 sentinel, re-join the pieces with single spaces,
            // and shorten full field names to their abbreviations.
            let abbreviated_all_field_info = self.replace_all_field_info_abbr(
                ALLFIELDINFO_SPECIAL_CHARS
                    .replace_all(&allfieldinfo, &["🦅", "🦅", "🦅"])
                    .split('🦅')
                    .filter(|x| !x.is_empty())
                    .join(" ")
                    .as_str(),
                target_allfieldinfo_abbr_table,
            );

            if search_option.sort_events {
                // We cannot sort the results until every record has been processed, so we just
                // collect the hit records here and sort them later.
                self.search_result.insert((
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    abbreviated_all_field_info,
                    self.filepath.clone(),
                ));
                self.search_result_cnt += 1;
            } else {
                // The sort_events option is false, so the hit record is output on the fly.
                // We avoid collecting hit records in memory whenever possible in order to reduce
                // memory usage.
                let hit_record = (
                    timestamp,
                    hostname,
                    channel,
                    eventid,
                    recordid,
                    abbreviated_all_field_info,
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

    /// Replaces full field names in the given AllFieldInfo string with their abbreviations from
    /// default_details.txt (e.g. "CommandLine" -> "Cmdline"). Replacement is applied in ascending
    /// order of field-name length.
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
        pairs.sort_unstable_by_key(|a| a.0.len());
        let mut all_field_info = value.to_string();
        for (k, v) in pairs {
            all_field_info = all_field_info.replace(k.as_str(), v.as_str());
        }
        all_field_info.into()
    }
}

/// Writes search results either to the terminal (colored) or to a CSV/JSON/JSONL file, depending
/// on the search options.
pub struct ResultWriter {
    // Terminal writer; Some only when no output file was specified.
    pub display_writer: Option<BufferWriter>,
    // File writer; Some only when an output file was specified.
    pub file_wtr: Option<Writer<BufWriter<File>>>,
    written_record_num: u64,
}

impl ResultWriter {
    pub fn new(search_option: &SearchOption) -> ResultWriter {
        let mut file_wtr = Option::None;
        if let Some(path) = &search_option.output {
            // Create the file if it does not exist, and append to it if it does.
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

        let display_writer = if file_wtr.is_none() {
            Some(BufferWriter::stdout(ColorChoice::Always))
        } else {
            Option::None
        };

        ResultWriter {
            display_writer,
            file_wtr,
            written_record_num: 0,
        }
    }

    /// Writes the output header: the CSV header row for file output, or the column names for
    /// terminal output. JSON/JSONL output has no header.
    fn write_header(&mut self, search_option: &SearchOption) {
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
                self.display_writer.as_mut().unwrap(),
                None,
                &OUTPUT_HEADERS.join(" · "),
                true,
            )
            .ok();
        }
    }

    /// Writes one search hit in the configured format: CSV or JSON/JSONL when writing to a file,
    /// or a colored " · "-separated line when writing to the terminal. The header is written
    /// first when is_write_header is true (i.e. for the first hit).
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
            self.write_header(search_option);
        }
        self.written_record_num += 1;

        let event_title = if let Some(event_info) = stored_static
            .event_timeline_config
            .get_event_id(&channel.to_ascii_lowercase(), &event_id)
        {
            CompactString::from(event_info.event_title.as_str())
        } else {
            "-".into()
        };
        let abbr_channel = stored_static.generic_abbr_matcher.replace_all(
            stored_static
                .channel_abbr_config
                .get(&channel.to_ascii_lowercase())
                .unwrap_or(&channel)
                .as_str(),
            &stored_static.generic_abbr_values,
        );
        let get_char_color = |output_char_color: Option<Color>| {
            if stored_static.common_options.no_color {
                None
            } else {
                output_char_color
            }
        };

        let fmted_all_field_info = all_field_info.split_whitespace().join(" ");
        // Depending on the output options, the " ¦ " separator between fields is replaced with a
        // newline (multiline file output) or a tab.
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
            // For JSON/JSONL file output, wrap the fields produced by output_json_str() in curly
            // braces.
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
            detect_info.output_fields.push((
                CompactString::from("Timestamp"),
                Profile::Timestamp(timestamp.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("Hostname"),
                Profile::Computer(hostname.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("Channel"),
                Profile::Channel(abbr_channel.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("Event ID"),
                Profile::EventID(event_id.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("Record ID"),
                Profile::RecordID(record_id.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("EventTitle"),
                Profile::Literal(event_title.into()),
            ));
            detect_info.output_fields.push((
                CompactString::from("AllFieldInfo"),
                Profile::AllFieldInfo(all_field_info.into()),
            ));
            detect_info.output_fields.push((
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
                    // Output the AllFieldInfo column: print each "name: value" pair in two
                    // colors, with " ¦ " between pairs.
                    let all_field_sep_info = all_field_info.split('¦').collect::<Vec<&str>>();
                    for (field_idx, fields) in all_field_sep_info.iter().enumerate() {
                        let mut separated_fields_data =
                            fields.split(':').map(|x| x.split_whitespace().join(" "));
                        write_color_buffer(
                            self.display_writer.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(255, 158, 61))),
                            &format!("{}: ", separated_fields_data.next().unwrap()),
                            newline_flag,
                        )
                        .ok();
                        write_color_buffer(
                            self.display_writer.as_mut().unwrap(),
                            get_char_color(Some(Color::Rgb(0, 255, 255))),
                            separated_fields_data.join(":").trim(),
                            newline_flag,
                        )
                        .ok();
                        if field_idx != all_field_sep_info.len() - 1 {
                            write_color_buffer(
                                self.display_writer.as_mut().unwrap(),
                                None,
                                " ¦ ",
                                newline_flag,
                            )
                            .ok();
                        }
                    }
                } else if record_field_idx == 0 || record_field_idx == 1 {
                    // Display timestamp and event title in the same color.
                    write_color_buffer(
                        self.display_writer.as_mut().unwrap(),
                        get_char_color(Some(Color::Rgb(0, 255, 0))),
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                } else {
                    write_color_buffer(
                        self.display_writer.as_mut().unwrap(),
                        None,
                        record_field_data,
                        newline_flag,
                    )
                    .ok();
                }

                if !newline_flag {
                    write_color_buffer(
                        self.display_writer.as_mut().unwrap(),
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

/// Parses the filter conditions ("FieldName:value" strings with wildcard support) into a map from
/// field name to wildcard patterns. Surrounding double quotes are stripped, and conditions
/// without a colon are ignored.
fn create_filter_rule(filters: &[String]) -> HashMap<String, Vec<WildMatch>> {
    filters
        .iter()
        .fold(HashMap::new(), |mut acc, filter_condition| {
            let prefix_trim_condition = filter_condition
                .strip_prefix('"')
                .unwrap_or(filter_condition);
            let trimmed_condition = prefix_trim_condition
                .strip_suffix('"')
                .unwrap_or(prefix_trim_condition);
            let condition = trimmed_condition.split(':').map(|x| x.trim()).collect_vec();
            if condition.len() != 1 {
                let acc_val = acc.entry(condition[0].to_string()).or_insert(vec![]);
                condition[1..]
                    .iter()
                    .for_each(|x| acc_val.push(WildMatch::new(x)));
            }
            acc
        })
}

/// Extracts the output fields (timestamp, hostname, channel, event ID, record ID, AllFieldInfo)
/// from an event record that matched the search conditions.
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
    // Fall back to the UNIX epoch when the record's timestamp cannot be parsed.
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

/// Outputs the collected search results to standard output or a file, followed by the total
/// number of findings. When the sort_events option is false, the hits were already written on
/// the fly, so only the summary is printed here.
pub fn search_result_dsp_msg(
    event_search: &EventSearch,
    search_option: &SearchOption,
    stored_static: &StoredStatic,
) {
    let mut wtr = ResultWriter::new(search_option);
    if search_option.sort_events {
        // Sort hits by timestamp, then record ID (string comparison), then evtx file path.
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

    // If the sort_events option is false, the search results have already been output on the fly.
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

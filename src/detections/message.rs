extern crate lazy_static;
use super::configs::EventKeyAliasConfig;
use super::utils::{get_writable_color, remove_sp_char};
use crate::detections::configs::CURRENT_EXE_PATH;
use crate::detections::field_data_map::{FieldDataMap, FieldDataMapKey, convert_field_data};
use crate::detections::rule::AggResult;
use crate::detections::utils::{self, get_serde_number_to_string, write_color_buffer};
use crate::level::LEVEL;
use crate::options::profile::Profile::{
    self, AllFieldInfo, Details, ExtraFieldInfo, Literal, SrcASN, SrcCity, SrcCountry, TgtASN,
    TgtCity, TgtCountry,
};
use chrono::{DateTime, Local, Utc};
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use hashbrown::HashMap;
use hashbrown::HashSet;
use itertools::Itertools;
use lazy_static::lazy_static;
use nested::Nested;
use regex::Regex;
use rust_embed::Embed;
use serde_json::Value;
use std::env;
use std::fs::{File, create_dir};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use termcolor::{BufferWriter, Color, ColorChoice};
/// Represents a single detection result: metadata of the matched rule, key values taken from the
/// matched event record (or aggregation result), and the output profile fields to render.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetectInfo {
    pub detected_time: DateTime<Utc>,
    pub rulepath: CompactString,
    pub ruleid: CompactString,
    pub ruletitle: CompactString,
    pub ruleauthor: CompactString,
    pub level: LEVEL,
    pub computername: CompactString,
    pub rec_id: CompactString,
    pub eventid: CompactString,
    // The rendered Details text. create_message() moves it into ext_field and clears it afterwards
    // to save memory.
    pub detail: CompactString,
    // Output profile columns as (column name, value) pairs.
    pub ext_field: Vec<(CompactString, Profile)>,
    // Set only when the detection comes from an aggregation (count/correlation) rule.
    pub agg_result: Option<AggResult>,
    // Per-field values keyed by "#Details" / "#AllFieldInfo" / "#ExtraFieldInfo", used by the JSON
    // output writers to expand those profile fields themselves.
    pub details_convert_map: HashMap<CompactString, Vec<CompactString>>,
}

/// Namespace for console error/warning output and for writing the error log file.
pub struct AlertMessage {}

// Embedded fallback copy of config/mitre_tactics.txt, used when the file cannot be read from disk.
#[derive(Embed)]
#[folder = "config"]
#[include = "mitre_tactics.txt"]
struct Mitretactics;

lazy_static! {
    // Matches a %EventKeyAlias% placeholder in details/profile templates, e.g. %CommandLine%.
    #[derive(Debug,PartialEq, Eq, Ord, PartialOrd)]
    pub static ref ALIASREGEX: Regex = Regex::new(r"%[a-zA-Z0-9-_\[\]]+%").unwrap();
    // Matches the 1-based array index suffix in aliases such as %Data[1]%.
    pub static ref SUFFIXREGEX: Regex = Regex::new(r"\[([0-9]+)\]").unwrap();
    // Errors collected while a run is in progress; flushed to ./logs/errorlog-<timestamp>.log by
    // AlertMessage::create_error_log().
    pub static ref ERROR_LOG_STACK: Mutex<Nested<String>> = Mutex::new(Nested::<String>::new());
    // Maps a MITRE tag (e.g. "attack.impact") to its display name (e.g. "Impact"), loaded from
    // config/mitre_tactics.txt.
    pub static ref TAGS_CONFIG: HashMap<CompactString, CompactString> = create_output_filter_config(
        utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "config/mitre_tactics.txt", true)
            .unwrap().to_str()
            .unwrap(),
        true,
        false
    );
    // Per-computer MITRE ATT&CK tactic counts as (tactic, unique detection count, total detection
    // count) tuples, collected for the HTML report.
    pub static ref COMPUTER_MITRE_ATTCK_MAP : DashMap<CompactString, Vec<(CompactString, i64, i64)>> = DashMap::new();
    // "computer|tactic|rulepath" keys that have already been seen, so each rule increments the
    // unique count in COMPUTER_MITRE_ATTCK_MAP only once per computer and tactic.
    pub static ref COMPUTER_MITRE_ATTCK_UNIQUE_KEYS : DashSet<CompactString> = DashSet::new();
}

/// Creates a HashMap from a CSV config file (e.g. mitre_tactics.txt or channel_abbreviations.txt)
/// that maps a full name to the abbreviated string shown in its place in the output.
/// e.g. the line "attack.impact,Impact" maps "attack.impact" to "Impact".
/// Returns an empty map when `disable_abbreviation` is set, so that no abbreviation takes place.
pub fn create_output_filter_config(
    path: &str,
    is_lower_case: bool,
    disable_abbreviation: bool,
) -> HashMap<CompactString, CompactString> {
    let mut ret: HashMap<CompactString, CompactString> = HashMap::new();
    if disable_abbreviation {
        return ret;
    }
    let read_result = match utils::read_csv(path) {
        Ok(c) => c,
        Err(e) => {
            // Fall back to the embedded copy of mitre_tactics.txt when the file on disk cannot be
            // read.
            if path.contains("mitre_tactics.txt") {
                let mitre_tactics = Mitretactics::get("mitre_tactics.txt").unwrap();
                utils::parse_csv(
                    std::str::from_utf8(mitre_tactics.data.as_ref()).unwrap_or_default(),
                )
            } else {
                AlertMessage::alert(&e).ok();
                Nested::new()
            }
        }
    };
    read_result.iter().for_each(|line| {
        let key = if is_lower_case {
            line[0].trim().to_ascii_lowercase()
        } else {
            line[0].trim().to_string()
        };
        ret.insert(
            CompactString::from(key),
            CompactString::from(line[1..].iter().map(|x| x.trim()).join(",")),
        );
    });
    ret
}

/// Builds the final per-detection output by filling in each profile field of
/// `detect_info.ext_field`: the Details template (`output`) and the other %alias% placeholders are
/// replaced with values from the event record, AllFieldInfo is generated from all of the record's
/// fields, and ExtraFieldInfo receives the record fields whose values do not already appear in
/// Details. For the JSON timeline, per-field values are additionally stored in
/// `details_convert_map` ("#Details" / "#AllFieldInfo" / "#ExtraFieldInfo") because the JSON
/// writers expand those fields themselves.
pub fn create_message(
    event_record: &Value,
    output: CompactString,
    mut detect_info: DetectInfo,
    profile_converter: &HashMap<&str, Profile>,
    (is_agg, is_json_timeline): (bool, bool),
    (eventkey_alias, field_data_map_key, field_data_map): (
        &EventKeyAliasConfig,
        &FieldDataMapKey,
        &Option<FieldDataMap>,
    ),
) -> DetectInfo {
    let mut record_details_info_map = HashMap::new();
    let mut special_char_removed_details = vec![];
    if !is_agg {
        // At this stage, obtain the details text with its %alias% placeholders replaced by record
        // values, along with the individual key/value pairs that make up the details.
        let (removed_sp_parsed_detail, mut details_in_record) = parse_message(
            event_record,
            &output,
            eventkey_alias,
            is_json_timeline,
            field_data_map_key,
            field_data_map,
        );
        details_in_record.drain(..).for_each(|v| {
            special_char_removed_details.push(remove_sp_char(v));
        });
        if is_json_timeline {
            record_details_info_map.insert("#Details".into(), special_char_removed_details.clone());
        }
        // remove_sp_char() strips special (control) characters via retain(). So that the newline
        // characters inside Details survive this, they are first converted to special placeholder
        // sequences that include an emoji (e.g. "🛂n").
        let parsed_detail = remove_sp_char(removed_sp_parsed_detail);
        detect_info.detail = if parsed_detail.is_empty() {
            CompactString::from("-")
        } else {
            parsed_detail
        };
    } else if output != "-" {
        record_details_info_map.insert("#Details".into(), vec![output]);
    } else if detect_info.detail != "-" {
        record_details_info_map.insert("#Details".into(), vec![detect_info.detail.clone()]);
    } else {
        record_details_info_map.insert("#Details".into(), vec!["-".into()]);
    }
    let mut replaced_profiles: Vec<(CompactString, Profile)> = vec![];
    let mut exist_all_field_info_in_ext_field = false;
    for (key, profile) in detect_info.ext_field.iter() {
        match profile {
            Details(_) => {
                if detect_info.detail.is_empty() {
                    // If the Details content is empty, insert the value as-is.
                    replaced_profiles.push((key.to_owned(), profile.to_owned()));
                } else {
                    replaced_profiles
                        .push((key.to_owned(), Details(detect_info.detail.clone().into())));

                    // Clear the Details content to save memory; the value now lives in
                    // replaced_profiles.
                    detect_info.detail = CompactString::default();
                }
            }
            AllFieldInfo(_) => {
                exist_all_field_info_in_ext_field = true;
                if is_agg {
                    replaced_profiles.push((
                        key.to_owned(),
                        AllFieldInfo(detect_info.detail.clone().into()),
                    ));
                    if is_json_timeline {
                        record_details_info_map.insert(
                            "#AllFieldInfo".into(),
                            vec![CompactString::new(detect_info.detail.clone())],
                        );
                    }
                } else {
                    let all_field_infos = if let Some(c) =
                        record_details_info_map.get("#AllFieldInfo")
                    {
                        c.to_owned()
                    } else {
                        utils::create_recordinfos(event_record, field_data_map_key, field_data_map)
                    };
                    if is_json_timeline {
                        record_details_info_map.insert("#AllFieldInfo".into(), all_field_infos);
                        replaced_profiles.push((key.to_owned(), AllFieldInfo("".into())));
                        continue;
                    }
                    let rec = if all_field_infos.is_empty() {
                        "-".to_string()
                    } else if !is_json_timeline {
                        all_field_infos.join(" ¦ ")
                    } else {
                        String::default()
                    };
                    replaced_profiles.push((key.to_owned(), AllFieldInfo(rec.into())));
                }
            }
            Literal(_) => replaced_profiles.push((key.to_owned(), profile.to_owned())),
            ExtraFieldInfo(_) => {
                if is_agg {
                    if is_json_timeline {
                        record_details_info_map
                            .insert("#ExtraFieldInfo".into(), vec![CompactString::from("-")]);
                        replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                    } else {
                        replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                    }
                    continue;
                }
                let profile_all_field_info_prof = record_details_info_map.get("#AllFieldInfo");
                // Collect the values already shown in Details so that ExtraFieldInfo only reports
                // the record fields whose values are not part of Details.
                let details_splits: HashSet<&str> = {
                    let details = special_char_removed_details.iter().map(|x| {
                        let v = x.split_once(": ").unwrap_or_default().1;
                        // Strip any trailing comma from the values put into the matching hash set;
                        // otherwise the ExtraFieldInfo match result would differ depending on
                        // whether or not a value carries a trailing comma.
                        v.strip_suffix(',').unwrap_or(v)
                    });
                    HashSet::from_iter(details)
                };
                let profile_all_field_info = if let Some(all_field_info_val) =
                    profile_all_field_info_prof
                {
                    all_field_info_val.to_owned()
                } else {
                    let recinfo =
                        utils::create_recordinfos(event_record, field_data_map_key, field_data_map);
                    record_details_info_map.insert("#AllFieldInfo".into(), recinfo.clone());
                    recinfo
                };
                let extra_field_vec = profile_all_field_info
                    .iter()
                    .filter(|x| {
                        let value = x.split_once(": ").unwrap_or_default().1;
                        !details_splits.contains(value)
                    })
                    .map(|y| y.to_owned())
                    .sorted_unstable()
                    .collect();
                if is_json_timeline {
                    record_details_info_map.insert("#ExtraFieldInfo".into(), extra_field_vec);
                    replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                } else if extra_field_vec.is_empty() {
                    replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                } else {
                    replaced_profiles.push((
                        key.to_owned(),
                        ExtraFieldInfo(extra_field_vec.join(" ¦ ").into()),
                    ));
                }
            }
            SrcASN(_) | SrcCountry(_) | SrcCity(_) | TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                replaced_profiles.push((
                    key.to_owned(),
                    profile_converter.get(key.as_str()).unwrap().to_owned(),
                ))
            }
            _ => {
                if let Some(p) = profile_converter.get(key.as_str()) {
                    let (parsed_message, _) = &parse_message(
                        event_record,
                        &CompactString::new(p.to_value()),
                        eventkey_alias,
                        is_json_timeline,
                        field_data_map_key,
                        field_data_map,
                    );
                    replaced_profiles.push((key.to_owned(), profile.convert(parsed_message)))
                }
            }
        }
    }
    if !exist_all_field_info_in_ext_field {
        record_details_info_map.remove("#AllFieldInfo");
    }
    detect_info.ext_field = replaced_profiles;
    detect_info.details_convert_map = record_details_info_map;

    detect_info
}

/// Treats each %...% section in `output` as an alias and replaces it with the corresponding value
/// looked up in the event record (via eventkey_alias.txt, falling back to Event.EventData.<name>).
/// Returns the replaced message together with the "key: value" pairs that make up the details.
/// For the JSON timeline the message itself is returned with its placeholders intact, because the
/// afterfact output functions perform the replacement in that case.
pub fn parse_message(
    event_record: &Value,
    output: &CompactString,
    eventkey_alias: &EventKeyAliasConfig,
    json_timeline_flag: bool,
    field_data_map_key: &FieldDataMapKey,
    field_data_map: &Option<FieldDataMap>,
) -> (CompactString, Vec<CompactString>) {
    let mut return_message = output.clone();
    let mut hash_map: Vec<(CompactString, Vec<CompactString>)> = vec![];
    let details_key: Vec<&str> = output.split(" ¦ ").collect();
    for caps in ALIASREGEX.captures_iter(&return_message) {
        let full_target_str = &caps[0];
        let target_str = full_target_str
            .strip_suffix('%')
            .unwrap()
            .strip_prefix('%')
            .unwrap();
        let event_key_path = if let Some(_array_str) = eventkey_alias.get_event_key(target_str) {
            _array_str.to_string()
        } else {
            // No alias definition exists, so fall back to looking the field up directly under
            // Event.EventData.
            format!("Event.EventData.{target_str}")
        };

        let mut tmp_event_record: &Value = event_record;
        let mut field = "";
        for s in event_key_path.split('.') {
            if let Some(record) = tmp_event_record.get(s) {
                tmp_event_record = record;
                field = s;
            }
        }
        // An alias like %Data[2]% selects a single element of the EventData "Data" array; the
        // bracketed index is 1-based. A value below 1 skips the element selection, and since the
        // bracketed name itself does not resolve to a record field, such an alias yields "n/a".
        let suffix_match = SUFFIXREGEX.captures(target_str);
        let suffix: i64 = match suffix_match {
            Some(cap) => cap.get(1).map_or(-1, |a| a.as_str().parse().unwrap_or(-1)),
            None => -1,
        };
        if suffix >= 1 {
            tmp_event_record = tmp_event_record
                .get("Data")
                .unwrap_or(tmp_event_record)
                .get((suffix - 1) as usize)
                .unwrap_or(tmp_event_record);
            field = target_str;
        }
        let hash_value = get_serde_number_to_string(tmp_event_record, false);
        if hash_value.is_some() {
            if let Some(hash_value) = hash_value {
                let field_data = if field_data_map.is_none() || field.is_empty() {
                    hash_value
                } else {
                    let converted_str = convert_field_data(
                        field_data_map.as_ref().unwrap(),
                        field_data_map_key,
                        field.to_lowercase().as_str(),
                        hash_value.as_str(),
                        event_record,
                    );
                    converted_str.unwrap_or(hash_value)
                };
                if json_timeline_flag {
                    hash_map.push((CompactString::from(full_target_str), [field_data].to_vec()));
                } else {
                    hash_map.push((
                        CompactString::from(full_target_str),
                        [field_data.split_ascii_whitespace().join(" ").into()].to_vec(),
                    ));
                }
            }
        } else {
            // The alias could not be resolved to a value in this record.
            hash_map.push((
                CompactString::from(full_target_str),
                ["n/a".into()].to_vec(),
            ));
        }
    }
    let mut details_key_and_value: Vec<CompactString> = vec![];
    for (k, v) in hash_map.iter() {
        // For JSON output, the alias replacement processing is handled by the afterfact output
        // functions, so it is not done here.
        if !json_timeline_flag {
            return_message = CompactString::new(return_message.replace(k.as_str(), v[0].as_str()));
        }
        for detail_contents in details_key.iter() {
            if detail_contents.contains(k.as_str()) {
                let key = detail_contents.split_once(": ").unwrap_or_default().0;
                details_key_and_value.push(format!("{}: {}", key, v[0]).into());
                break;
            }
        }
    }
    if hash_map.is_empty() {
        for detail_contents in details_key.iter() {
            let key = detail_contents.split_once(": ").unwrap_or_default().0;
            let val = detail_contents.split_once(": ").unwrap_or_default().1;
            details_key_and_value.push(format!("{key}: {val}").into());
        }
    }
    (return_message, details_key_and_value)
}

/// Returns the record's creation time: Event.System.@timestamp for JSON input, or the SystemTime
/// attribute of Event.System.TimeCreated for evtx input.
pub fn get_event_time(event_record: &Value, json_input_flag: bool) -> Option<DateTime<Utc>> {
    let system_time = if json_input_flag {
        &event_record["Event"]["System"]["@timestamp"]
    } else {
        &event_record["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
    };
    utils::str_time_to_datetime(system_time.as_str().unwrap_or(""))
}

impl AlertMessage {
    /// Writes all errors accumulated in ERROR_LOG_STACK to ./logs/errorlog-<timestamp>.log
    /// (creating the logs directory if needed and recording the command line that was run first),
    /// then prints a red notice pointing to that file. Does nothing when --quiet-errors is set.
    pub fn create_error_log(quiet_errors_flag: bool, no_color: bool) {
        if quiet_errors_flag {
            return;
        }
        let file_path = format!(
            "./logs/errorlog-{}.log",
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let path = Path::new(&file_path);
        if !path.parent().unwrap().exists() {
            create_dir(path.parent().unwrap()).ok();
        }
        let mut error_log_writer = BufWriter::new(File::create(path).unwrap());
        error_log_writer
            .write_all(
                format!(
                    "user input: {:?}\n",
                    format_args!(
                        "{}",
                        env::args().collect::<Nested<String>>().iter().join(" ")
                    )
                )
                .as_bytes(),
            )
            .ok();
        let error_logs = ERROR_LOG_STACK.lock().unwrap();
        error_logs.iter().for_each(|error_log| {
            writeln!(error_log_writer, "{error_log}").ok();
        });
        println!();
        let msg = format!("Errors were generated. Please check {file_path} for details.");
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(Some(Color::Rgb(255, 0, 0)), no_color),
            msg.as_str(),
            true,
        )
        .ok();
        write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", false).ok();
    }

    /// Function to display an [ERROR] message on stderr.
    pub fn alert(contents: &str) -> io::Result<()> {
        write_color_buffer(
            &BufferWriter::stderr(ColorChoice::Always),
            None,
            &format!("[ERROR] {contents}"),
            true,
        )
    }

    /// Function to display a [WARN] message on stderr.
    pub fn warn(contents: &str) -> io::Result<()> {
        write_color_buffer(
            &BufferWriter::stderr(ColorChoice::Always),
            None,
            &format!("[WARN] {contents}"),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::configs::{CURRENT_EXE_PATH, StoredStatic, load_eventkey_alias};
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::detections::message::{AlertMessage, parse_message};
    use crate::detections::utils;

    use compact_str::CompactString;
    use hashbrown::HashMap;
    use serde_json::Value;

    use super::create_output_filter_config;

    #[test]
    fn test_error_message() {
        let input = "TEST!";
        AlertMessage::alert(input).expect("[ERROR] TEST!");
    }

    #[test]
    fn test_warn_message() {
        let input = "TESTWarn!";
        AlertMessage::warn(input).expect("[WARN] TESTWarn!");
    }

    #[test]
    /// Verifies that %alias% keys in output (defined in eventkey_alias.txt) are replaced with the
    /// corresponding values from the target record.
    fn test_parse_message() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest1"
                },
                "System": {
                    "Computer": "testcomputer1",
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest1 computername:testcomputer1";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% computername:%ComputerName%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }

    #[test]
    /// Verifies that a key with no eventkey_alias.txt entry is automatically looked up directly
    /// under Event.EventData.
    fn test_parse_message_auto_search() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "NoAlias": "no_alias"
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "alias:no_alias";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("alias:%NoAlias%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }

    #[test]
    /// Output test for when the key specified in output is neither set in eventkey_alias.txt nor
    /// present in the record: the value becomes "n/a".
    fn test_parse_message_not_exist_key_in_output() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest2"
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "NoExistAlias:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("NoExistAlias:%NoAliasNoHit%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// Output test for when the key specified in output is defined in eventkey_alias.txt but the
    /// target record contains no corresponding value: the value becomes "n/a".
    fn test_parse_message_not_exist_value_in_record() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3"
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 computername:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% computername:%ComputerName%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// Output test for an alias that refers to an array field (Data) without an index suffix: the
    /// whole array is output as-is in its JSON form.
    fn test_parse_message_multiple_no_suffix_in_record() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:[\"data1\",\"data2\",\"data3\"]";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// Output test for an alias with an index suffix (%Data[2]%): the second element of the Data
    /// array is selected, since the suffix is 1-based.
    fn test_parse_message_multiple_with_suffix_in_record() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:data2";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data[2]%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// Output test for an alias with an invalid index suffix (%Data[0]%): index suffixes are
    /// 1-based, so no array element is selected and the value becomes "n/a".
    fn test_parse_message_multiple_no_exist_in_record() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data[0]%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// Loading test for the output filter config in mitre_tactics.txt.
    fn test_load_mitre_tactics_log() {
        let actual =
            create_output_filter_config("test_files/config/mitre_tactics.txt", true, false);
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("attack.impact".into(), "Impact".into()),
            ("xxx".into(), "yyy".into()),
        ]);
        _check_hashmap_element(&expected, actual);
    }

    #[test]
    /// Loading test for channel_abbreviations.txt.
    fn test_load_abbreviations() {
        let actual =
            create_output_filter_config("test_files/config/channel_abbreviations.txt", true, false);
        let actual2 =
            create_output_filter_config("test_files/config/channel_abbreviations.txt", true, false);
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("security".into(), "Sec".into()),
            ("xxx".into(), "yyy".into()),
        ]);
        _check_hashmap_element(&expected, actual);
        _check_hashmap_element(&expected, actual2);
    }

    #[test]
    fn _get_default_details() {
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("Microsoft-Windows-PowerShell_4104".into(),"%ScriptBlockText%".into()),("Microsoft-Windows-Security-Auditing_4624".into(), "User: %TargetUserName% | Comp: %WorkstationName% | IP Addr: %IpAddress% | LID: %TargetLogonId% | Process: %ProcessName%".into()),
            ("Microsoft-Windows-Sysmon_1".into(), "Cmd: %CommandLine% | Process: %Image% | User: %User% | Parent Cmd: %ParentCommandLine% | LID: %LogonId% | PID: %ProcessId% | PGUID: %ProcessGuid%".into()),
            ("Service Control Manager_7031".into(), "Svc: %param1% | Crash Count: %param2% | Action: %param5%".into()),
        ]);
        let actual =
            StoredStatic::get_default_details("test_files/config/default_details.txt", false);
        _check_hashmap_element(&expected, actual);
    }

    #[test]
    fn _get_default_details_with_abbreviation() {
        let expected: HashMap<CompactString, CompactString> = HashMap::new();
        let actual =
            StoredStatic::get_default_details("test_files/config/default_details.txt", true);
        _check_hashmap_element(&expected, actual);
    }

    /// Asserts that both HashMaps have the same length and that every expected entry is present in
    /// `actual` with the same value.
    fn _check_hashmap_element(
        expected: &HashMap<CompactString, CompactString>,
        actual: HashMap<CompactString, CompactString>,
    ) {
        assert_eq!(expected.len(), actual.len());
        for (k, v) in expected.iter() {
            assert!(actual.get(k).unwrap_or(&CompactString::default()) == v);
        }
    }
}

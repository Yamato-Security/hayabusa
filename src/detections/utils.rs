extern crate base64;
extern crate csv;
extern crate regex;

use std::cmp::Ordering;
use std::fs::{File, read_to_string};
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str;
use std::string::String;
use std::sync::Mutex;
use std::thread::available_parallelism;
use std::vec;
use std::{fs, io};

use chrono::Local;
use chrono::{DateTime, TimeZone, Utc};
use compact_str::{CompactString, ToCompactString};
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use memchr::memmem;
use nested::Nested;
use regex::Regex;
use serde_json::{Error, Map, Value, json};
use termcolor::{BufferWriter, ColorSpec, WriteColor};
use termcolor::{Color, ColorChoice};
use tokio::runtime::{Builder, Runtime};

use crate::detections::configs::{CURRENT_EXE_PATH, ONE_CONFIG_MAP, TimeFormatOptions};
use crate::detections::field_data_map::{FieldDataMap, FieldDataMapKey, convert_field_data};
use crate::detections::field_extract::extract_fields;
use crate::options::htmlreport;

use super::configs::{EventKeyAliasConfig, OutputOption};
use super::detection::EvtxRecordInfo;
use super::message::AlertMessage;
use rust_embed::Embed;

/// Embedded copy of config/default_profile_name.txt, used as a fallback when the file does not
/// exist on disk.
#[derive(Embed)]
#[folder = "config"]
#[include = "default_profile_name.txt"]
pub struct DefaultProfileName;

/// Builds a human-readable path into a rule's detection section, e.g.
/// "detection -> selection -> key1 -> key2", for use in rule parse error messages.
pub fn concat_selection_key(key_list: &Nested<String>) -> String {
    key_list
        .iter()
        .fold("detection -> selection".to_string(), |mut acc, cur| {
            acc = acc + " -> " + cur;
            acc
        })
}

/// Returns true if the string matches any of the given regexes.
pub fn check_regex(string: &str, regex_list: &[Regex]) -> bool {
    for regex in regex_list {
        if !regex.is_match(string) {
            continue;
        }

        return true;
    }

    false
}

/// Returns true if the target matches any of the allowlist regexes.
pub fn check_allowlist(target: &str, regexes: &[Regex]) -> bool {
    for regex in regexes {
        if regex.is_match(target) {
            return true;
        }
    }

    false
}

/// Converts a scalar JSON value (bool/number/string) to a trimmed string. Returns None for
/// null, arrays and objects.
pub fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => Option::None,
        Value::Bool(b) => Option::Some(b.to_string()),
        Value::Number(n) => Option::Some(n.to_string()),
        Value::String(s) => Option::Some(s.trim().to_string()),
        Value::Array(_) => Option::None,
        Value::Object(_) => Option::None,
    }
}

/// Reads a text file into its lines. If the file is part of the all-in-one config bundle
/// (ONE_CONFIG_MAP), the embedded content is used instead of reading from disk.
pub fn read_txt(filename: &str) -> Result<Nested<String>, String> {
    let filepath = if filename.starts_with("./") {
        check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), filename, true)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    } else {
        filename.to_string()
    };
    let re = Regex::new(r".*/").unwrap();
    let one_config_path = &re.replace(filename, "").to_string();
    if ONE_CONFIG_MAP.contains_key(one_config_path) {
        return Ok(Nested::from_iter(
            ONE_CONFIG_MAP
                .get(one_config_path)
                .unwrap()
                .lines()
                .map(|s| s.to_string()),
        ));
    }
    let f = File::open(filepath);
    if f.is_err() {
        let errmsg = format!("Cannot open file. [file:{filename}]");
        return Err(errmsg);
    }
    let reader = BufReader::new(f.unwrap());
    Ok(Nested::from_iter(
        reader.lines().map(|line| line.unwrap_or_default()),
    ))
}

/// Converts a JSONL-format file into an iterator of serde_json Values, wrapping each line's
/// object in {"Event": {"EventData": ...}} so that it has the same shape as an evtx-derived
/// record.
pub fn read_jsonl_to_value(path: &str) -> Result<Box<dyn Iterator<Item = Value>>, String> {
    let f = File::open(path);
    if f.is_err() {
        return Err("Cannot open file. [file:{path}]".to_string());
    }
    let reader = BufReader::new(f.unwrap());
    let mut peekable_lines = reader.lines().peekable();
    let first_line = peekable_lines.peek().unwrap();
    let is_jsonl = match first_line {
        Ok(s) => serde_json::from_str::<Value>(s).is_ok(),
        Err(_) => false,
    };
    if is_jsonl {
        let ret = peekable_lines
            .filter_map(|s| s.ok())
            .filter(|s| !s.trim().is_empty())
            .map(|line| {
                let v: Value = serde_json::from_str(&line).unwrap();
                json!({"Event":{"EventData": v}})
            });
        return Ok(Box::new(ret));
    }
    Err("Conversion failed because it is not in JSONL format.".to_string())
}

/// Converts a JSON-format file (either a JSON array, or concatenated objects as produced by
/// `jq -c`) into an iterator of serde_json Values, wrapping each record in
/// {"Event": {"EventData": ...}} so that it has the same shape as an evtx-derived record.
pub fn read_json_to_value(path: &str) -> Result<Box<dyn Iterator<Item = Value>>, String> {
    let f = fs::read_to_string(path);
    if f.is_err() {
        return Err("Cannot open file. [file:{path}]".to_string());
    }
    let contents = f.unwrap();
    let json_values: Result<Vec<Value>, Error> = serde_json::from_str(&contents);
    let value_converter = |record: Value| json!({"Event":{"EventData": record}});
    match json_values {
        Ok(values) => {
            // For JSON (Array) format.
            let ret = values.into_iter().map(value_converter);
            Ok(Box::new(ret))
        }
        Err(_) => {
            // For jq format.
            let newline_replaced_contents = contents.replace(['\n', '\r'], "");
            let json = format!(
                "[{}]",
                newline_replaced_contents
                    .split("}{")
                    .filter(|s| !s.trim().is_empty())
                    .join("},{")
            );
            let all_values_res: Result<Value, Error> = serde_json::from_str(&json);
            if let Err(err_msg) = all_values_res {
                return Err(err_msg.to_string());
            }
            let values = all_values_res.unwrap().as_array().unwrap().clone();
            let ret = values.into_iter().map(value_converter);
            Ok(Box::new(ret))
        }
    }
}

/// Reads a CSV config file into rows, preferring the all-in-one config bundle (ONE_CONFIG_MAP)
/// over the file on disk.
pub fn read_csv(filename: &str) -> Result<Nested<Vec<String>>, String> {
    let re = Regex::new(r".*/").unwrap();
    let one_config_path = &re.replace(filename, "").to_string();
    if ONE_CONFIG_MAP.contains_key(one_config_path) {
        let csv_res = parse_csv(ONE_CONFIG_MAP.get(one_config_path).unwrap());
        return Ok(csv_res);
    }
    let f = File::open(filename);
    if f.is_err() {
        return Err(format!("Cannot open file. [file:{filename}]"));
    }
    let mut contents: String = String::new();
    let read_res = f.unwrap().read_to_string(&mut contents);
    if let Err(e) = read_res {
        return Err(e.to_string());
    }

    let csv_res = parse_csv(&contents);
    Ok(csv_res)
}

/// Parses CSV contents into rows of column strings. The first row is treated as a header and is
/// not included in the result; unparsable rows are skipped silently.
pub fn parse_csv(file_contents: &str) -> Nested<Vec<String>> {
    let mut ret = Nested::<Vec<String>>::new();
    let mut rdr = csv::ReaderBuilder::new().from_reader(file_contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    ret
}

pub fn get_event_id_key() -> String {
    "Event.System.EventID".to_string()
}

/// Parses an RFC 3339 timestamp string (e.g. an evtx SystemTime value) into a UTC DateTime.
/// Returns None for empty or unparsable input.
pub fn str_time_to_datetime(system_time_str: &str) -> Option<DateTime<Utc>> {
    if system_time_str.is_empty() {
        return Option::None;
    }

    let rfc3339_time = DateTime::parse_from_rfc3339(system_time_str);
    if rfc3339_time.is_err() {
        return Option::None;
    }
    Utc.from_local_datetime(&rfc3339_time.unwrap().naive_utc())
        .single()
}

/// Converts a serde_json Value to a string regardless of its underlying type (string, number,
/// bool). When search_flag is true, objects are also flattened into "key:value ¦ key:value"
/// form so that the search feature can match against them; otherwise objects and null return
/// None.
pub fn get_serde_number_to_string(
    value: &serde_json::Value,
    search_flag: bool,
) -> Option<CompactString> {
    if value.is_string() {
        let val_str = value.as_str().unwrap_or("");
        Some(CompactString::from(val_str))
    } else if value.is_object() && search_flag {
        let map: Map<String, Value> = Map::new();
        let val_obj = value.as_object().unwrap_or(&map);
        let val = val_obj
            .iter()
            .map(|(k, v)| format!("{k}:{v}").replace('\"', ""))
            .collect::<Nested<String>>()
            .iter()
            .join(" ¦ ");
        Some(CompactString::from(val))
    } else if value.is_null() || (value.is_object() && !search_flag) {
        // Objects are not expected as record values (they are only stringified for the search
        // feature above), so return None.
        Option::None
    } else {
        Some(CompactString::from(value.to_string()))
    }
}

/// Looks up a value in the event record by key. The key is first resolved through
/// eventkey_alias.txt (e.g. "Computer" -> "Event.System.Computer"); keys without an alias are
/// treated as dot-separated JSON paths, and keys containing no dot are assumed to live under
/// "Event.EventData".
pub fn get_event_value<'a>(
    key: &str,
    event_value: &'a Value,
    eventkey_alias: &EventKeyAliasConfig,
) -> Option<&'a Value> {
    if key.is_empty() {
        return Option::None;
    }

    let event_key = eventkey_alias.get_event_key(key);
    let mut ret: &Value = event_value;
    if let Some(event_key) = event_key {
        // get_event_key_split always has an entry whenever get_event_key succeeded, so the
        // unwrap below is not checked.
        let splits = eventkey_alias.get_event_key_split(key);
        let mut start_idx = 0;
        // splits holds the length of each dot-separated segment of the resolved event key, so
        // the JSON path can be walked by slicing the key string instead of re-splitting it.
        for key in splits.unwrap() {
            if !ret.is_object() {
                return Option::None;
            }

            let val = &event_key[start_idx..(*key + start_idx)];
            ret = &ret[val];
            start_idx += *key;
            start_idx += 1;
        }

        Option::Some(ret)
    } else {
        let event_key = if !contains_str(key, ".") {
            "Event.EventData.".to_string() + key
        } else {
            key.to_string()
        };
        for key in event_key.split('.') {
            if !ret.is_object() {
                return Option::None;
            }
            ret = &ret[key];
        }

        Option::Some(ret)
    }
}

/// Returns the number of worker threads to use: the user-specified value if given, otherwise
/// the number of available CPU cores.
pub fn get_thread_num(thread_number: Option<usize>) -> usize {
    let cpu_num = available_parallelism().unwrap();
    thread_number.unwrap_or(cpu_num.into())
}

pub fn create_tokio_runtime(thread_number: Option<usize>) -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(get_thread_num(thread_number))
        .thread_name("hayabusa-thread")
        .build()
        .unwrap()
}

/// Creates an EvtxRecordInfo from a parsed event record.
pub fn create_rec_info(
    mut data: Value,
    path: String,
    keys: &Nested<String>,
    recovered_record: &bool,
    no_pwsh_field_extraction: &bool,
    eventkey_alias: &EventKeyAliasConfig,
) -> EvtxRecordInfo {
    // Processing for performance optimization.

    // For example, getting the value of "Event.System.EventID" from a serde_json Value requires
    // three accesses: value["Event"]["System"]["EventID"]. To speed this up, the value is stored
    // in the rec.key_to_value hashmap under the flat key "Event.System.EventID", so it can later
    // be retrieved with a single lookup, which should improve performance. Also, retrieving
    // values from a serde_json Value like value["Event"] is somehow slow, so this might help
    // there too. In addition, serde_json internally uses the standard library hashmap, but using
    // hashbrown is reportedly faster; since the standard library adopted hashbrown, serde_json
    // has also been sped up.
    let mut flat_key_to_value = HashMap::new();

    let mut event_id = None;
    let mut channel = None;
    for key in keys.iter() {
        let val = get_event_value(key, &data, eventkey_alias);
        if val.is_none() {
            continue;
        }

        let val = value_to_string(val.unwrap());
        if val.is_none() {
            continue;
        }

        if !*no_pwsh_field_extraction {
            if key == "EventID" {
                event_id.clone_from(&val);
            }
            if key == "Channel" {
                channel.clone_from(&val);
            }
        }
        flat_key_to_value.insert(key.to_string(), val.unwrap());
    }
    if !*no_pwsh_field_extraction {
        extract_fields(channel, event_id, &mut data, &mut flat_key_to_value);
    }

    // Create EvtxRecordInfo.
    let data_str = data.to_string();

    EvtxRecordInfo {
        evtx_filepath: path,
        record: data,
        data_string: data_str,
        key_to_value: flat_key_to_value,
        recovered_record: *recovered_record,
    }
}

/**
 * Writes the string to the given buffer writer with the specified foreground color and prints
 * it to the screen.
 */
pub fn write_color_buffer(
    wtr: &BufferWriter,
    color: Option<Color>,
    output_str: &str,
    newline_flag: bool,
) -> io::Result<()> {
    let mut buf = wtr.buffer();
    buf.set_color(ColorSpec::new().set_fg(color)).ok();
    if newline_flag {
        writeln!(buf, "{output_str}").ok();
    } else {
        write!(buf, "{output_str}").ok();
    }
    wtr.print(&buf)
}

/// Checks whether the no-color option is specified: returns None if it is, otherwise the color
/// given as an argument.
pub fn get_writable_color(color: Option<Color>, no_color: bool) -> Option<Color> {
    if no_color { None } else { color }
}

/**
 * Creates the string to output in the record info column of CSV.
 */
pub fn create_recordinfos(
    record: &Value,
    field_data_map_key: &FieldDataMapKey,
    field_data_map: &Option<FieldDataMap>,
) -> Vec<CompactString> {
    let mut output = HashSet::new();
    _collect_recordinfo(
        &mut vec![],
        "",
        -1,
        record,
        record,
        &mut output,
        (field_data_map, field_data_map_key),
    );

    let mut output_vec: Vec<&(String, String)> = output.iter().collect();
    // Sort so that the output is the same every time for the same record.
    output_vec.sort_by(|(left, left_data), (right, right_data)| {
        let ord = left.cmp(right);
        if ord == Ordering::Equal {
            left_data.cmp(right_data)
        } else {
            ord
        }
    });

    output_vec
        .iter()
        .map(|(key, value)| {
            if let Some(map) = field_data_map.as_ref()
                && let Some(converted_str) =
                    convert_field_data(map, field_data_map_key, &key.to_lowercase(), value, record)
            {
                let val = remove_sp_char(converted_str);
                return format!("{key}: {val}",).into();
            }
            let val = remove_sp_char(value.into());
            format!("{key}: {val}").into()
        })
        .collect()
}

/**
 * Collects all elements to output in the fields column of CSV.
 */
fn _collect_recordinfo<'a>(
    keys: &mut Vec<&'a str>,
    parent_key: &'a str,
    arr_index: i8,
    org_value: &'a Value,
    cur_value: &'a Value,
    output: &mut HashSet<(String, String)>,
    field_data_converter: (&Option<FieldDataMap>, &FieldDataMapKey),
) {
    match cur_value {
        Value::Array(ary) => {
            for (i, sub_value) in ary.iter().enumerate() {
                _collect_recordinfo(
                    keys,
                    parent_key,
                    i as i8,
                    org_value,
                    sub_value,
                    output,
                    field_data_converter,
                );
            }
        }
        Value::Object(obj) => {
            // The implementation is a bit unusual due to lifetime constraints: parent keys are
            // pushed/popped on a shared Vec of borrowed &strs instead of building owned path
            // strings.
            if !parent_key.is_empty() {
                keys.push(parent_key);
            }
            for (key, value) in obj {
                if key.eq("xmlns") {
                    continue;
                }
                // Do not output Event.System.
                if key.eq("System") && keys.first().unwrap_or(&"").eq(&"Event") {
                    continue;
                }

                _collect_recordinfo(
                    keys,
                    key,
                    -1,
                    org_value,
                    value,
                    output,
                    field_data_converter,
                );
            }
            if !parent_key.is_empty() {
                keys.pop();
            }
        }
        Value::Null => (),
        _ => {
            // Only collect the values of the innermost child elements.
            let strval = value_to_string(cur_value);
            if let Some(strval) = strval {
                // Replace control characters and whitespace with plain spaces, except for
                // \r, \n and \t, which are handled later by remove_sp_char.
                let mut strval = strval.chars().fold(String::default(), |mut acc, c| {
                    if (c.is_control() || c.is_ascii_whitespace())
                        && !['\r', '\n', '\t'].contains(&c)
                    {
                        acc.push(' ');
                    } else {
                        acc.push(c);
                    };
                    acc
                });
                // Array elements are output with 1-based indices, e.g. "Data[1]", "Data[2]".
                let key = if arr_index >= 0 {
                    let (field_data_map, field_data_map_key) = field_data_converter;
                    let i = arr_index + 1;
                    let field = format!("{parent_key}[{i}]").to_lowercase();
                    if let Some(map) = field_data_map {
                        let converted_str = convert_field_data(
                            map,
                            field_data_map_key,
                            field.as_str(),
                            strval.as_str(),
                            org_value,
                        );
                        if let Some(converted_str) = converted_str {
                            strval = converted_str.to_string();
                        }
                    }
                    format!("{parent_key}[{i}]")
                } else {
                    parent_key.to_string()
                };
                output.insert((key, strval));
            }
        }
    }
}

/**
 * Function to capitalize the first character.
 */
pub fn make_ascii_titlecase(s: &str) -> CompactString {
    let mut c = s.trim().chars();
    match c.next() {
        None => CompactString::default(),
        Some(f) => {
            if !f.is_ascii() {
                CompactString::from(s)
            } else {
                f.to_uppercase().collect::<CompactString>() + c.as_str()
            }
        }
    }
}

/// Resolves a config file path: returns the path as-is if it is part of the all-in-one config
/// bundle (ONE_CONFIG_MAP), otherwise base_path/path if that exists. If neither applies, returns
/// the path unchanged (interpreted relative to the current directory) when ignore_err is set,
/// or None otherwise.
pub fn check_setting_path(base_path: &Path, path: &str, ignore_err: bool) -> Option<PathBuf> {
    let re = Regex::new(r".*/").unwrap();
    if ONE_CONFIG_MAP.contains_key(&re.replace(path, "").to_string()) {
        Some(path.into())
    } else if base_path.join(path).exists() {
        Some(base_path.join(path))
    } else if ignore_err {
        Some(Path::new(path).to_path_buf())
    } else {
        None
    }
}

/// Function to verify the location of rule config files.
pub fn check_rule_config(config_path: &PathBuf) -> Result<(), String> {
    // Rule config files that must be present.
    let files = vec![
        "channel_abbreviations.txt",
        "target_event_IDs.txt",
        "default_details.txt",
        "level_tuning.txt",
        "channel_eid_info.txt",
        "eventkey_alias.txt",
    ];
    let all_keys_present = files.iter().all(|key| ONE_CONFIG_MAP.contains_key(*key));
    if all_keys_present {
        return Ok(());
    }

    // Check whether the rules/config folder exists.
    let exist_rule_config_folder = if config_path == &CURRENT_EXE_PATH.to_path_buf() {
        check_setting_path(config_path, "rules/config", false).is_some()
    } else {
        check_setting_path(config_path, "", false).is_some()
    };
    if !exist_rule_config_folder {
        return Err("The required rules and config files were not found. Please download them with the update-rules command.".to_string());
    }

    let mut not_exist_file = vec![];
    for file in &files {
        if check_setting_path(config_path, file, false).is_none() {
            not_exist_file.push(*file);
        }
    }

    if !not_exist_file.is_empty() {
        return Err(format!(
            "Could not find the following config files: {}\nPlease specify a correct rules config directory.\n",
            not_exist_file.join(", ")
        ));
    }
    Ok(())
}

/// Formats a UTC timestamp for output, converting it to the local timezone unless the UTC or
/// ISO 8601 output option is specified.
pub fn format_time(
    time: &DateTime<Utc>,
    date_only: bool,
    output_option: &TimeFormatOptions,
) -> CompactString {
    if !(output_option.utc || output_option.iso_8601) {
        format_rfc(&time.with_timezone(&Local), date_only, output_option)
    } else {
        format_rfc(time, date_only, output_option)
    }
}

/// Formats the time according to the selected time format option (RFC 2822, RFC 3339, US,
/// US military, European or ISO 8601 style, defaulting to "YYYY-MM-DD hh:mm:ss.fff +-hh:mm").
fn format_rfc<Tz: TimeZone>(
    time: &DateTime<Tz>,
    date_only: bool,
    time_args: &TimeFormatOptions,
) -> CompactString
where
    Tz::Offset: std::fmt::Display,
{
    if time_args.rfc_2822 {
        if date_only {
            time.format("%a, %e %b %Y").to_compact_string()
        } else {
            time.format("%a, %e %b %Y %H:%M:%S %:z").to_compact_string()
        }
    } else if time_args.rfc_3339 {
        if date_only {
            time.format("%Y-%m-%d").to_compact_string()
        } else {
            time.format("%Y-%m-%d %H:%M:%S%.6f%:z").to_compact_string()
        }
    } else if time_args.us_time {
        if date_only {
            time.format("%m-%d-%Y").to_compact_string()
        } else {
            time.format("%m-%d-%Y %I:%M:%S%.3f %p %:z")
                .to_compact_string()
        }
    } else if time_args.us_military_time {
        if date_only {
            time.format("%m-%d-%Y").to_compact_string()
        } else {
            time.format("%m-%d-%Y %H:%M:%S%.3f %:z").to_compact_string()
        }
    } else if time_args.european_time {
        if date_only {
            time.format("%d-%m-%Y").to_compact_string()
        } else {
            time.format("%d-%m-%Y %H:%M:%S%.3f %:z").to_compact_string()
        }
    } else if time_args.iso_8601 {
        if date_only {
            time.format("%Y-%m-%d").to_compact_string()
        } else {
            time.format("%Y-%m-%dT%H:%M:%S%.fZ").to_compact_string()
        }
    } else if date_only {
        time.format("%Y-%m-%d").to_compact_string()
    } else {
        time.format("%Y-%m-%d %H:%M:%S%.3f %:z").to_compact_string()
    }
}

/// Checks whether the file path already exists; if it does, prints the given alert message and
/// returns true.
pub fn check_file_expect_not_exist(path: &Path, exist_alert_str: String) -> bool {
    let ret = path.exists();
    if ret {
        AlertMessage::alert(&exist_alert_str).ok();
    }
    ret
}

/// Accumulates the given output line into the specified section of the HTML report when the
/// --html-report option is enabled.
pub fn output_and_data_stack_for_html(
    output_str: &str,
    section_name: &str,
    html_report_flag: &bool,
    html_reporter: &mut htmlreport::HtmlReporter,
) {
    if *html_report_flag {
        let mut output_data = Nested::<String>::new();
        output_data.extend(vec![format!("- {output_str}")]);
        html_reporter.add_md_data(section_name, output_data);
    }
}

/// Returns true if `input` contains `check` as a substring. Uses memchr::memmem, which is
/// faster than the standard str::contains.
pub fn contains_str(input: &str, check: &str) -> bool {
    memmem::find(input.as_bytes(), check.as_bytes()).is_some()
}

/// Outputs the active output profile name, either to the terminal or to the HTML report
/// depending on the stdout argument.
pub fn output_profile_name(
    output_option: &Option<OutputOption>,
    stdout: bool,
    no_color: bool,
    html_reporter: &mut htmlreport::HtmlReporter,
) {
    // output profile name
    if let Some(profile_opt) = output_option {
        // Determine the default profile name, preferring config/default_profile_name.txt on
        // disk and falling back to the embedded copy.
        let default_profile_name = if let Ok(name) = read_to_string(
            check_setting_path(
                &CURRENT_EXE_PATH.to_path_buf(),
                "config/default_profile_name.txt",
                true,
            )
            .unwrap()
            .to_str()
            .unwrap(),
        ) {
            name.trim().to_string()
        } else {
            let default_profile_name = DefaultProfileName::get("default_profile_name.txt").unwrap();
            str::from_utf8(default_profile_name.data.as_ref())
                .unwrap_or("n/a")
                .to_string()
        };

        // Use the profile specified by the user, or the default profile name.
        let profile_name = profile_opt
            .profile
            .as_ref()
            .unwrap_or(&default_profile_name);
        if stdout {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(Some(Color::Rgb(0, 255, 0)), no_color),
                "Output profile: ",
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                profile_name,
                true,
            )
            .ok();
        }
        let output_saved_str = format!("Output profile: {profile_name}");
        // The profile name appears at a different position in the terminal output than in the
        // HTML report, so the stdout argument controls which of the two this call produces (the
        // function is called once for each).
        if !stdout && profile_opt.html_report.is_some() {
            html_reporter.add_md_data(
                htmlreport::GENERAL_OVERVIEW_SECTION,
                Nested::from_iter(vec![format!("- {output_saved_str}")]),
            );
        }
    }
}

/// Determines whether a record should be filtered out based on its Computer field and the
/// include_computer/exclude_computer options. Returns true when the record should be skipped.
pub fn is_filtered_by_computer_name(
    record: Option<&Value>,
    (include_computer, exclude_computer): (&HashSet<CompactString>, &HashSet<CompactString>),
) -> bool {
    if let Some(computer_name) = record {
        let computer_str = computer_name.as_str().unwrap_or_default().replace('\"', "");
        if (!include_computer.is_empty() && !include_computer.contains(computer_str.as_str()))
            || (!exclude_computer.is_empty() && exclude_computer.contains(computer_str.as_str()))
        {
            return true;
        }
    }
    false
}

/// Creates an output string in hh:mm:ss.fff format from the given seconds and milliseconds.
/// Both components are negated only when the seconds component is negative; a negative
/// milliseconds value with a zero seconds component is not normalized.
pub fn output_duration((mut s, mut ms): (i64, i64)) -> String {
    if s < 0 {
        s = -s;
        ms = -ms;
    }
    let h = s / 3600;
    s %= 3600;
    let m = s / 60;
    s %= 60;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

/// Sanitizes a field value for single-line output: runs of spaces are collapsed into one, all
/// control characters except `\n`/`\r`/`\t` are removed, and leading/trailing spaces are trimmed.
/// The kept `\n`/`\r`/`\t` are escaped or flattened per output format later — serde_json escapes
/// them in JSON, while the CSV and `search` output paths collapse them to spaces.
///
/// NOTE (#1849): previously `\n`/`\r`/`\t` were replaced here with the `🛂n`/`🛂r`/`🛂t` placeholder
/// sequences and restored/re-escaped by the output code. Keeping them as real characters removed
/// that round-trip, but it is a deliberate BEHAVIOR CHANGE with two effects on JSON output —
/// verified against the full sample-evtx corpus, where CSV output stays byte-identical and JSON
/// differs only by these two things:
///
///   1. An interior newline/tab/CR inside a value now serializes as a proper `\n`/`\t`/`\r` JSON
///      escape (a real newline when the JSON is parsed) instead of the old visible `\\n`/`\\t`/`\\r`
///      two-character text.
///   2. Leading/trailing `\n`/`\r`/`\t` (with the spaces next to them) in a value are now trimmed
///      away: this function preserves them, but the downstream `.trim()` calls in the JSON
///      `Details` grouping now see real whitespace instead of the opaque `🛂` placeholders that
///      used to survive them. No interior content is lost.
///
/// CSV/`search` output is unchanged (control characters are still collapsed to a space). If either
/// effect was actually relied on — e.g. a downstream consumer expected the visible `\\n` text, or
/// expected leading/trailing newlines to be preserved — this will need to be reverted to the
/// placeholder approach; see issue #1849.
pub fn remove_sp_char(record_value: CompactString) -> CompactString {
    let mut cleaned: String = record_value.into();
    let mut prev = 'a';
    cleaned.retain(|ch| {
        // Collapse runs of spaces and drop every control character except `\n`/`\r`/`\t`, which
        // are kept and handled per output format later.
        let drop = (prev == ' ' && ch == ' ')
            || (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t');
        if !drop {
            prev = ch;
        }
        !drop
    });
    // Trim only spaces so any leading/trailing `\n`/`\r`/`\t` are preserved (the previous code
    // kept them because they were opaque `🛂` placeholders at that point).
    cleaned.trim_matches(' ').into()
}

/// Returns the size of the file in bytes, or 0 if its metadata cannot be read (in which case a
/// warning is shown and/or stacked depending on the verbose and quiet-errors flags).
pub fn get_file_size(
    file_path: &Path,
    verbose_flag: bool,
    quiet_errors_flag: bool,
    error_log_stack: &Mutex<Nested<String>>,
) -> u64 {
    match fs::metadata(file_path) {
        Ok(res) => res.len(),
        Err(err) => {
            if verbose_flag {
                AlertMessage::warn(&err.to_string()).ok();
            }
            if !quiet_errors_flag {
                error_log_stack
                    .lock()
                    .unwrap()
                    .push(format!("[WARN] {err}"));
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::NaiveDate;
    use compact_str::CompactString;
    use hashbrown::{HashMap, HashSet};
    use nested::Nested;
    use regex::Regex;
    use serde_json::Value;

    use super::{output_duration, output_profile_name};
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::{
        detections::{
            configs::{Action, Config, CsvOutputOption, OutputOption, StoredStatic},
            utils::{self, check_setting_path, make_ascii_titlecase},
        },
        options::htmlreport::{GENERAL_OVERVIEW_SECTION, HtmlReporter, RESULTS_SUMMARY_SECTION},
    };

    #[test]
    fn test_create_recordinfos() {
        let record_json_str = r#"
        {
            "Event": {
                "System": {"EventID": 4103, "Channel": "PowerShell", "Computer":"DESKTOP-ICHIICHI"},
                "UserData": {"User": "u1", "AccessMask": "%%1369", "Process":"lsass.exe"},
                "UserData_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let ret = utils::create_recordinfos(&record, &FieldDataMapKey::default(), &None);
                // Event.System is excluded, xmlns keys are excluded (which removes the
                // *_attributes objects here), and the output is sorted by key.
                let expected = "AccessMask: %%1369 ¦ Process: lsass.exe ¦ User: u1".to_string();
                assert_eq!(ret.join(" ¦ "), expected);
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_create_recordinfos2() {
        // Special case for EventData.
        let record_json_str = r#"
        {
            "Event": {
                "System": {"EventID": 4103, "Channel": "PowerShell", "Computer":"DESKTOP-ICHIICHI"},
                "EventData": {
                    "Binary": "hogehoge",
                    "Data":[
                        "Data1",
                        "DataData2",
                        "",
                        "DataDataData3"
                    ]
                },
                "EventData_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let ret = utils::create_recordinfos(&record, &FieldDataMapKey::default(), &None);
                // Event.System is excluded, xmlns keys are excluded (which removes the
                // *_attributes objects here), and the output is sorted by key.
                let expected = "Binary: hogehoge ¦ Data[1]: Data1 ¦ Data[2]: DataData2 ¦ Data[3]:  ¦ Data[4]: DataDataData3"
                    .to_string();
                assert_eq!(ret.join(" ¦ "), expected);
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_check_regex() {
        let regexes: Vec<Regex> =
            utils::read_txt("test_files/config/regex/detectlist_suspicous_services.txt")
                .unwrap()
                .iter()
                .map(|regex_str| Regex::new(regex_str).unwrap())
                .collect();
        let regextext = utils::check_regex("\\cvtres.exe", &regexes);
        assert!(regextext);

        let regextext = utils::check_regex("\\hogehoge.exe", &regexes);
        assert!(!regextext);
    }

    #[test]
    fn test_check_allowlist() {
        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"";
        let allowlist: Vec<Regex> =
            utils::read_txt("test_files/config/regex/allowlist_legitimate_services.txt")
                .unwrap()
                .iter()
                .map(|allow_str| Regex::new(allow_str).unwrap())
                .collect();
        assert!(utils::check_allowlist(commandline, &allowlist));

        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate2.exe\"";
        assert!(!utils::check_allowlist(commandline, &allowlist));
    }

    #[test]
    /// Test to verify that numeric type values of Serde::Value are returned as strings.
    fn test_get_serde_number_to_string() {
        let json_str = r#"
        {
            "Event": {
                "System": {
                    "EventID": 11111
                }
            }
        }
        "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(
            utils::get_serde_number_to_string(&event_record["Event"]["System"]["EventID"], false),
            Some(CompactString::from("11111"))
        );
    }

    #[test]
    /// Test to verify that string type values of Serde::Value are returned as strings.
    fn test_get_serde_number_serde_string_to_string() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(
            utils::get_serde_number_to_string(
                &event_record["Event"]["EventData"]["ComputerName"],
                false
            )
            .unwrap(),
            "HayabusaComputer1".to_owned()
        );
    }

    #[test]
    /// Test to verify that None is returned when object type contents of Serde::Value are incorrectly passed.
    fn test_get_serde_number_serde_object_ret_none() {
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert!(
            utils::get_serde_number_to_string(&event_record["Event"]["EventData"], false).is_none()
        );
    }

    #[test]
    /// Test for the function that capitalizes ASCII characters when given a string.
    fn test_make_ascii_titlecase() {
        assert_eq!(make_ascii_titlecase("aaaa".to_string().as_mut()), "Aaaa");
        assert_eq!(
            make_ascii_titlecase("i am Test".to_string().as_mut()),
            "I am Test"
        );
        assert_eq!(make_ascii_titlecase("β".to_string().as_mut()), "β");
    }

    #[test]
    /// Test to verify that file existence can be confirmed from the given path.
    fn test_check_setting_path() {
        let exist_path = Path::new("./test_files").to_path_buf();
        let not_exist_path = Path::new("not_exist_path").to_path_buf();
        assert_eq!(
            check_setting_path(&not_exist_path, "rules", true)
                .unwrap()
                .to_str()
                .unwrap(),
            "rules"
        );
        assert_eq!(
            check_setting_path(&not_exist_path, "fake", true)
                .unwrap()
                .to_str()
                .unwrap(),
            "fake"
        );
        assert_eq!(
            check_setting_path(&exist_path, "rules", true)
                .unwrap()
                .to_str()
                .unwrap(),
            exist_path.join("rules").to_str().unwrap()
        );
        assert_eq!(
            check_setting_path(&exist_path, "fake", true)
                .unwrap()
                .to_str()
                .unwrap(),
            "fake"
        );
    }

    #[test]
    fn test_json_array_file_to_serde_json_value() {
        // Non-existent paths return Err.
        let r = utils::read_json_to_value("invalid path");
        assert!(r.is_err());

        // Verify that JSON (Array) format can be converted.
        let path = "test_files/evtx/test.json";
        let records = utils::read_json_to_value(path).unwrap();
        let records: Vec<Value> = records.into_iter().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:26.493Z"
        );
        assert_eq!(
            records[1]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:30.540Z"
        );
    }

    #[test]
    fn test_jsonl_file_to_serde_json_value() {
        // Non-existent paths return Err.
        let r = utils::read_jsonl_to_value("invalid path");
        assert!(r.is_err());
        // JSON (Array) format formatted with newlines also returns Err.
        let r = utils::read_jsonl_to_value("test_files/evtx/test.json");
        assert!(r.is_err());

        // Verify that JSONL format can be converted.
        let path = "test_files/evtx/test.jsonl";
        let records = utils::read_jsonl_to_value(path).unwrap();
        let records: Vec<Value> = records.into_iter().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:26.493Z"
        );
        assert_eq!(
            records[1]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:30.540Z"
        );
    }

    #[test]
    fn test_jq_c_file_to_serde_json_value() {
        // Non-existent paths return Err.
        let r = utils::read_json_to_value("invalid path");
        assert!(r.is_err());

        // Verify that the JSON format of jq command output can be converted.
        let path = "test_files/evtx/test-jq-output.json";
        let records = utils::read_json_to_value(path).unwrap();
        let records: Vec<Value> = records.into_iter().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:26.493Z"
        );
        assert_eq!(
            records[1]["Event"]["EventData"]["@timestamp"],
            "2020-05-02T02:55:30.540Z"
        );
    }

    #[test]
    fn test_output_profile() {
        let mut html_reporter = HtmlReporter::default();
        let stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    profile: Some("super-verbose".to_string()),
                    min_level: "informational".to_string(),
                    html_report: Some(Path::new("dummy.html").to_path_buf()),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            ..Default::default()
        }));
        output_profile_name(
            &stored_static.output_option,
            true,
            false,
            &mut html_reporter,
        );
        output_profile_name(
            &stored_static.output_option,
            false,
            false,
            &mut html_reporter,
        );
        let expect: HashMap<&str, Nested<String>> = HashMap::from_iter(vec![
            (RESULTS_SUMMARY_SECTION, Nested::new()),
            (
                GENERAL_OVERVIEW_SECTION,
                Nested::from_iter(vec!["- Output profile: super-verbose"]),
            ),
        ]);
        for (k, v) in html_reporter.section_markdown.iter() {
            assert!(expect.keys().any(|x| x == k));
            assert!(expect.values().any(|y| y == v));
        }
    }

    #[test]
    /// Test to verify that filtering is performed based on the Computer value.
    fn test_is_filtered_by_computer_name() {
        let json_str = r#"
        {
            "Event": {
                "System": {
                    "Computer": "HayabusaComputer1"
                }
            }
        }
        "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        // If include_computer and exclude_computer are not specified, filtering is not performed.
        assert!(!utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (&HashSet::new(), &HashSet::new()),
        ));

        // If there is no computer name information in the record, filtering is not performed.
        assert!(!utils::is_filtered_by_computer_name(
            None,
            (&HashSet::new(), &HashSet::new()),
        ));

        // If there is no match with include_computer, filtering is performed.
        assert!(utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::from_iter(vec!["Hayabusa".into()]),
                &HashSet::new()
            ),
        ));

        // If there is a match with include_computer, filtering is not performed.
        assert!(!utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::from_iter(vec!["HayabusaComputer1".into()]),
                &HashSet::new()
            ),
        ));

        // If there is a match with exclude_computer, filtering is performed.
        assert!(utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::new(),
                &HashSet::from_iter(vec!["HayabusaComputer1".into()]),
            ),
        ));
    }

    #[test]
    /// Test for the function that creates an output string from a Duration.
    fn test_output_duration() {
        let time1 = NaiveDate::from_ymd_opt(2021, 12, 26)
            .unwrap()
            .and_hms_milli_opt(2, 34, 49, 0)
            .unwrap();
        let time2 = NaiveDate::from_ymd_opt(2021, 12, 25)
            .unwrap()
            .and_hms_milli_opt(1, 23, 45, 678)
            .unwrap();
        let duration = time1 - time2;
        let s = duration.num_seconds();
        let ms = duration.num_milliseconds() - 1000 * s;

        assert_eq!(output_duration((s, ms)), "25:11:03.322".to_string());

        let duration = time2 - time1;
        let s = duration.num_seconds();
        let ms = duration.num_milliseconds() - 1000 * s;
        assert_eq!(output_duration((s, ms)), "25:11:03.322".to_string());
    }
}

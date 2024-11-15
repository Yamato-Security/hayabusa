extern crate base64;
extern crate csv;
extern crate regex;

use std::cmp::Ordering;
use std::fs::{read_to_string, File};
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str;
use std::string::String;
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
use serde_json::{json, Error, Map, Value};
use termcolor::{BufferWriter, ColorSpec, WriteColor};
use termcolor::{Color, ColorChoice};
use tokio::runtime::{Builder, Runtime};

use crate::detections::configs::{TimeFormatOptions, CURRENT_EXE_PATH, ONE_CONFIG_MAP};
use crate::detections::field_data_map::{convert_field_data, FieldDataMap, FieldDataMapKey};
use crate::detections::field_extract::extract_fields;
use crate::options::htmlreport;

use super::configs::{EventKeyAliasConfig, OutputOption, STORED_EKEY_ALIAS};
use super::detection::EvtxRecordInfo;
use super::message::AlertMessage;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "config"]
#[include = "default_profile_name.txt"]
pub struct DefaultProfileName;

pub fn concat_selection_key(key_list: &Nested<String>) -> String {
    return key_list
        .iter()
        .fold("detection -> selection".to_string(), |mut acc, cur| {
            acc = acc + " -> " + cur;
            acc
        });
}

pub fn check_regex(string: &str, regex_list: &[Regex]) -> bool {
    for regex in regex_list {
        if !regex.is_match(string) {
            continue;
        }

        return true;
    }

    false
}

pub fn check_allowlist(target: &str, regexes: &[Regex]) -> bool {
    for regex in regexes {
        if regex.is_match(target) {
            return true;
        }
    }

    false
}

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

/// convert jsonl fmt string to serde_json Value iterator
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

/// convert json fmt string to serde_json Value iterator
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
            // JSON(Array)形式の場合
            let ret = values.into_iter().map(value_converter);
            Ok(Box::new(ret))
        }
        Err(_) => {
            // jq形式の場合
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

pub fn get_event_time() -> String {
    "Event.System.TimeCreated_attributes.SystemTime".to_string()
}

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

/// serde:Valueの型を確認し、文字列を返します。
pub fn get_serde_number_to_string(
    value: &serde_json::Value,
    search_flag: bool,
) -> Option<CompactString> {
    if value.is_string() {
        let val_str = value.as_str().unwrap_or("");
        if val_str.ends_with(',') {
            Some(CompactString::from(val_str))
        } else {
            Option::Some(CompactString::from(val_str))
        }
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
        // Object type is not specified record value.
        Option::None
    } else {
        Some(CompactString::from(value.to_string()))
    }
}

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
        // get_event_keyが取得できてget_event_key_splitが取得できないことはないため、unwrapのチェックは行わない
        let splits = eventkey_alias.get_event_key_split(key);
        let mut start_idx = 0;
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

// EvtxRecordInfoを作成します。
pub fn create_rec_info(
    mut data: Value,
    path: String,
    keys: &Nested<String>,
    recovered_record: &bool,
    no_pwsh_field_extraction: &bool,
) -> EvtxRecordInfo {
    // 高速化のための処理

    // 例えば、Value型から"Event.System.EventID"の値を取得しようとすると、value["Event"]["System"]["EventID"]のように3回アクセスする必要がある。
    // この処理を高速化するため、rec.key_2_valueというhashmapに"Event.System.EventID"というキーで値を設定しておく。
    // これなら、"Event.System.EventID"というキーを1回指定するだけで値を取得できるようになるので、高速化されるはず。
    // あと、serde_jsonのValueからvalue["Event"]みたいな感じで値を取得する処理がなんか遅いので、そういう意味でも早くなるかも
    // それと、serde_jsonでは内部的に標準ライブラリのhashmapを使用しているが、hashbrownを使った方が早くなるらしい。標準ライブラリがhashbrownを採用したためserde_jsonについても高速化した。
    let mut key_2_values = HashMap::new();

    let binding = STORED_EKEY_ALIAS.read().unwrap();
    let eventkey_alias = binding.as_ref().unwrap();
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
        key_2_values.insert(key.to_string(), val.unwrap());
    }
    if !*no_pwsh_field_extraction {
        extract_fields(channel, event_id, &mut data, &mut key_2_values);
    }

    // EvtxRecordInfoを作る
    let data_str = data.to_string();

    EvtxRecordInfo {
        evtx_filepath: path,
        record: data,
        data_string: data_str,
        key_2_value: key_2_values,
        recovered_record: *recovered_record,
    }
}

/**
 * 標準出力のカラー出力設定を指定した値に変更し画面出力を行う関数
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

/// no-colorのオプションの指定があるかを確認し、指定されている場合はNoneをかえし、指定されていない場合は引数で指定されたColorをSomeでラップして返す関数
pub fn get_writable_color(color: Option<Color>, no_color: bool) -> Option<Color> {
    if no_color {
        None
    } else {
        color
    }
}

/**
 * CSVのrecord infoカラムに出力する文字列を作る
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
    // 同じレコードなら毎回同じ出力になるようにソートしておく
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
            if let Some(map) = field_data_map.as_ref() {
                if let Some(converted_str) =
                    convert_field_data(map, field_data_map_key, &key.to_lowercase(), value, record)
                {
                    let val = remove_sp_char(converted_str);
                    return format!("{key}: {val}",).into();
                }
            }
            let val = remove_sp_char(value.into());
            format!("{key}: {val}").into()
        })
        .collect()
}

/**
 * CSVのfieldsカラムに出力する要素を全て収集する
 */
fn _collect_recordinfo<'a>(
    keys: &mut Vec<&'a str>,
    parent_key: &'a str,
    arr_index: i8,
    org_value: &'a Value,
    cur_value: &'a Value,
    output: &mut HashSet<(String, String)>,
    filed_data_converter: (&Option<FieldDataMap>, &FieldDataMapKey),
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
                    filed_data_converter,
                );
            }
        }
        Value::Object(obj) => {
            // lifetimeの関係でちょっと変な実装になっている
            if !parent_key.is_empty() {
                keys.push(parent_key);
            }
            for (key, value) in obj {
                if key.eq("xmlns") {
                    continue;
                }
                // Event.Systemは出力しない
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
                    filed_data_converter,
                );
            }
            if !parent_key.is_empty() {
                keys.pop();
            }
        }
        Value::Null => (),
        _ => {
            // 一番子の要素の値しか収集しない
            let strval = value_to_string(cur_value);
            if let Some(strval) = strval {
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
                let key = if arr_index >= 0 {
                    let (field_data_map, field_data_map_key) = filed_data_converter;
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
 * 最初の文字を大文字にする関数
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

/// base_path/path が存在するかを確認し、存在しなければカレントディレクトリを参照するpathを返す関数
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

/// rule configのファイルの所在を確認する関数。
pub fn check_rule_config(config_path: &PathBuf) -> Result<(), String> {
    // 各種ファイルを確認する
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

    // rules/configのフォルダが存在するかを確認する
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

///タイムゾーンに合わせた情報を情報を取得する関数
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

/// return rfc time format string by option
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

/// Check file path exist. If path is existed, output alert message.
pub fn check_file_expect_not_exist(path: &Path, exist_alert_str: String) -> bool {
    let ret = path.exists();
    if ret {
        AlertMessage::alert(&exist_alert_str).ok();
    }
    ret
}

pub fn output_and_data_stack_for_html(
    output_str: &str,
    section_name: &str,
    html_report_flag: &bool,
) {
    if *html_report_flag {
        let mut output_data = Nested::<String>::new();
        output_data.extend(vec![format!("- Elapsed time: {output_str}")]);
        htmlreport::add_md_data(section_name, output_data);
    }
}

pub fn contains_str(input: &str, check: &str) -> bool {
    memmem::find(input.as_bytes(), check.as_bytes()).is_some()
}

pub fn output_profile_name(output_option: &Option<OutputOption>, stdout: bool, no_color: bool) {
    // output profile name
    if let Some(profile_opt) = output_option {
        // default profile name check
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

        // user input profile option
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
        // profileの表示位置とHTMLの出力順が異なるため引数で管理をした
        if !stdout && profile_opt.html_report.is_some() {
            htmlreport::add_md_data(
                "General Overview {#general_overview}",
                Nested::from_iter(vec![format!("- {output_saved_str}")]),
            );
        }
    }
}

/// コンピュータ名がフィルタリング対象であるかを判定する関数
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

///指定された秒数とミリ秒数から出力文字列を作成する関数。絶対値での秒数から算出してhh:mm:ss.fffの形式で出力する。
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

pub fn remove_sp_char(record_value: CompactString) -> CompactString {
    let mut newline_replaced_cs: String = record_value
        .replace('\n', "🛂n")
        .replace('\r', "🛂r")
        .replace('\t', "🛂t");
    let mut prev = 'a';
    newline_replaced_cs.retain(|ch| {
        let retain_flag = (prev == ' ' && ch == ' ') || ch.is_control();
        if !retain_flag {
            prev = ch;
        }
        !retain_flag
    });
    newline_replaced_cs.trim().into()
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
    use crate::detections::configs::TimeFormatOptions;
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::{
        detections::{
            configs::{
                Action, CommonOptions, Config, CsvOutputOption, DetectCommonOption, InputOption,
                OutputOption, StoredStatic,
            },
            utils::{self, check_setting_path, make_ascii_titlecase},
        },
        options::htmlreport::HTML_REPORTER,
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
                // Systemは除外される/属性(_attributesも除外される)/key順に並ぶ
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
        // EventDataの特殊ケース
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
                // Systemは除外される/属性(_attributesも除外される)/key順に並ぶ
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
    /// Serde::Valueの数値型の値を文字列として返却することを確かめるテスト
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
    /// Serde::Valueの文字列型の値を文字列として返却することを確かめるテスト
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
    /// Serde::Valueのオブジェクト型の内容を誤って渡した際にNoneを返却することを確かめるテスト
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
    /// 文字列を与えてascii文字を大文字にするように対応する関数のテスト
    fn test_make_ascii_titlecase() {
        assert_eq!(make_ascii_titlecase("aaaa".to_string().as_mut()), "Aaaa");
        assert_eq!(
            make_ascii_titlecase("i am Test".to_string().as_mut()),
            "I am Test"
        );
        assert_eq!(make_ascii_titlecase("β".to_string().as_mut()), "β");
    }

    #[test]
    /// 与えられたパスからファイルの存在確認ができているかのテスト
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
        // 存在しないパスはErr
        let r = utils::read_json_to_value("invalid path");
        assert!(r.is_err());

        // JSON(Array)形式を変換できること
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
        // 存在しないパスはErr
        let r = utils::read_jsonl_to_value("invalid path");
        assert!(r.is_err());
        // 改行でフォーマットされたJSON(Array)形式もErr
        let r = utils::read_jsonl_to_value("test_files/evtx/test.json");
        assert!(r.is_err());

        // JSONL形式を変換できること
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
        // 存在しないパスはErr
        let r = utils::read_json_to_value("invalid path");
        assert!(r.is_err());

        // jqコマンド出力結果のJSON形式を変換できること
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
        HTML_REPORTER.write().unwrap().md_datas.clear();
        let stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        time_offset: None,
                    },
                    profile: Some("super-verbose".to_string()),
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    exact_level: None,
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    time_format_options: TimeFormatOptions {
                        european_time: false,
                        iso_8601: false,
                        rfc_2822: false,
                        rfc_3339: false,
                        us_military_time: false,
                        us_time: false,
                        utc: false,
                    },
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: Some(Path::new("dummy.html").to_path_buf()),
                    no_summary: false,
                    common_options: CommonOptions {
                        no_color: false,
                        quiet: false,
                        help: None,
                    },
                    detect_common_options: DetectCommonOption {
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                        json_input: false,
                        include_computer: None,
                        exclude_computer: None,
                    },
                    enable_unsupported_rules: false,
                    clobber: false,
                    proven_rules: false,
                    include_tag: None,
                    exclude_tag: None,
                    include_category: None,
                    exclude_category: None,
                    include_eid: None,
                    exclude_eid: None,
                    no_field: false,
                    no_pwsh_field_extraction: false,
                    remove_duplicate_data: false,
                    remove_duplicate_detections: false,
                    no_wizard: true,
                    include_status: None,
                    sort_events: false,
                    enable_all_rules: false,
                    scan_all_evtx_files: false,
                },
                geo_ip: None,
                output: None,
                multiline: false,
                disable_abbreviations: false,
            })),
            debug: false,
        }));
        output_profile_name(&stored_static.output_option, true, false);
        output_profile_name(&stored_static.output_option, false, false);
        let expect: HashMap<&str, Nested<String>> = HashMap::from_iter(vec![
            ("Results Summary {#results_summary}", Nested::new()),
            (
                "General Overview {#general_overview}",
                Nested::from_iter(vec!["- Output profile: super-verbose"]),
            ),
        ]);
        for (k, v) in HTML_REPORTER.read().unwrap().md_datas.iter() {
            assert!(expect.keys().any(|x| x == k));
            assert!(expect.values().any(|y| y == v));
        }
    }

    #[test]
    /// Computerの値をもとにフィルタリングされることを確認するテスト
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

        // include_computer, exclude_computerが指定されていない場合はフィルタリングされない
        assert!(!utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (&HashSet::new(), &HashSet::new()),
        ));

        // recordのコンピュータ名の情報がない場合はフィルタリングされない
        assert!(!utils::is_filtered_by_computer_name(
            None,
            (&HashSet::new(), &HashSet::new()),
        ));

        // include_computerで合致しない場合フィルタリングされる
        assert!(utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::from_iter(vec!["Hayabusa".into()]),
                &HashSet::new()
            ),
        ));

        // include_computerで合致する場合フィルタリングされない
        assert!(!utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::from_iter(vec!["HayabusaComputer1".into()]),
                &HashSet::new()
            ),
        ));

        // exclude_computerで合致する場合フィルタリングされる
        assert!(utils::is_filtered_by_computer_name(
            Some(&event_record["Event"]["System"]["Computer"]),
            (
                &HashSet::new(),
                &HashSet::from_iter(vec!["HayabusaComputer1".into()]),
            ),
        ));
    }

    #[test]
    /// Durationから出力文字列を作成する関数のテスト
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

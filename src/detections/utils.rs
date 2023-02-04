extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs::CURRENT_EXE_PATH;
use crate::options::htmlreport;

use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use nested::Nested;
use std::path::{Path, PathBuf};

use chrono::Local;
use termcolor::{Color, ColorChoice};

use tokio::runtime::{Builder, Runtime};

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::str;
use std::string::String;
use std::vec;
use termcolor::{BufferWriter, ColorSpec, WriteColor};

use super::configs::{Config, EventKeyAliasConfig, OutputOption, STORED_EKEY_ALIAS};
use super::detection::EvtxRecordInfo;
use super::message::AlertMessage;

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
    let f = File::open(filepath);
    if f.is_err() {
        let errmsg = format!("Cannot open file. [file:{filename}]");
        return Result::Err(errmsg);
    }
    let reader = BufReader::new(f.unwrap());
    Result::Ok(Nested::from_iter(
        reader.lines().map(|line| line.unwrap_or_default()),
    ))
}

/// convert json fmt string to serde_json Value.
pub fn read_json_to_value(filename: &str) -> Result<impl Iterator<Item = Value>, String> {
    let filepath = if filename.starts_with("./") {
        check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), filename, true)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    } else {
        filename.to_string()
    };
    let f = File::open(filepath);
    if f.is_err() {
        let errmsg = format!("Cannot open file. [file:{filename}]");
        return Result::Err(errmsg);
    }
    let reader = BufReader::new(f.unwrap());
    let ret = reader
        .lines()
        .into_iter()
        .filter_map(|s| s.ok())
        .filter(|s| !s.trim().is_empty())
        .map(|line| {
            let v: Value = serde_json::from_str(&line).unwrap();
            json!({"Event":{"EventData": v}})
        });
    Result::Ok(ret)
}

pub fn read_csv(filename: &str) -> Result<Nested<Vec<String>>, String> {
    let f = File::open(filename);
    if f.is_err() {
        return Result::Err(format!("Cannot open file. [file:{filename}]"));
    }
    let mut contents: String = String::new();
    let mut ret = Nested::<Vec<String>>::new();
    let read_res = f.unwrap().read_to_string(&mut contents);
    if let Err(e) = read_res {
        return Result::Err(e.to_string());
    }

    let mut rdr = csv::ReaderBuilder::new().from_reader(contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    Result::Ok(ret)
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
pub fn get_serde_number_to_string(value: &serde_json::Value) -> Option<CompactString> {
    if value.is_string() {
        let val_str = value.as_str().unwrap_or("");
        if val_str.ends_with(',') {
            Some(CompactString::from(val_str.strip_suffix(',').unwrap()))
        } else {
            Option::Some(CompactString::from(val_str))
        }
    } else if value.is_object() || value.is_null() {
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
        let event_key = if !key.contains('.') {
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
    let cpu_num = num_cpus::get();
    thread_number.unwrap_or(cpu_num)
}

pub fn create_tokio_runtime(thread_number: Option<usize>) -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(get_thread_num(thread_number))
        .thread_name("hayabusa-thread")
        .build()
        .unwrap()
}

// EvtxRecordInfoを作成します。
pub fn create_rec_info(data: Value, path: String, keys: &Nested<String>) -> EvtxRecordInfo {
    // 高速化のための処理

    // 例えば、Value型から"Event.System.EventID"の値を取得しようとすると、value["Event"]["System"]["EventID"]のように3回アクセスする必要がある。
    // この処理を高速化するため、rec.key_2_valueというhashmapに"Event.System.EventID"というキーで値を設定しておく。
    // これなら、"Event.System.EventID"というキーを1回指定するだけで値を取得できるようになるので、高速化されるはず。
    // あと、serde_jsonのValueからvalue["Event"]みたいな感じで値を取得する処理がなんか遅いので、そういう意味でも早くなるかも
    // それと、serde_jsonでは内部的に標準ライブラリのhashmapを使用しているが、hashbrownを使った方が早くなるらしい。標準ライブラリがhashbrownを採用したためserde_jsonについても高速化した。
    let mut key_2_values = HashMap::new();

    let binding = STORED_EKEY_ALIAS.read().unwrap();
    let eventkey_alias = binding.as_ref().unwrap();
    for key in keys.iter() {
        let val = get_event_value(key, &data, eventkey_alias);
        if val.is_none() {
            continue;
        }

        let val = value_to_string(val.unwrap());
        if val.is_none() {
            continue;
        }

        key_2_values.insert(key.to_string(), val.unwrap());
    }

    // EvtxRecordInfoを作る
    let data_str = data.to_string();

    EvtxRecordInfo {
        evtx_filepath: path,
        record: data,
        data_string: data_str,
        key_2_value: key_2_values,
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
pub fn get_writable_color(color: Option<Color>, config: &Config) -> Option<Color> {
    if config.no_color {
        None
    } else {
        color
    }
}

/**
 * CSVのrecord infoカラムに出力する文字列を作る
 */
pub fn create_recordinfos(record: &Value) -> String {
    let mut output = HashSet::new();
    _collect_recordinfo(&mut vec![], "", record, &mut output);

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
            if value.ends_with(',') {
                format!("{}: {}", key, &value[..value.len() - 1])
            } else {
                format!("{key}: {value}")
            }
        })
        .join(" ¦ ")
}

/**
 * CSVのfieldsカラムに出力する要素を全て収集する
 */
fn _collect_recordinfo<'a>(
    keys: &mut Vec<&'a str>,
    parent_key: &'a str,
    value: &'a Value,
    output: &mut HashSet<(String, String)>,
) {
    match value {
        Value::Array(ary) => {
            for sub_value in ary {
                _collect_recordinfo(keys, parent_key, sub_value, output);
            }
        }
        Value::Object(obj) => {
            // lifetimeの関係でちょっと変な実装になっている
            if !parent_key.is_empty() {
                keys.push(parent_key);
            }
            for (key, value) in obj {
                // 属性は出力しない
                if key.ends_with("_attributes") {
                    continue;
                }
                // Event.Systemは出力しない
                if key.eq("System") && keys.first().unwrap_or(&"").eq(&"Event") {
                    continue;
                }

                _collect_recordinfo(keys, key, value, output);
            }
            if !parent_key.is_empty() {
                keys.pop();
            }
        }
        Value::Null => (),
        _ => {
            // 一番子の要素の値しか収集しない
            let strval = value_to_string(value);
            if let Some(strval) = strval {
                let strval = strval.trim().chars().fold(String::default(), |mut acc, c| {
                    if c.is_control() || c.is_ascii_whitespace() {
                        acc.push(' ');
                    } else {
                        acc.push(c);
                    };
                    acc
                });
                output.insert((parent_key.to_string(), strval));
            }
        }
    }
}

/**
 * 最初の文字を大文字にする関数
 */
pub fn make_ascii_titlecase(s: &str) -> CompactString {
    let mut c = s.chars();
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
    if base_path.join(path).exists() {
        Some(base_path.join(path))
    } else if ignore_err {
        Some(Path::new(path).to_path_buf())
    } else {
        None
    }
}

/// rule configのファイルの所在を確認する関数。
pub fn check_rule_config(config_path: &PathBuf) -> Result<(), String> {
    // rules/configのフォルダが存在するかを確認する
    let exist_rule_config_folder = if config_path == &CURRENT_EXE_PATH.to_path_buf() {
        check_setting_path(config_path, "rules/config", false).is_some()
    } else {
        check_setting_path(config_path, "", false).is_some()
    };
    if !exist_rule_config_folder {
        return Err("The required rules and config files were not found. Please download them with the update-rules command.".to_string());
    }

    // 各種ファイルを確認する
    let files = vec![
        "channel_abbreviations.txt",
        "target_event_IDs.txt",
        "default_details.txt",
        "level_tuning.txt",
        "event_id_info.txt",
        "eventkey_alias.txt",
    ];
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
pub fn format_time(time: &DateTime<Utc>, date_only: bool, output_option: &OutputOption) -> String {
    if output_option.utc || output_option.iso_8601 {
        format_rfc(time, date_only, output_option)
    } else {
        format_rfc(&time.with_timezone(&Local), date_only, output_option)
    }
}

/// return rfc time format string by option
fn format_rfc<Tz: TimeZone>(
    time: &DateTime<Tz>,
    date_only: bool,
    time_args: &OutputOption,
) -> String
where
    Tz::Offset: std::fmt::Display,
{
    if time_args.rfc_2822 {
        if date_only {
            time.format("%a, %e %b %Y").to_string()
        } else {
            time.format("%a, %e %b %Y %H:%M:%S %:z").to_string()
        }
    } else if time_args.rfc_3339 {
        if date_only {
            time.format("%Y-%m-%d").to_string()
        } else {
            time.format("%Y-%m-%d %H:%M:%S%.6f%:z").to_string()
        }
    } else if time_args.us_time {
        if date_only {
            time.format("%m-%d-%Y").to_string()
        } else {
            time.format("%m-%d-%Y %I:%M:%S%.3f %p %:z").to_string()
        }
    } else if time_args.us_military_time {
        if date_only {
            time.format("%m-%d-%Y").to_string()
        } else {
            time.format("%m-%d-%Y %H:%M:%S%.3f %:z").to_string()
        }
    } else if time_args.european_time {
        if date_only {
            time.format("%d-%m-%Y").to_string()
        } else {
            time.format("%d-%m-%Y %H:%M:%S%.3f %:z").to_string()
        }
    } else if time_args.iso_8601 {
        if date_only {
            time.format("%Y-%m-%d").to_string()
        } else {
            time.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
        }
    } else if date_only {
        time.format("%Y-%m-%d").to_string()
    } else {
        time.format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string()
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
    html_report_flag: bool,
) {
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        None,
        output_str,
        true,
    )
    .ok();

    if html_report_flag {
        let mut output_data = Nested::<String>::new();
        output_data.extend(vec![format!("- {output_str}")]);
        htmlreport::add_md_data(section_name, output_data);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::detections::utils::{self, check_setting_path, make_ascii_titlecase};
    use compact_str::CompactString;
    use regex::Regex;
    use serde_json::Value;

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
                let ret = utils::create_recordinfos(&record);
                // Systemは除外される/属性(_attributesも除外される)/key順に並ぶ
                let expected = "AccessMask: %%1369 ¦ Process: lsass.exe ¦ User: u1".to_string();
                assert_eq!(ret, expected);
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
                let ret = utils::create_recordinfos(&record);
                // Systemは除外される/属性(_attributesも除外される)/key順に並ぶ
                let expected = "Binary: hogehoge ¦ Data:  ¦ Data: Data1 ¦ Data: DataData2 ¦ Data: DataDataData3"
                    .to_string();
                assert_eq!(ret, expected);
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_check_regex() {
        let regexes: Vec<Regex> =
            utils::read_txt("rules/config/regex/detectlist_suspicous_services.txt")
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
            utils::read_txt("rules/config/regex/allowlist_legitimate_services.txt")
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
        let json_str = r##"
        {
            "Event": {
                "System": {
                    "EventID": 11111
                }
            }
        }
        "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(
            utils::get_serde_number_to_string(&event_record["Event"]["System"]["EventID"]),
            Some(CompactString::from("11111"))
        );
    }

    #[test]
    /// Serde::Valueの文字列型の値を文字列として返却することを確かめるテスト
    fn test_get_serde_number_serde_string_to_string() {
        let json_str = r##"
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert_eq!(
            utils::get_serde_number_to_string(&event_record["Event"]["EventData"]["ComputerName"])
                .unwrap(),
            "HayabusaComputer1".to_owned()
        );
    }

    #[test]
    /// Serde::Valueのオブジェクト型の内容を誤って渡した際にNoneを返却することを確かめるテスト
    fn test_get_serde_number_serde_object_ret_none() {
        let json_str = r##"
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();

        assert!(utils::get_serde_number_to_string(&event_record["Event"]["EventData"]).is_none());
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
}

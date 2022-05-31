extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs;
use termcolor::Color;

use tokio::runtime::Builder;
use tokio::runtime::Runtime;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::Value;
use std::cmp::Ordering;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::str;
use std::string::String;
use std::vec;
use termcolor::{BufferWriter, ColorSpec, WriteColor};

use super::detection::EvtxRecordInfo;

pub fn concat_selection_key(key_list: &[String]) -> String {
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

pub fn read_txt(filename: &str) -> Result<Vec<String>, String> {
    let f = File::open(filename);
    if f.is_err() {
        let errmsg = format!("Cannot open file. [file:{}]", filename);
        return Result::Err(errmsg);
    }
    let reader = BufReader::new(f.unwrap());
    Result::Ok(
        reader
            .lines()
            .map(|line| line.unwrap_or_default())
            .collect(),
    )
}

pub fn read_csv(filename: &str) -> Result<Vec<Vec<String>>, String> {
    let f = File::open(filename);
    if f.is_err() {
        return Result::Err(format!("Cannot open file. [file:{}]", filename));
    }
    let mut contents: String = String::new();
    let mut ret = vec![];
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

pub fn is_target_event_id(s: &str) -> bool {
    configs::CONFIG.read().unwrap().target_eventids.is_target(s)
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
pub fn get_serde_number_to_string(value: &serde_json::Value) -> Option<String> {
    if value.is_string() {
        Option::Some(value.as_str().unwrap_or("").to_string())
    } else if value.is_object() {
        // Object type is not specified record value.
        Option::None
    } else {
        Option::Some(value.to_string())
    }
}

pub fn get_event_value<'a>(key: &str, event_value: &'a Value) -> Option<&'a Value> {
    if key.is_empty() {
        return Option::None;
    }

    let event_key = configs::EVENTKEY_ALIAS.get_event_key(key);
    let mut ret: &Value = event_value;
    if let Some(event_key) = event_key {
        // get_event_keyが取得できてget_event_key_splitが取得できないことはない
        let splits = configs::EVENTKEY_ALIAS.get_event_key_split(key);
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

pub fn get_thread_num() -> usize {
    let def_thread_num_str = num_cpus::get().to_string();
    let conf = configs::CONFIG.read().unwrap();
    conf.args
        .value_of("thread-number")
        .unwrap_or(def_thread_num_str.as_str())
        .parse::<usize>()
        .unwrap()
}

pub fn create_tokio_runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(get_thread_num())
        .thread_name("yea-thread")
        .build()
        .unwrap()
}

// EvtxRecordInfoを作成します。
pub fn create_rec_info(data: Value, path: String, keys: &[String]) -> EvtxRecordInfo {
    // 高速化のための処理

    // 例えば、Value型から"Event.System.EventID"の値を取得しようとすると、value["Event"]["System"]["EventID"]のように3回アクセスする必要がある。
    // この処理を高速化するため、rec.key_2_valueというhashmapに"Event.System.EventID"というキーで値を設定しておく。
    // これなら、"Event.System.EventID"というキーを1回指定するだけで値を取得できるようになるので、高速化されるはず。
    // あと、serde_jsonのValueからvalue["Event"]みたいな感じで値を取得する処理がなんか遅いので、そういう意味でも早くなるかも
    // それと、serde_jsonでは内部的に標準ライブラリのhashmapを使用しているが、hashbrownを使った方が早くなるらしい。
    let mut key_2_values = hashbrown::HashMap::new();
    for key in keys {
        let val = get_event_value(key, &data);
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
    let rec_info = if configs::CONFIG.read().unwrap().args.is_present("full-data") {
        Option::Some(create_recordinfos(&data))
    } else {
        Option::None
    };
    EvtxRecordInfo {
        evtx_filepath: path,
        record: data,
        data_string: data_str,
        key_2_value: key_2_values,
        record_information: rec_info,
    }
}

/**
 * 標準出力のカラー出力設定を指定した値に変更し画面出力を行う関数
 */
pub fn write_color_buffer(
    wtr: BufferWriter,
    color: Option<Color>,
    output_str: &str,
) -> io::Result<()> {
    let mut buf = wtr.buffer();
    buf.set_color(ColorSpec::new().set_fg(color)).ok();
    writeln!(buf, "{}", output_str).ok();
    wtr.print(&buf)
}

/**
 * CSVのrecord infoカラムに出力する文字列を作る
 */
fn create_recordinfos(record: &Value) -> String {
    let mut output = vec![];
    _collect_recordinfo(&mut vec![], "", record, &mut output);

    // 同じレコードなら毎回同じ出力になるようにソートしておく
    output.sort_by(|(left, left_data), (right, right_data)| {
        let ord = left.cmp(right);
        if ord == Ordering::Equal {
            left_data.cmp(right_data)
        } else {
            ord
        }
    });

    let summary: Vec<String> = output
        .iter()
        .map(|(key, value)| {
            return format!("{}:{}", key, value);
        })
        .collect();

    // 標準出力する時はセルがハイプ区切りになるので、パイプ区切りにしない
    if configs::CONFIG.read().unwrap().args.is_present("output") {
        summary.join(" | ")
    } else {
        summary.join(" ")
    }
}

/**
 * CSVのfieldsカラムに出力する要素を全て収集する
 */
fn _collect_recordinfo<'a>(
    keys: &mut Vec<&'a str>,
    parent_key: &'a str,
    value: &'a Value,
    output: &mut Vec<(String, String)>,
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
                if key.eq("System") && keys.get(0).unwrap_or(&"").eq(&"Event") {
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
                output.push((parent_key.to_string(), strval));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::utils;
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
                let expected = "AccessMask:%%1369 Process:lsass.exe User:u1".to_string();
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
                let expected = "Binary:hogehoge Data: Data:Data1 Data:DataData2 Data:DataDataData3"
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
            utils::read_txt("./rules/config/regex/detectlist_suspicous_services.txt")
                .unwrap()
                .into_iter()
                .map(|regex_str| Regex::new(&regex_str).unwrap())
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
            utils::read_txt("./rules/config/regex/allowlist_legitimate_services.txt")
                .unwrap()
                .into_iter()
                .map(|allow_str| Regex::new(&allow_str).unwrap())
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
            utils::get_serde_number_to_string(&event_record["Event"]["System"]["EventID"]).unwrap(),
            "11111".to_owned()
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
}

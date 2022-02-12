extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs;
use crate::filter::DataFilterRule;

use tokio::runtime::Builder;
use tokio::runtime::Runtime;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::str;
use std::string::String;

use super::detection::EvtxRecordInfo;

pub fn concat_selection_key(key_list: &Vec<String>) -> String {
    return key_list
        .iter()
        .fold("detection -> selection".to_string(), |mut acc, cur| {
            acc = acc + " -> " + cur;
            return acc;
        });
}

pub fn check_regex(string: &str, regex_list: &Vec<Regex>) -> bool {
    for regex in regex_list {
        if regex.is_match(string) == false {
            continue;
        }

        return true;
    }

    return false;
}

/// replace string from all defined regex in input to replace_str
pub fn replace_target_character<'a>(
    input_str: Option<&'a String>,
    replace_rule: Option<&'a DataFilterRule>,
) -> Option<String> {
    if input_str.is_none() {
        return None;
    }
    if replace_rule.is_none() {
        return Some(input_str.unwrap().to_string());
    }

    let replace_regex_rule = &replace_rule.unwrap().regex_rule;
    let replace_str = &replace_rule.unwrap().replace_str;

    return Some(
        replace_regex_rule
            .replace_all(input_str.unwrap(), replace_str)
            .to_string(),
    );
}

pub fn check_allowlist(target: &str, regexes: &Vec<Regex>) -> bool {
    for regex in regexes {
        if regex.is_match(target) {
            return true;
        }
    }

    return false;
}

pub fn value_to_string(value: &Value) -> Option<String> {
    return match value {
        Value::Null => Option::None,
        Value::Bool(b) => Option::Some(b.to_string()),
        Value::Number(n) => Option::Some(n.to_string()),
        Value::String(s) => Option::Some(s.to_string()),
        Value::Array(_) => Option::None,
        Value::Object(_) => Option::None,
    };
}

pub fn read_txt(filename: &str) -> Result<Vec<String>, String> {
    let f = File::open(filename);
    if f.is_err() {
        let errmsg = format!("Cannot open file. [file:{}]", filename);
        return Result::Err(errmsg);
    }
    let reader = BufReader::new(f.unwrap());
    return Result::Ok(
        reader
            .lines()
            .map(|line| line.unwrap_or(String::default()))
            .collect(),
    );
}

pub fn read_csv(filename: &str) -> Result<Vec<Vec<String>>, String> {
    let f = File::open(filename);
    if f.is_err() {
        return Result::Err(format!("Cannot open file. [file:{}]", filename));
    }
    let mut contents: String = String::new();
    let mut ret = vec![];
    let read_res = f.unwrap().read_to_string(&mut contents);
    if read_res.is_err() {
        return Result::Err(read_res.unwrap_err().to_string());
    }

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    return Result::Ok(ret);
}

pub fn is_target_event_id(s: &String) -> bool {
    return configs::CONFIG.read().unwrap().target_eventids.is_target(s);
}

pub fn get_event_id_key() -> String {
    return "Event.System.EventID".to_string();
}

pub fn get_event_time() -> String {
    return "Event.System.TimeCreated_attributes.SystemTime".to_string();
}

pub fn str_time_to_datetime(system_time_str: &str) -> Option<DateTime<Utc>> {
    if system_time_str.is_empty() {
        return Option::None;
    }

    let rfc3339_time = DateTime::parse_from_rfc3339(system_time_str);
    if rfc3339_time.is_err() {
        return Option::None;
    }
    let datetime = Utc
        .from_local_datetime(&rfc3339_time.unwrap().naive_utc())
        .single();
    if datetime.is_none() {
        return Option::None;
    } else {
        return Option::Some(datetime.unwrap());
    }
}

/// serde:Valueの型を確認し、文字列を返します。
pub fn get_serde_number_to_string(value: &serde_json::Value) -> Option<String> {
    if value.is_string() {
        return Option::Some(value.as_str().unwrap_or("").to_string());
    } else if value.is_object() {
        // Object type is not specified record value.
        return Option::None;
    } else {
        return Option::Some(value.to_string());
    }
}

pub fn get_event_value<'a>(key: &String, event_value: &'a Value) -> Option<&'a Value> {
    if key.len() == 0 {
        return Option::None;
    }

    let event_key = configs::EVENTKEY_ALIAS.get_event_key(key);
    if let Some(event_key) = event_key {
        let mut ret: &Value = event_value;
        // get_event_keyが取得できてget_event_key_splitが取得できないことはない
        let splits = configs::EVENTKEY_ALIAS.get_event_key_split(key);
        let mut start_idx = 0;
        for key in splits.unwrap() {
            if ret.is_object() == false {
                return Option::None;
            }

            let val = &event_key[start_idx..(*key + start_idx)];
            ret = &ret[val];
            start_idx = *key + start_idx;
            start_idx += 1;
        }

        return Option::Some(ret);
    } else {
        let mut ret: &Value = event_value;
        let event_key = key;
        for key in event_key.split(".") {
            if ret.is_object() == false {
                return Option::None;
            }
            ret = &ret[key];
        }

        return Option::Some(ret);
    }
}

pub fn get_thread_num() -> usize {
    let def_thread_num_str = num_cpus::get().to_string();
    let conf = configs::CONFIG.read().unwrap();
    let threadnum = &conf
        .args
        .value_of("thread-number")
        .unwrap_or(def_thread_num_str.as_str());
    return threadnum.parse::<usize>().unwrap().clone();
}

pub fn create_tokio_runtime() -> Runtime {
    return Builder::new_multi_thread()
        .worker_threads(get_thread_num())
        .thread_name("yea-thread")
        .build()
        .unwrap();
}

// EvtxRecordInfoを作成します。
pub fn create_rec_info(data: Value, path: String, keys: &Vec<String>) -> EvtxRecordInfo {
    // EvtxRecordInfoを作る
    let data_str = data.to_string();
    let mut rec = EvtxRecordInfo {
        evtx_filepath: path,
        record: data,
        data_string: data_str,
        key_2_value: hashbrown::HashMap::new(),
    };

    // 高速化のための処理

    // 例えば、Value型から"Event.System.EventID"の値を取得しようとすると、value["Event"]["System"]["EventID"]のように3回アクセスする必要がある。
    // この処理を高速化するため、rec.key_2_valueというhashmapに"Event.System.EventID"というキーで値を設定しておく。
    // これなら、"Event.System.EventID"というキーを1回指定するだけで値を取得できるようになるので、高速化されるはず。
    // あと、serde_jsonのValueからvalue["Event"]みたいな感じで値を取得する処理がなんか遅いので、そういう意味でも早くなるかも
    // それと、serde_jsonでは内部的に標準ライブラリのhashmapを使用しているが、hashbrownを使った方が早くなるらしい。
    for key in keys {
        let val = get_event_value(key, &rec.record);
        if val.is_none() {
            continue;
        }

        let val = value_to_string(val.unwrap());
        if val.is_none() {
            continue;
        }

        rec.key_2_value.insert(key.to_string(), val.unwrap());
    }

    return rec;
}

#[cfg(test)]
mod tests {
    use crate::detections::utils;
    use crate::filter::DataFilterRule;
    use regex::Regex;
    use serde_json::Value;

    #[test]
    fn test_check_regex() {
        let regexes = utils::read_txt("./config/regex/detectlist_suspicous_services.txt")
            .unwrap()
            .into_iter()
            .map(|regex_str| Regex::new(&regex_str).unwrap())
            .collect();
        let regextext = utils::check_regex("\\cvtres.exe", &regexes);
        assert!(regextext == true);

        let regextext = utils::check_regex("\\hogehoge.exe", &regexes);
        assert!(regextext == false);
    }

    #[test]
    fn test_check_allowlist() {
        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"";
        let allowlist = utils::read_txt("./config/regex/allowlist_legitimate_services.txt")
            .unwrap()
            .into_iter()
            .map(|allow_str| Regex::new(&allow_str).unwrap())
            .collect();
        assert!(true == utils::check_allowlist(commandline, &allowlist));

        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate2.exe\"";
        assert!(false == utils::check_allowlist(commandline, &allowlist));
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

    #[test]
    /// 指定された文字から\r \n \tを取り除く関数が動作するかのテスト
    fn test_remove_space_control() {
        let none_test_str: Option<&String> = None;
        assert_eq!(
            utils::replace_space_control_character(none_test_str, "").is_none(),
            true
        );

        let tmp = "h\ra\ny\ta\tb\nu\r\nsa".to_string();
        let test_str: Option<&String> = Some(&tmp);
        assert_eq!(
            utils::replace_space_control_character(test_str, "").unwrap(),
            "hayabusa"
        );
    }
}

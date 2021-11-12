extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs;

use tokio::runtime::Builder;
use tokio::runtime::Runtime;

use regex::Regex;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::str;
use std::string::String;

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

pub fn check_allowlist(target: &str, regexes: &Vec<Regex>) -> bool {
    for regex in regexes {
        if regex.is_match(target) {
            return true;
        }
    }

    return false;
}

pub fn read_txt(filename: &str) -> Result<Vec<String>, String> {
    let f = File::open(filename);
    if f.is_err() {
        let errmsg = format!("cannot open file. [file:{}]", filename);
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
    let mut f = File::open(filename).expect("file not found!!!");
    let mut contents: String = String::new();
    let mut ret = vec![];
    let read_res = f.read_to_string(&mut contents);
    if f.read_to_string(&mut contents).is_err() {
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

pub fn get_event_id_key() -> String {
    return "Event.System.EventID".to_string();
}

// alias.txtについて、指定されたevent_keyに対応するaliasを取得します。
pub fn get_alias(event_key: &String) -> Option<String> {
    let conf = configs::CONFIG.read().unwrap();
    let keyvalues = &conf.event_key_alias_config.get_event_key_values();
    let value = keyvalues
        .iter()
        .find(|(_, cur_event_key)| &event_key == cur_event_key);

    if value.is_none() {
        return Option::None;
    } else {
        return Option::Some(value.unwrap().0.clone());
    }
}

pub fn get_event_value<'a>(key: &String, event_value: &'a Value) -> Option<&'a Value> {
    if key.len() == 0 {
        return Option::None;
    }
    let singleton = configs::CONFIG.read().unwrap();
    let event_key = match singleton
        .event_key_alias_config
        .get_event_key(key.to_string())
    {
        Some(alias_event_key) => alias_event_key,
        None => key,
    };

    let mut ret: &Value = event_value;
    for key in event_key.split(".") {
        if ret.is_object() == false {
            return Option::None;
        }
        ret = &ret[key];
    }

    return Option::Some(ret);
}

pub fn get_thread_num() -> usize {
    let def_thread_num_str = num_cpus::get().to_string();
    let conf = configs::CONFIG.read().unwrap();
    let threadnum = &conf
        .args
        .value_of("threadnum")
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

#[cfg(test)]
mod tests {
    use crate::detections::utils;
    use regex::Regex;

    #[test]
    fn test_check_regex() {
        let regexes = utils::read_txt("./config/regex/regexes_suspicous_service.txt")
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
        let allowlist = utils::read_txt("./config/regex/allowlist_legimate_serviceimage.txt")
            .unwrap()
            .into_iter()
            .map(|allow_str| Regex::new(&allow_str).unwrap())
            .collect();
        assert!(true == utils::check_allowlist(commandline, &allowlist));

        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate2.exe\"";
        assert!(false == utils::check_allowlist(commandline, &allowlist));
    }
}

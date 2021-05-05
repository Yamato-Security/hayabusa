extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs;

use regex::Regex;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::str;
use std::string::String;

pub fn check_regex(
    string: &str,
    r#type: usize,
    regex_list: &Vec<Vec<String>>,
) -> std::string::String {
    let empty = "".to_string();
    let mut regextext = "".to_string();
    for line in regex_list {
        let type_str = line.get(0).unwrap_or(&empty);
        if type_str != &r#type.to_string() {
            continue;
        }

        let regex_str = line.get(1).unwrap_or(&empty);
        if regex_str.is_empty() {
            continue;
        }

        let re = Regex::new(regex_str);
        if re.is_err() || re.unwrap().is_match(string) == false {
            continue;
        }

        let text = line.get(2).unwrap_or(&empty);
        if text.is_empty() {
            continue;
        }

        regextext.push_str(text);
        regextext.push_str("\n");
    }

    return regextext;
}

pub fn check_whitelist(target: &str, whitelist: &Vec<Vec<String>>) -> bool {
    let empty = "".to_string();
    for line in whitelist {
        let r_str = line.get(0).unwrap_or(&empty);
        if r_str.is_empty() {
            continue;
        }

        let r = Regex::new(r_str);
        if r.is_ok() && r.unwrap().is_match(target) {
            return true;
        }
    }

    return false;
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

#[cfg(test)]
mod tests {
    use crate::detections::utils;
    #[test]
    fn test_check_regex() {
        let regexes = utils::read_csv("regexes.txt").unwrap();
        let regextext = utils::check_regex("\\cvtres.exe", 0, &regexes);
        assert!(regextext == "Resource File To COFF Object Conversion Utility cvtres.exe\n");

        let regextext = utils::check_regex("\\hogehoge.exe", 0, &regexes);
        assert!(regextext == "");
    }

    #[test]
    fn test_check_whitelist() {
        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"";
        let whitelist = utils::read_csv("whitelist.txt").unwrap();
        assert!(true == utils::check_whitelist(commandline, &whitelist));

        let commandline = "\"C:\\Program Files\\Google\\Update\\GoogleUpdate2.exe\"";
        assert!(false == utils::check_whitelist(commandline, &whitelist));
    }
}

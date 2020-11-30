extern crate chrono;
extern crate lazy_static;
use crate::detections::configs;
use chrono::{DateTime, TimeZone, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Message {
    map: BTreeMap<DateTime<Utc>, Vec<String>>,
}

lazy_static! {
    pub static ref MESSAGES: Mutex<Message> = Mutex::new(Message::new());
}

impl Message {
    pub fn new() -> Self {
        let messages: BTreeMap<DateTime<Utc>, Vec<String>> = BTreeMap::new();
        Message { map: messages }
    }

    /// メッセージを設定
    pub fn insert(&mut self, event_record: &Value, output: String) {
        if output.is_empty() {
            return;
        }

        let message = &self.parse_message(event_record, output);
        let default_time = Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
        let time = Message::get_event_time(event_record).unwrap_or(default_time);

        match self.map.get_mut(&time) {
            Some(v) => {
                v.push(message.to_string());
            }
            None => {
                let m = vec![message.to_string(); 1];
                self.map.insert(time, m);
            }
        }
    }

    fn parse_message(&mut self, event_record: &Value, output: String) -> String {
        let mut return_message: String = output;
        let mut hash_map: HashMap<String, String> = HashMap::new();
        let re = Regex::new(r"%[a-zA-Z0-9-_]+%").unwrap();
        for caps in re.captures_iter(&return_message) {
            let full_target_str = &caps[0];
            let target_length = full_target_str.chars().count() - 2; // The meaning of 2 is two percent
            let target_str = full_target_str
                .chars()
                .skip(1)
                .take(target_length)
                .collect::<String>();

            if let Some(array_str) = configs::singleton()
                .event_key_alias_config
                .get_event_key(target_str.to_string())
            {
                let split: Vec<&str> = array_str.split(".").collect();
                let mut tmp_event_record: &Value = event_record.into();
                for s in split {
                    if let Some(record) = tmp_event_record.get(s) {
                        tmp_event_record = record;
                    }
                }
                hash_map.insert(
                    full_target_str.to_string(),
                    tmp_event_record.as_str().unwrap_or("").to_string(),
                );
            }
        }

        for (k, v) in &hash_map {
            return_message = return_message.replace(k, v);
        }

        return_message
    }

    /// メッセージを返す
    pub fn get(&self, time: DateTime<Utc>) -> Vec<String> {
        match self.map.get(&time) {
            Some(v) => (&v).to_vec(),
            None => Vec::new(),
        }
    }

    /// Messageのなかに入っているメッセージすべてを表示する
    pub fn debug(&self) {
        println!("{:?}", self.map);
    }

    /// 最後に表示を行う
    pub fn print(&self) {
        for (key, values) in self.map.iter() {
            for value in values.iter() {
                println!("{} : {}", key, value);
            }
        }
    }

    pub fn iter(&self) -> &BTreeMap<DateTime<Utc>, Vec<String>> {
        &self.map
    }

    fn get_event_time(event_record: &Value) -> Option<DateTime<Utc>> {
        let system_time =
            &event_record["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"];
        let system_time_str = system_time.as_str().unwrap_or("");
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
}

#[cfg(test)]
mod tests {
    use crate::detections::print::Message;
    use serde_json::Value;

    #[test]
    fn test_create_and_append_message() {
        let mut message = Message::new();
        let json_str_1 = r##"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "hoge"
                },
                "System": {
                    "TimeCreated": {
                        "#attributes":{
                            "SystemTime": "1996-02-27T01:05:01Z"
                        }
                    }
                }
            }
        }
    "##;
        let event_record_1: Value = serde_json::from_str(json_str_1).unwrap();
        message.insert(&event_record_1, "CommandLine1: %CommandLine%".to_string());

        let json_str_2 = r##"
    {
        "Event": {
            "EventData": {
                "CommandLine": "hoge"
            },
            "System": {
                "TimeCreated": {
                    "#attributes":{
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    }
    "##;
        let event_record_2: Value = serde_json::from_str(json_str_2).unwrap();
        message.insert(&event_record_2, "CommandLine2: %CommandLine%".to_string());

        let json_str_3 = r##"
    {
        "Event": {
            "EventData": {
                "CommandLine": "hoge"
            },
            "System": {
                "TimeCreated": {
                    "#attributes":{
                        "SystemTime": "2000-01-21T09:06:01Z"
                    }
                }
            }
        }
    }
    "##;
        let event_record_3: Value = serde_json::from_str(json_str_3).unwrap();
        message.insert(&event_record_3, "CommandLine3: %CommandLine%".to_string());

        let json_str_4 = r##"
    {
        "Event": {
            "EventData": {
                "CommandLine": "hoge"
            }
        }
    }
    "##;
        let event_record_4: Value = serde_json::from_str(json_str_4).unwrap();
        message.insert(&event_record_4, "CommandLine4: %CommandLine%".to_string());

        let display = format!("{}", format_args!("{:?}", message));
        println!("display::::{}", display);
        let expect = "Message { map: {1970-01-01T00:00:00Z: [\"CommandLine4: hoge\"], 1996-02-27T01:05:01Z: [\"CommandLine1: hoge\", \"CommandLine2: hoge\"], 2000-01-21T09:06:01Z: [\"CommandLine3: hoge\"]} }";
        assert_eq!(display, expect);
    }
}

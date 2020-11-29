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
    pub fn insert(
        &mut self,
        mut time: Option<DateTime<Utc>>,
        event_record: &Value,
        output: Option<String>,
    ) {
        if Option::None == output {
            return;
        }

        let message = &self.parse_message(event_record, output);

        if Option::None == time {
            time = Option::Some(Utc.ymd(1970, 1, 1).and_hms(0, 0, 0));
        }

        match self.map.get_mut(&time.unwrap()) {
            Some(v) => {
                v.push(message.to_string());
            }
            None => {
                let m = vec![message.to_string(); 1];
                self.map.insert(time.unwrap(), m);
            }
        }
    }

    fn parse_message(&mut self, event_record: &Value, output: Option<String>) -> String {
        if Option::None == output {
            return "".to_string();
        }

        let mut return_message: String = output.unwrap();
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
}

#[test]
fn test_create_and_append_message() {
    let mut message = Message::new();
    let poke = Utc.ymd(1996, 2, 27).and_hms(1, 5, 1);
    let taka = Utc.ymd(2000, 1, 21).and_hms(9, 6, 1);

    let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "hoge"
                }
            }
        }
    "#;
    let event_record: Value = serde_json::from_str(json_str).unwrap();

    message.insert(
        Some(poke),
        &event_record,
        Some("CommandLine1: %CommandLine%".to_string()),
    );
    message.insert(
        Some(poke),
        &event_record,
        Some("CommandLine2: %CommandLine%".to_string()),
    );
    message.insert(
        Some(taka),
        &event_record,
        Some("CommandLine3: %CommandLine%".to_string()),
    );
    message.insert(
        Option::None,
        &event_record,
        Some("CommandLine4: %CommandLine%".to_string()),
    );

    let display = format!("{}", format_args!("{:?}", message));
    let expect = "Message { map: {1970-01-01T00:00:00Z: [\"CommandLine4: hoge\"], 1996-02-27T01:05:01Z: [\"CommandLine1: hoge\", \"CommandLine2: hoge\"], 2000-01-21T09:06:01Z: [\"CommandLine3: hoge\"]} }";
    assert_eq!(display, expect);
}

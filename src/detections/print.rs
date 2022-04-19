extern crate lazy_static;
use crate::detections::configs;
use crate::detections::utils;
use crate::detections::utils::get_serde_number_to_string;
use chrono::{DateTime, Local, TimeZone, Utc};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fs::create_dir;
use std::fs::File;
use std::io::BufWriter;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Message {
    map: BTreeMap<DateTime<Utc>, Vec<DetectInfo>>,
}

#[derive(Debug, Clone)]
pub struct DetectInfo {
    pub filepath: String,
    pub rulepath: String,
    pub level: String,
    pub computername: String,
    pub eventid: String,
    pub channel: String,
    pub alert: String,
    pub detail: String,
    pub tag_info: String,
    pub record_information: Option<String>,
}

pub struct AlertMessage {}

lazy_static! {
    pub static ref MESSAGES: Mutex<Message> = Mutex::new(Message::new());
    pub static ref ALIASREGEX: Regex = Regex::new(r"%[a-zA-Z0-9-_]+%").unwrap();
    pub static ref ERROR_LOG_PATH: String = format!(
        "./logs/errorlog-{}.log",
        Local::now().format("%Y%m%d_%H%M%S")
    );
    pub static ref QUIET_ERRORS_FLAG: bool = configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("quiet-errors");
    pub static ref ERROR_LOG_STACK: Mutex<Vec<String>> = Mutex::new(Vec::new());
    pub static ref STATISTICS_FLAG: bool = configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("statistics");
    pub static ref TAGS_CONFIG: HashMap<String, String> =
        Message::create_output_filter_config("config/output_tag.txt");
    pub static ref CH_CONFIG: HashMap<String, String> =
        Message::create_output_filter_config("config/channel_abbrevations.txt");
    pub static ref PIVOT_KEYWORD_LIST_FLAG: bool = configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("pivot-keywords-list");
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

impl Message {
    pub fn new() -> Self {
        let messages: BTreeMap<DateTime<Utc>, Vec<DetectInfo>> = BTreeMap::new();
        Message { map: messages }
    }

    /// ファイルパスで記載されたtagでのフル名、表示の際に置き換えられる文字列のHashMapを作成する関数。tagではこのHashMapのキーに対応しない出力は出力しないものとする
    /// ex. attack.impact,Impact
    pub fn create_output_filter_config(path: &str) -> HashMap<String, String> {
        let read_result = utils::read_csv(path);
        if read_result.is_err() {
            AlertMessage::alert(
                &mut BufWriter::new(std::io::stderr().lock()),
                read_result.as_ref().unwrap_err(),
            )
            .ok();
            return HashMap::default();
        }
        let mut ret: HashMap<String, String> = HashMap::new();
        read_result.unwrap().into_iter().for_each(|line| {
            if line.len() != 2 {
                return;
            }

            let empty = &"".to_string();
            let tag_full_str = line.get(0).unwrap_or(empty).trim();
            let tag_replace_str = line.get(1).unwrap_or(empty).trim();

            ret.insert(tag_full_str.to_owned(), tag_replace_str.to_owned());
        });
        ret
    }

    /// メッセージの設定を行う関数。aggcondition対応のためrecordではなく出力をする対象時間がDatetime形式での入力としている
    pub fn insert_message(&mut self, detect_info: DetectInfo, event_time: DateTime<Utc>) {
        if let Some(v) = self.map.get_mut(&event_time) {
            v.push(detect_info);
        } else {
            let m = vec![detect_info; 1];
            self.map.insert(event_time, m);
        }
    }

    /// メッセージを設定
    pub fn insert(&mut self, event_record: &Value, output: String, mut detect_info: DetectInfo) {
        detect_info.detail = self.parse_message(event_record, output);
        let default_time = Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
        let time = Message::get_event_time(event_record).unwrap_or(default_time);
        self.insert_message(detect_info, time)
    }

    fn parse_message(&mut self, event_record: &Value, output: String) -> String {
        let mut return_message: String = output;
        let mut hash_map: HashMap<String, String> = HashMap::new();
        for caps in ALIASREGEX.captures_iter(&return_message) {
            let full_target_str = &caps[0];
            let target_length = full_target_str.chars().count() - 2; // The meaning of 2 is two percent
            let target_str = full_target_str
                .chars()
                .skip(1)
                .take(target_length)
                .collect::<String>();

            let array_str =
                if let Some(_array_str) = configs::EVENTKEY_ALIAS.get_event_key(&target_str) {
                    _array_str.to_string()
                } else {
                    "Event.EventData.".to_owned() + &target_str
                };

            let split: Vec<&str> = array_str.split('.').collect();
            let mut is_exist_event_key = false;
            let mut tmp_event_record: &Value = event_record;
            for s in &split {
                if let Some(record) = tmp_event_record.get(s) {
                    is_exist_event_key = true;
                    tmp_event_record = record;
                }
            }
            if is_exist_event_key {
                let hash_value = get_serde_number_to_string(tmp_event_record);
                if let Some(hash_value) = hash_value {
                    // UnicodeのWhitespace characterをそのままCSVに出力すると見難いので、スペースに変換する。なお、先頭と最後のWhitespace characterは単に削除される。
                    let hash_value: Vec<&str> = hash_value.split_whitespace().collect();
                    let hash_value = hash_value.join(" ");
                    hash_map.insert(full_target_str.to_string(), hash_value);
                }
            }
        }

        for (k, v) in &hash_map {
            return_message = return_message.replace(k, v);
        }

        return_message
    }

    /// メッセージを返す
    pub fn get(&self, time: DateTime<Utc>) -> Vec<DetectInfo> {
        match self.map.get(&time) {
            Some(v) => v.to_vec(),
            None => Vec::new(),
        }
    }

    /// Messageのなかに入っているメッセージすべてを表示する
    pub fn debug(&self) {
        println!("{:?}", self.map);
    }

    /// 最後に表示を行う
    pub fn print(&self) {
        let mut detect_count = 0;
        for (key, detect_infos) in self.map.iter() {
            for detect_info in detect_infos.iter() {
                println!("{} <{}> {}", key, detect_info.alert, detect_info.detail);
            }
            detect_count += detect_infos.len();
        }
        println!();
        println!("Total events:{:?}", detect_count);
    }

    pub fn iter(&self) -> &BTreeMap<DateTime<Utc>, Vec<DetectInfo>> {
        &self.map
    }

    pub fn get_event_time(event_record: &Value) -> Option<DateTime<Utc>> {
        let system_time = &event_record["Event"]["System"]["TimeCreated_attributes"]["SystemTime"];
        return utils::str_time_to_datetime(system_time.as_str().unwrap_or(""));
    }

    /// message内のマップをクリアする。テストする際の冪等性の担保のため作成。
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl AlertMessage {
    ///対象のディレクトリが存在することを確認後、最初の定型文を追加して、ファイルのbufwriterを返す関数
    pub fn create_error_log(path_str: String) {
        if *QUIET_ERRORS_FLAG {
            return;
        }
        let path = Path::new(&path_str);
        if !path.parent().unwrap().exists() {
            create_dir(path.parent().unwrap()).ok();
        }
        let mut error_log_writer = BufWriter::new(File::create(path).unwrap());
        error_log_writer
            .write_all(
                format!(
                    "user input: {:?}\n",
                    format_args!("{}", env::args().collect::<Vec<String>>().join(" "))
                )
                .as_bytes(),
            )
            .ok();
        for error_log in ERROR_LOG_STACK.lock().unwrap().iter() {
            writeln!(error_log_writer, "{}", error_log).ok();
        }
        println!(
            "Errors were generated. Please check {} for details.",
            *ERROR_LOG_PATH
        );
        println!();
    }

    /// ERRORメッセージを表示する関数
    pub fn alert<W: Write>(w: &mut W, contents: &str) -> io::Result<()> {
        writeln!(w, "[ERROR] {}", contents)
    }

    /// WARNメッセージを表示する関数
    pub fn warn<W: Write>(w: &mut W, contents: &str) -> io::Result<()> {
        writeln!(w, "[WARN] {}", contents)
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::print::DetectInfo;
    use crate::detections::print::{AlertMessage, Message};
    use hashbrown::HashMap;
    use serde_json::Value;
    use std::io::BufWriter;

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
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "##;
        let event_record_1: Value = serde_json::from_str(json_str_1).unwrap();
        message.insert(
            &event_record_1,
            "CommandLine1: %CommandLine%".to_string(),
            DetectInfo {
                filepath: "a".to_string(),
                rulepath: "test_rule".to_string(),
                level: "high".to_string(),
                computername: "testcomputer1".to_string(),
                eventid: "1".to_string(),
                channel: String::default(),
                alert: "test1".to_string(),
                detail: String::default(),
                tag_info: "txxx.001".to_string(),
                record_information: Option::Some("record_information1".to_string()),
            },
        );

        let json_str_2 = r##"
    {
        "Event": {
            "EventData": {
                "CommandLine": "hoge"
            },
            "System": {
                "TimeCreated_attributes": {
                    "SystemTime": "1996-02-27T01:05:01Z"
                }
            }
        }
    }
    "##;
        let event_record_2: Value = serde_json::from_str(json_str_2).unwrap();
        message.insert(
            &event_record_2,
            "CommandLine2: %CommandLine%".to_string(),
            DetectInfo {
                filepath: "a".to_string(),
                rulepath: "test_rule2".to_string(),
                level: "high".to_string(),
                computername: "testcomputer2".to_string(),
                eventid: "2".to_string(),
                channel: String::default(),
                alert: "test2".to_string(),
                detail: String::default(),
                tag_info: "txxx.002".to_string(),
                record_information: Option::Some("record_information2".to_string()),
            },
        );

        let json_str_3 = r##"
    {
        "Event": {
            "EventData": {
                "CommandLine": "hoge"
            },
            "System": {
                "TimeCreated_attributes": {
                    "SystemTime": "2000-01-21T09:06:01Z"
                }
            }
        }
    }
    "##;
        let event_record_3: Value = serde_json::from_str(json_str_3).unwrap();
        message.insert(
            &event_record_3,
            "CommandLine3: %CommandLine%".to_string(),
            DetectInfo {
                filepath: "a".to_string(),
                rulepath: "test_rule3".to_string(),
                level: "high".to_string(),
                computername: "testcomputer3".to_string(),
                eventid: "3".to_string(),
                channel: String::default(),
                alert: "test3".to_string(),
                detail: String::default(),
                tag_info: "txxx.003".to_string(),
                record_information: Option::Some("record_information3".to_string()),
            },
        );

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
        message.insert(
            &event_record_4,
            "CommandLine4: %CommandLine%".to_string(),
            DetectInfo {
                filepath: "a".to_string(),
                rulepath: "test_rule4".to_string(),
                level: "medium".to_string(),
                computername: "testcomputer4".to_string(),
                eventid: "4".to_string(),
                channel: String::default(),
                alert: "test4".to_string(),
                detail: String::default(),
                tag_info: "txxx.004".to_string(),
                record_information: Option::Some("record_information4".to_string()),
            },
        );

        let display = format!("{}", format_args!("{:?}", message));
        println!("display::::{}", display);
        let expect = "Message { map: {1970-01-01T00:00:00Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule4\", level: \"medium\", computername: \"testcomputer4\", eventid: \"4\", channel: \"\", alert: \"test4\", detail: \"CommandLine4: hoge\", tag_info: \"txxx.004\", record_information: Some(\"record_information4\") }], 1996-02-27T01:05:01Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule\", level: \"high\", computername: \"testcomputer1\", eventid: \"1\", channel: \"\", alert: \"test1\", detail: \"CommandLine1: hoge\", tag_info: \"txxx.001\", record_information: Some(\"record_information1\") }, DetectInfo { filepath: \"a\", rulepath: \"test_rule2\", level: \"high\", computername: \"testcomputer2\", eventid: \"2\", channel: \"\", alert: \"test2\", detail: \"CommandLine2: hoge\", tag_info: \"txxx.002\", record_information: Some(\"record_information2\") }], 2000-01-21T09:06:01Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule3\", level: \"high\", computername: \"testcomputer3\", eventid: \"3\", channel: \"\", alert: \"test3\", detail: \"CommandLine3: hoge\", tag_info: \"txxx.003\", record_information: Some(\"record_information3\") }]} }";
        assert_eq!(display, expect);
    }

    #[test]
    fn test_error_message() {
        let input = "TEST!";
        AlertMessage::alert(&mut BufWriter::new(std::io::stdout().lock()), input)
            .expect("[ERROR] TEST!");
    }

    #[test]
    fn test_warn_message() {
        let input = "TESTWarn!";
        AlertMessage::warn(&mut BufWriter::new(std::io::stdout().lock()), input)
            .expect("[WARN] TESTWarn!");
    }

    #[test]
    /// outputで指定されているキー(eventkey_alias.txt内で設定済み)から対象のレコード内の情報でメッセージをパースしているか確認する関数
    fn test_parse_message() {
        let mut message = Message::new();
        let json_str = r##"
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
    "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest1 computername:testcomputer1";
        assert_eq!(
            message.parse_message(
                &event_record,
                "commandline:%CommandLine% computername:%ComputerName%".to_owned()
            ),
            expected,
        );
    }

    #[test]
    fn test_parse_message_auto_search() {
        let mut message = Message::new();
        let json_str = r##"
        {
            "Event": {
                "EventData": {
                    "NoAlias": "no_alias"
                }
            }
        }
    "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "alias:no_alias";
        assert_eq!(
            message.parse_message(&event_record, "alias:%NoAlias%".to_owned()),
            expected,
        );
    }

    #[test]
    /// outputで指定されているキーが、eventkey_alias.txt内で設定されていない場合の出力テスト
    fn test_parse_message_not_exist_key_in_output() {
        let mut message = Message::new();
        let json_str = r##"
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
    "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "NoExistAlias:%NoAliasNoHit%";
        assert_eq!(
            message.parse_message(&event_record, "NoExistAlias:%NoAliasNoHit%".to_owned()),
            expected,
        );
    }
    #[test]
    /// output test when no exist info in target record output and described key-value data in eventkey_alias.txt
    fn test_parse_message_not_exist_value_in_record() {
        let mut message = Message::new();
        let json_str = r##"
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
    "##;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 computername:%ComputerName%";
        assert_eq!(
            message.parse_message(
                &event_record,
                "commandline:%CommandLine% computername:%ComputerName%".to_owned()
            ),
            expected,
        );
    }
    #[test]
    /// test of loading output filter config by output_tag.txt
    fn test_load_output_tag() {
        let actual = Message::create_output_filter_config("test_files/config/output_tag.txt");
        let expected: HashMap<String, String> = HashMap::from([
            ("attack.impact".to_string(), "Impact".to_string()),
            ("xxx".to_string(), "yyy".to_string()),
        ]);

        assert_eq!(actual.len(), expected.len());
        for (k, v) in expected.iter() {
            assert!(actual.get(k).unwrap_or(&String::default()) == v);
        }
    }
}

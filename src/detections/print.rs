extern crate lazy_static;
use crate::detections::configs;
use crate::detections::utils;
use crate::detections::utils::get_serde_number_to_string;
use chrono::{DateTime, Local, TimeZone, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
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
    pub alert: String,
    pub detail: String,
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
}

impl Message {
    pub fn new() -> Self {
        let messages: BTreeMap<DateTime<Utc>, Vec<DetectInfo>> = BTreeMap::new();
        Message { map: messages }
    }

    /// メッセージの設定を行う関数。aggcondition対応のためrecordではなく出力をする対象時間がDatetime形式での入力としている
    pub fn insert_message(
        &mut self,
        target_file: String,
        rule_path: String,
        event_time: DateTime<Utc>,
        level: String,
        computername: String,
        eventid: String,
        event_title: String,
        event_detail: String,
    ) {
        let detect_info = DetectInfo {
            filepath: target_file,
            rulepath: rule_path,
            level: level,
            computername: computername,
            eventid: eventid,
            alert: event_title,
            detail: event_detail,
        };

        match self.map.get_mut(&event_time) {
            Some(v) => {
                v.push(detect_info);
            }
            None => {
                let m = vec![detect_info; 1];
                self.map.insert(event_time, m);
            }
        }
    }

    /// メッセージを設定
    pub fn insert(
        &mut self,
        target_file: String,
        rule_path: String,
        event_record: &Value,
        level: String,
        computername: String,
        eventid: String,
        event_title: String,
        output: String,
    ) {
        let message = &self.parse_message(event_record, output);
        let default_time = Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
        let time = Message::get_event_time(event_record).unwrap_or(default_time);
        self.insert_message(
            target_file,
            rule_path,
            time,
            level,
            computername,
            eventid,
            event_title,
            message.to_string(),
        )
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

            if let Some(array_str) = configs::EVENTKEY_ALIAS.get_event_key(&target_str) {
                let split: Vec<&str> = array_str.split(".").collect();
                let mut is_exist_event_key = false;
                let mut tmp_event_record: &Value = event_record.into();
                for s in split {
                    if let Some(record) = tmp_event_record.get(s) {
                        is_exist_event_key = true;
                        tmp_event_record = record;
                    }
                }
                if is_exist_event_key {
                    let hash_value = get_serde_number_to_string(tmp_event_record);
                    if hash_value.is_some() {
                        hash_map.insert(full_target_str.to_string(), hash_value.unwrap());
                    }
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
        println!("");
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
        // 1行目は必ず実行したコマンド情報を入れておく。
        let mut ret = BufWriter::new(File::create(path).unwrap());

        ret.write(
            format!(
                "user input: {:?}\n",
                format_args!(
                    "{}",
                    env::args()
                        .map(|arg| arg)
                        .collect::<Vec<String>>()
                        .join(" ")
                )
            )
            .as_bytes(),
        )
        .unwrap();
        ret.flush().ok();
    }

    /// ERRORメッセージを表示する関数
    pub fn alert<W: Write>(w: &mut W, contents: &String) -> io::Result<()> {
        writeln!(w, "[ERROR] {}", contents)
    }

    /// WARNメッセージを表示する関数
    pub fn warn<W: Write>(w: &mut W, contents: &String) -> io::Result<()> {
        writeln!(w, "[WARN] {}", contents)
    }

    /// エラーログへのERRORメッセージの出力数を確認して、0であったらファイルを削除する。1以上あればエラーを書き出した旨を標準出力に表示する
    pub fn output_error_log_exist() {
        if *QUIET_ERRORS_FLAG {
            return;
        }
        println!(
            "Errors were generated. Please check {} for details.",
            ERROR_LOG_PATH.to_string()
        );
        println!("");
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::print::{AlertMessage, Message};
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
            "a".to_string(),
            "test_rule".to_string(),
            &event_record_1,
            "high".to_string(),
            "testcomputer1".to_string(),
            "1".to_string(),
            "test1".to_string(),
            "CommandLine1: %CommandLine%".to_string(),
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
            "a".to_string(),
            "test_rule2".to_string(),
            &event_record_2,
            "high".to_string(),
            "testcomputer2".to_string(),
            "2".to_string(),
            "test2".to_string(),
            "CommandLine2: %CommandLine%".to_string(),
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
            "a".to_string(),
            "test_rule3".to_string(),
            &event_record_3,
            "high".to_string(),
            "testcomputer3".to_string(),
            "3".to_string(),
            "test3".to_string(),
            "CommandLine3: %CommandLine%".to_string(),
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
            "a".to_string(),
            "test_rule4".to_string(),
            &event_record_4,
            "medium".to_string(),
            "testcomputer4".to_string(),
            "4".to_string(),
            "test4".to_string(),
            "CommandLine4: %CommandLine%".to_string(),
        );

        let display = format!("{}", format_args!("{:?}", message));
        println!("display::::{}", display);
        let expect = "Message { map: {1970-01-01T00:00:00Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule4\", level: \"medium\", computername: \"testcomputer4\", eventid: \"4\", alert: \"test4\", detail: \"CommandLine4: hoge\" }], 1996-02-27T01:05:01Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule\", level: \"high\", computername: \"testcomputer1\", eventid: \"1\", alert: \"test1\", detail: \"CommandLine1: hoge\" }, DetectInfo { filepath: \"a\", rulepath: \"test_rule2\", level: \"high\", computername: \"testcomputer2\", eventid: \"2\", alert: \"test2\", detail: \"CommandLine2: hoge\" }], 2000-01-21T09:06:01Z: [DetectInfo { filepath: \"a\", rulepath: \"test_rule3\", level: \"high\", computername: \"testcomputer3\", eventid: \"3\", alert: \"test3\", detail: \"CommandLine3: hoge\" }]} }";
        assert_eq!(display, expect);
    }

    #[test]
    fn test_error_message() {
        let input = "TEST!";
        AlertMessage::alert(
            &mut BufWriter::new(std::io::stdout().lock()),
            &input.to_string(),
        )
        .expect("[ERROR] TEST!");
    }

    #[test]
    fn test_warn_message() {
        let input = "TESTWarn!";
        AlertMessage::warn(
            &mut BufWriter::new(std::io::stdout().lock()),
            &input.to_string(),
        )
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
        let expected = "NoExistKey:%TESTNoExistKey%";
        assert_eq!(
            message.parse_message(&event_record, "NoExistKey:%TESTNoExistKey%".to_owned()),
            expected,
        );
    }
    #[test]
    /// outputで指定されているキー(eventkey_alias.txt内で設定済み)が対象のレコード内に該当する情報がない場合の出力テスト
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
}

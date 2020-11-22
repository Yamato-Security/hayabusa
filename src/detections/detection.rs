extern crate chrono;
extern crate csv;

use crate::detections::print::Message;
use crate::detections::rule;
use crate::detections::rule::RuleNode;
use crate::yaml::ParseYaml;

use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use evtx::EvtxParser;
use serde_json::{Error, Value};

const DIRPATH_RULES: &str = "rules";

#[derive(Debug)]
pub struct Detection {}

impl Detection {
    pub fn new() -> Detection {
        Detection {}
    }

    pub fn start(&mut self, mut parser: EvtxParser<std::fs::File>) {
        // serialize from .etvx to jsons
        let event_records: Vec<Value> = parser
            .records_json()
            .filter_map(|result_record| {
                if result_record.is_err() {
                    eprintln!("{}", result_record.unwrap_err());
                    return Option::None;
                }

                //// https://rust-lang-nursery.github.io/rust-cookbook/encoding/complex.html
                let result_json: Result<Value, Error> =
                    serde_json::from_str(&result_record.unwrap().data);
                if result_json.is_err() {
                    eprintln!("{}", result_json.unwrap_err());
                    return Option::None;
                }
                return result_json.ok();
            })
            .collect();

        // load rule files
        let mut rulefile_loader = ParseYaml::new();
        let resutl_readdir = rulefile_loader.read_dir(DIRPATH_RULES);
        if resutl_readdir.is_err() {
            eprintln!("{}", resutl_readdir.unwrap_err());
            return;
        }

        // parse rule files
        let selection_rules: Vec<RuleNode> = rulefile_loader
            .files
            .into_iter()
            .map(|rule_file| rule::parse_rule(rule_file))
            .filter_map(|mut rule| {
                let err_msgs_result = rule.init();
                if err_msgs_result.is_ok() {
                    return Option::Some(rule);
                }

                // ruleファイルの初期化失敗時のエラーを表示する部分
                err_msgs_result.err().iter().for_each(|err_msgs| {
                    // TODO 本当はファイルパスを出力したい
                    // ParseYamlの変更が必要なので、一旦yamlのタイトルを表示。
                    println!(
                        "[Failed to parse Rule file. See following detail. rule file title:{}]",
                        rule.yaml["title"].as_str().unwrap_or("")
                    );
                    err_msgs.iter().for_each(|err_msg| println!("{}", err_msg));
                    println!("");
                });

                return Option::None;
            })
            .collect();

        // selection rule files and collect message
        let mut message = Message::new();
        selection_rules.iter().for_each(|rule| {
            &event_records
                .iter()
                .filter(|event_record| rule.select(event_record))
                .for_each(|event_record| {
                    let event_time = Detection::get_event_time(event_record);
                    // TODO ログから日付がとれない場合に本当は時刻不明という感じで表示したい。
                    // しかし、Messageクラスのinsertメソッドが、UTCクラスのインスタンスを必ず渡すようなインタフェースになっているので、
                    // やむなくUtc.ymd(1970, 1, 1).and_hms(0, 0, 0)を渡している。

                    // Messageクラスのinsertメソッドの引数をDateTime<UTC>からOption<DateTime<UTC>>に変更して、
                    // insertメソッドでOption::Noneが渡された場合に時刻不明だと分かるように表示させるような実装にした方がいいかも
                    let utc_event_time = event_time
                        .and_then(|datetime| {
                            let utc = Utc.from_local_datetime(&datetime.naive_utc()).unwrap();
                            return Option::Some(utc);
                        })
                        .or(Option::Some(Utc.ymd(1970, 1, 1).and_hms(0, 0, 0)));
                    message.insert(utc_event_time.unwrap(), event_record.to_string())
                });
        });

        // output message
        message.debug();
    }

    fn get_event_time(event_record: &Value) -> Option<DateTime<FixedOffset>> {
        let system_time =
            &event_record["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"];
        let system_time_str = system_time.as_str().unwrap_or("");
        if system_time_str.is_empty() {
            return Option::None;
        }

        return DateTime::parse_from_rfc3339(system_time_str).ok();
    }
}

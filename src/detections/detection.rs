extern crate chrono;
extern crate csv;

use crate::detections::print::MESSAGES;
use crate::detections::rule;
use crate::detections::rule::RuleNode;
use crate::yaml::ParseYaml;

use evtx::EvtxParser;
use serde_json::{Error, Value};

const DIRPATH_RULES: &str = "rules";

// TODO テストケースかかなきゃ...
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
        let mut selection_rules: Vec<RuleNode> = rulefile_loader
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

                    // TODO エラーの出力方法を統一したい。
                    // エラー出力用のクラスを作成してもいいかも
                    println!(
                        "[ERROR] Failed to parse Rule file. (Error Rule Title : {})",
                        rule.yaml["title"].as_str().unwrap_or("")
                    );
                    err_msgs.iter().for_each(|err_msg| println!("{}", err_msg));
                    println!("");
                });

                return Option::None;
            })
            .collect();

        // selection rule files and collect message
        let mut message = MESSAGES.lock().unwrap();
        selection_rules.iter_mut().for_each(|rule| {
            event_records.iter().for_each(|event_record| {
                if !rule.select(event_record) {
                    return;
                }

                message.insert(
                    event_record,
                    rule.yaml["output"].as_str().unwrap_or("").to_string(),
                )
            });
        });
    }
}

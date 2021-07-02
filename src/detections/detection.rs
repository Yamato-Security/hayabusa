extern crate csv;

use crate::detections::rule::AggResult;
use serde_json::Value;
use tokio::spawn;

use crate::detections::print::MESSAGES;
use crate::detections::rule;
use crate::detections::rule::RuleNode;
use crate::detections::{print::AlertMessage, utils};
use crate::yaml::ParseYaml;

use std::sync::Arc;

const DIRPATH_RULES: &str = "rules";

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス　ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
}

impl EvtxRecordInfo {
    pub fn new(evtx_filepath: String, record: Value) -> EvtxRecordInfo {
        return EvtxRecordInfo {
            evtx_filepath: evtx_filepath,
            record: record,
        };
    }
}

// TODO テストケースかかなきゃ...
#[derive(Debug)]
pub struct Detection {}

impl Detection {
    pub fn new() -> Detection {
        return Detection {};
    }

    pub fn start(&mut self, records: Vec<EvtxRecordInfo>) {
        let rules = self.parse_rule_files();
        if rules.is_empty() {
            return;
        }

        let tokio_rt = utils::create_tokio_runtime();
        tokio_rt.block_on(Detection::execute_rules(rules, records));
        tokio_rt.shutdown_background();
    }

    // ルールファイルをパースします。
    fn parse_rule_files(&self) -> Vec<RuleNode> {
        // ルールファイルのパースを実行
        let mut rulefile_loader = ParseYaml::new();
        let resutl_readdir = rulefile_loader.read_dir(DIRPATH_RULES);
        if resutl_readdir.is_err() {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            AlertMessage::alert(&mut stdout, format!("{}", resutl_readdir.unwrap_err())).ok();
            return vec![];
        }

        let return_if_success = |mut rule: RuleNode| {
            let err_msgs_result = rule.init();
            if err_msgs_result.is_ok() {
                return Option::Some(rule);
            }

            // ruleファイルのパースに失敗した場合はエラー出力
            err_msgs_result.err().iter().for_each(|err_msgs| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                let errmsg_body = format!(
                    "Failed to parse Rule file. (Error Rule Title : {})",
                    rule.yaml["title"].as_str().unwrap_or("")
                );
                AlertMessage::alert(&mut stdout, errmsg_body).ok();

                err_msgs.iter().for_each(|err_msg| {
                    AlertMessage::alert(&mut stdout, err_msg.to_string()).ok();
                });
                println!("");
            });
            return Option::None;
        };

        // parse rule files
        return rulefile_loader
            .files
            .into_iter()
            .map(|rule_file| rule::create_rule(rule_file))
            .filter_map(return_if_success)
            .collect();
    }

    async fn execute_rules(rules: Vec<RuleNode>, records: Vec<EvtxRecordInfo>) {
        let records_arc = Arc::new(records);
        let traiter = rules.into_iter();
        // 各rule毎にスレッドを作成して、スレッドを起動する。
        let handles = traiter.map(|rule| {
            let records_cloned = Arc::clone(&records_arc);
            return spawn(async move {
                Detection::execute_rule(rule, records_cloned);
            });
        });

        // 全スレッドの実行完了を待機
        for handle in handles {
            handle.await.unwrap();
        }
    }

    // 検知ロジックを実行します。
    fn execute_rule(mut rule: RuleNode, records: Arc<Vec<EvtxRecordInfo>>) {
        let records = &*records;
        let agg_condition = rule.has_agg_condition();
        for record_info in records {
            let result = rule.select(&record_info.evtx_filepath, &record_info.record);
            if !result {
                continue;
            }
            // aggregation conditionが存在しない場合はそのまま出力対応を行う
            if !agg_condition {
                Detection::insert_message(&rule, &record_info);
                return;
            }
        }

        let agg_results = rule.judge_satisfy_aggcondition();
        let output = &rule.yaml["output"].as_str().is_some();
        for value in agg_results {
            if agg_condition && !output {
                Detection::insert_agg_message(&rule, value);
            }
        }
    }

    /// 条件に合致したレコードを表示するための関数
    fn insert_message(rule: &RuleNode, record_info: &EvtxRecordInfo) {
        MESSAGES.lock().unwrap().insert(
            record_info.evtx_filepath.to_string(),
            &record_info.record,
            rule.yaml["title"].as_str().unwrap_or("").to_string(),
            rule.yaml["output"].as_str().unwrap_or("").to_string(),
        );
    }

    /// insert aggregation condition detection message tooutput stack
    fn insert_agg_message(rule: &RuleNode, agg_result: AggResult) {
        let output = "".to_string();
        MESSAGES.lock().unwrap().insert_message(
            agg_result.filepath,
            agg_result.start_timedate,
            rule.yaml["title"].as_str().unwrap_or("").to_string(),
            output,
        )
    }
}

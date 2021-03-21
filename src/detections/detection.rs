extern crate csv;

use crate::detections::print::MESSAGES;
use crate::detections::rule;
use crate::detections::rule::RuleNode;
use crate::yaml::ParseYaml;

use evtx::err;
use evtx::{EvtxParser, ParserSettings, SerializedEvtxRecord};
use serde_json::{Error, Value};
use tokio::runtime;
use tokio::{spawn, task::JoinHandle};

use std::{fs::File, sync::Arc};
use std::{path::PathBuf, time::Instant};

const DIRPATH_RULES: &str = "rules";

// TODO テストケースかかなきゃ...
#[derive(Debug)]
pub struct Detection {}

impl Detection {
    pub fn new() -> Detection {
        Detection {}
    }

    pub fn start(&mut self, evtx_files: Vec<PathBuf>) {
        if evtx_files.is_empty() {
            return;
        }

        // parse rule files
        let rules = self.parse_rule_files();
        if rules.is_empty() {
            return;
        }

        // transform from evtx files into json
        let records = self.evtx_to_jsons(evtx_files);

        runtime::Runtime::new()
            .unwrap()
            .block_on(self.execute_rule(rules, records));
    }

    fn parse_rule_files(&self) -> Vec<RuleNode> {
        // load rule files
        let mut rulefile_loader = ParseYaml::new();
        let resutl_readdir = rulefile_loader.read_dir(DIRPATH_RULES);
        if resutl_readdir.is_err() {
            eprintln!("{}", resutl_readdir.unwrap_err());
            return vec![];
        }

        // parse rule files
        return rulefile_loader
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
    }

    // evtxファイルをjsonに変換する。
    fn evtx_to_jsons(&mut self, evtx_files: Vec<PathBuf>) -> Vec<Value> {
        // EvtxParserを生成する。
        let evtx_parsers: Vec<EvtxParser<File>> = evtx_files
            .iter()
            .filter_map(|evtx_file| {
                // convert to evtx parser
                match EvtxParser::from_path(evtx_file) {
                    Ok(parser) => Option::Some(parser),
                    Err(e) => {
                        eprintln!("{}", e);
                        return Option::None;
                    }
                }
            })
            .collect();

        let xml_records = runtime::Runtime::new()
            .unwrap()
            .block_on(self.evtx_to_xml(evtx_parsers));

        return runtime::Runtime::new()
            .unwrap()
            .block_on(self.xml_to_json(xml_records));
    }

    // evtxファイルからxmlを生成する。
    async fn evtx_to_xml(
        &mut self,
        evtx_parsers: Vec<EvtxParser<File>>,
    ) -> Vec<SerializedEvtxRecord<String>> {
        // evtx_parser.records_json()でevtxをxmlに変換するJobを作成
        let handles: Vec<JoinHandle<Vec<err::Result<SerializedEvtxRecord<String>>>>> = evtx_parsers
            .into_iter()
            .map(|mut evtx_parser| {
                return spawn(async move {
                    let mut parse_config = ParserSettings::default();
                    parse_config = parse_config.separate_json_attributes(true);
                    evtx_parser = evtx_parser.with_configuration(parse_config);
                    let values = evtx_parser.records_json().collect();
                    return values;
                });
            })
            .collect();

        // 作成したjobを実行し(handle.awaitの部分)、スレッドの実行時にエラーが発生した場合、標準エラー出力に出しておく
        let mut ret = vec![];
        for handle in handles {
            let future_result = handle.await;
            if future_result.is_err() {
                eprintln!("{}", future_result.unwrap_err());
                continue;
            }

            ret.push(future_result.unwrap());
        }

        // xmlの変換でエラーが出た場合、標準エラー出力に出しておく
        return ret
            .into_iter()
            .flatten()
            .filter_map(|parse_result| {
                if parse_result.is_err() {
                    eprintln!("{}", parse_result.unwrap_err());
                    return Option::None;
                }

                return Option::Some(parse_result.unwrap());
            })
            .collect();
    }

    async fn xml_to_json(&mut self, xml_records: Vec<SerializedEvtxRecord<String>>) -> Vec<Value> {
        // xmlからjsonに変換するJobを作成
        let handles: Vec<JoinHandle<Result<Value, Error>>> = xml_records
            .into_iter()
            .map(|xml_record| {
                return spawn(async move {
                    return serde_json::from_str(&xml_record.data);
                });
            })
            .collect();

        // 作成したjobを実行し(handle.awaitの部分)、スレッドの実行時にエラーが発生した場合、標準エラー出力に出しておく
        let mut ret = vec![];
        for handle in handles {
            let future_result = handle.await;
            if future_result.is_err() {
                eprintln!("{}", future_result.unwrap_err());
                continue;
            }

            ret.push(future_result.unwrap());
        }

        // xmlの変換でエラーが出た場合、標準エラー出力に出しておく
        return ret
            .into_iter()
            .filter_map(|parse_result| {
                if parse_result.is_err() {
                    eprintln!("{}", parse_result.unwrap_err());
                    return Option::None;
                }

                return Option::Some(parse_result.unwrap());
            })
            .collect();
    }

    async fn execute_rule(&mut self, rules: Vec<RuleNode>, records: Vec<Value>) {
        // 排他制御と所有権共有のため、recordをRwLockとArcで囲む
        // recordは不変参照(mutが不要)なので、不変参照なら複数スレッドが同時にロックを取得できるようにRwLockを用いている。
        // RwLockの代わりにMutexを使うこともできるが、これは不変参照であっても同時に1スレッドしかロックを取得できず、パフォーマンスが良くないと思う。
        let mut records_arcs = vec![];
        for record_chunk in Detection::chunks(records, num_cpus::get() * 4) {
            let record_chunk_arc = Arc::new(record_chunk);
            records_arcs.push(record_chunk_arc);
        }

        // 所有権共有のため、ruleをArcで囲む
        let rules_arc = Arc::new(rules);

        // ルール実行するスレッドを作成。
        let mut handles = vec![];
        for record_chunk_arc in &records_arcs {
            let records_arc_clone = Arc::clone(&record_chunk_arc);
            let rules_clones = Arc::clone(&rules_arc);

            let handle: JoinHandle<Vec<bool>> = spawn(async move {
                let mut ret = vec![];
                for record in records_arc_clone.iter() {
                    for rule in rules_clones.iter() {
                        if rule.select(record) {
                            // TODO ここはtrue/falseじゃなくて、ruleとrecordのタプルをretにpushする実装に変更したい。
                            ret.push(true);
                        } else {
                            ret.push(false);
                        }
                    }
                }
                return ret;
            });
            handles.push(handle);
        }

        // メッセージを追加する。これを上記のspawnの中でやると、ロックの取得で逆に時間がかかるので、外に出す
        let mut message = MESSAGES.lock().unwrap();
        let mut handles_ite = handles.into_iter();
        for record_chunk_arc in &records_arcs {
            let mut handles_ret_ite = handles_ite.next().unwrap().await.unwrap().into_iter();
            for rule in rules_arc.iter() {
                for record_arc in record_chunk_arc.iter() {
                    if handles_ret_ite.next().unwrap() == true {
                        // TODO メッセージが多いと、rule.select()よりもこの処理の方が時間かかる。
                        message.insert(
                            record_arc,
                            rule.yaml["title"].as_str().unwrap_or("").to_string(),
                            rule.yaml["output"].as_str().unwrap_or("").to_string(),
                        );
                    }
                }
            }
        }
    }

    // 配列を指定したサイズで分割する。Vector.chunksと同じ動作をするが、Vectorの関数だとinto的なことができないので自作
    fn chunks(ary: Vec<Value>, size: usize) -> Vec<Vec<Value>> {
        let arylen = ary.len();
        let mut ite = ary.into_iter();

        let mut ret = vec![];
        for i in 0..arylen {
            if i % size == 0 {
                ret.push(vec![]);
                ret.iter_mut().last().unwrap().push(ite.next().unwrap());
            } else {
                ret.iter_mut().last().unwrap().push(ite.next().unwrap());
            }
        }

        return ret;
    }
}

extern crate csv;

use crate::detections::print::AlertMessage;
use crate::detections::print::MESSAGES;
use crate::detections::rule;
use crate::detections::rule::RuleNode;
use crate::yaml::ParseYaml;

use evtx::err;
use evtx::{EvtxParser, ParserSettings, SerializedEvtxRecord};
use serde_json::{Error, Value};
use tokio::runtime;
use tokio::{spawn, task::JoinHandle};

use std::{collections::HashSet, path::PathBuf};
use std::{fs::File, sync::Arc};

const DIRPATH_RULES: &str = "rules";

#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    evtx_filepath: String,
    record: Value,
}

// TODO テストケースかかなきゃ...
#[derive(Debug)]
pub struct Detection {
    parseinfos: Vec<EvtxRecordInfo>,
}

impl Detection {
    pub fn new() -> Detection {
        let initializer: Vec<EvtxRecordInfo> = Vec::new();
        Detection {
            parseinfos: initializer,
        }
    }

    pub fn start(&mut self, evtx_files: Vec<PathBuf>) {
        if evtx_files.is_empty() {
            return;
        }

        let rules = self.parse_rule_files();
        if rules.is_empty() {
            return;
        }

        let records = self.evtx_to_jsons(evtx_files, &rules);
        runtime::Runtime::new()
            .unwrap()
            .block_on(self.execute_rule(rules, records));
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
            .map(|rule_file| rule::parse_rule(rule_file))
            .filter_map(return_if_success)
            .collect();
    }

    // evtxファイルをjsonに変換します。
    fn evtx_to_jsons(
        &mut self,
        evtx_files: Vec<PathBuf>,
        rules: &Vec<RuleNode>,
    ) -> Vec<EvtxRecordInfo> {
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
            .block_on(self.evtx_to_xml(evtx_parsers, &evtx_files));
        let json_records = runtime::Runtime::new().unwrap().block_on(self.xml_to_json(
            xml_records,
            &evtx_files,
            &rules,
        ));

        return json_records
            .into_iter()
            .map(|(parser_idx, json_record)| {
                let evtx_filepath = evtx_files[parser_idx].display().to_string();
                return EvtxRecordInfo {
                    evtx_filepath: String::from(&evtx_filepath),
                    record: json_record,
                };
            })
            .collect();
    }

    // evtxファイルからxmlを生成する。
    // 戻り値は「どのイベントファイルから生成されたXMLかを示すindex」と「変換されたXML」のタプルです。
    // タプルのindexは、引数で指定されるevtx_filesのindexに対応しています。
    async fn evtx_to_xml(
        &mut self,
        evtx_parsers: Vec<EvtxParser<File>>,
        evtx_files: &Vec<PathBuf>,
    ) -> Vec<(usize, SerializedEvtxRecord<String>)> {
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
        for (parser_idx, handle) in handles.into_iter().enumerate() {
            let future_result = handle.await;
            if future_result.is_err() {
                let evtx_filepath = &evtx_files[parser_idx].display();
                let errmsg = format!(
                    "Failed to parse event file. EventFile:{} Error:{}",
                    evtx_filepath,
                    future_result.unwrap_err()
                );
                AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                continue;
            }

            future_result.unwrap().into_iter().for_each(|parse_result| {
                ret.push((parser_idx, parse_result));
            });
        }

        return ret
            .into_iter()
            .filter_map(|(parser_idx, parse_result)| {
                if parse_result.is_err() {
                    let evtx_filepath = &evtx_files[parser_idx].display();
                    let errmsg = format!(
                        "Failed to parse event file. EventFile:{} Error:{}",
                        evtx_filepath,
                        parse_result.unwrap_err()
                    );
                    AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                    return Option::None;
                }
                return Option::Some((parser_idx, parse_result.unwrap()));
            })
            .collect();
    }

    // xmlからjsonに変換します。
    // 戻り値は「どのイベントファイルから生成されたXMLかを示すindex」と「変換されたJSON」のタプルです。
    // タプルのindexは、引数で指定されるevtx_filesのindexに対応しています。
    async fn xml_to_json(
        &mut self,
        xml_records: Vec<(usize, SerializedEvtxRecord<String>)>,
        evtx_files: &Vec<PathBuf>,
        rules: &Vec<RuleNode>,
    ) -> Vec<(usize, Value)> {
        // 非同期で実行される処理
        let async_job = |pair: (usize, SerializedEvtxRecord<String>)| {
            let parser_idx = pair.0;
            let handle = spawn(async move {
                return serde_json::from_str(&pair.1.data);
            });

            return (parser_idx, handle);
        };
        // 非同期で実行するスレッドを生成し、実行する。
        let handles: Vec<(usize, JoinHandle<Result<Value, Error>>)> =
            xml_records.into_iter().map(async_job).collect();

        // スレッドの終了待ちをしている。
        let mut ret = vec![];
        for (parser_idx, handle) in handles {
            let future = handle.await;
            if future.is_err() {
                // スレッドが正常に完了しなかった場合はエラーメッセージを出力する。
                let evtx_filepath = &evtx_files[parser_idx].display();
                let errmsg = format!(
                    "Failed to serialize from event xml to json. EventFile:{} Error:{}",
                    evtx_filepath,
                    future.unwrap_err()
                );
                AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                continue;
            }

            let parse_result = future.unwrap();
            ret.push((parser_idx, parse_result));
        }

        // JSONの変換に失敗したものを除外して、返す。
        return ret
            .into_iter()
            .filter_map(|(parser_idx, parse_result)| {
                if parse_result.is_err() {
                    let evtx_filepath = &evtx_files[parser_idx].display();
                    let errmsg = format!(
                        "Failed to serialize from event xml to json. EventFile:{} Error:{}",
                        evtx_filepath,
                        parse_result.unwrap_err()
                    );
                    AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                    return Option::None;
                }

                let ret_elem = (parser_idx, parse_result.unwrap());
                return Option::Some(ret_elem);
            })
            .collect();
    }

    // 検知ロジックを実行します。
    async fn execute_rule(&mut self, rules: Vec<RuleNode>, records: Vec<EvtxRecordInfo>) {
        // 複数スレッドで所有権を共有するため、recordsをArcでwwap
        let mut records_arcs = vec![];
        for record_chunk in Detection::chunks(records, num_cpus::get() * 4) {
            let record_chunk_arc = Arc::new(record_chunk);
            records_arcs.push(record_chunk_arc);
        }

        // 複数スレッドで所有権を共有するため、rulesをArcでwwap
        let rules_arc = Arc::new(rules);

        // ルール実行するスレッドを作成。
        let mut handles = vec![];
        for record_chunk_arc in &records_arcs {
            let records_arc_clone = Arc::clone(&record_chunk_arc);
            let rules_clones = Arc::clone(&rules_arc);

            let handle: JoinHandle<Vec<bool>> = spawn(async move {
                let mut ret = vec![];
                for record_info in records_arc_clone.iter() {
                    for rule in rules_clones.iter() {
                        if rule.select(&record_info.record) {
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
                for record_info_arc in record_chunk_arc.iter() {
                    if handles_ret_ite.next().unwrap() == false {
                        continue;
                    }

                    // TODO メッセージが多いと、rule.select()よりもこの処理の方が時間かかる。
                    message.insert(
                        record_info_arc.evtx_filepath.to_string(),
                        &record_info_arc.record,
                        rule.yaml["title"].as_str().unwrap_or("").to_string(),
                        rule.yaml["output"].as_str().unwrap_or("").to_string(),
                    );
                }
            }
        }
    }

    fn get_event_ids(rules: &Vec<RuleNode>) -> HashSet<i64> {
        return rules
            .iter()
            .map(|rule| rule.get_event_ids())
            .flatten()
            .collect();
    }

    // 配列を指定したサイズで分割する。Vector.chunksと同じ動作をするが、Vectorの関数だとinto的なことができないので自作
    fn chunks<T>(ary: Vec<T>, size: usize) -> Vec<Vec<T>> {
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

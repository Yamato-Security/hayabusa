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

use std::path::PathBuf;
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

        let records = self.evtx_to_jsons(evtx_files);
        runtime::Runtime::new()
            .unwrap()
            .block_on(self.execute_rule(rules, records));
    }

    // ルールファイルをパースします。
    fn parse_rule_files(&self) -> Vec<RuleNode> {
        // load rule files
        let mut rulefile_loader = ParseYaml::new();
        let resutl_readdir = rulefile_loader.read_dir(DIRPATH_RULES);
        if resutl_readdir.is_err() {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            AlertMessage::alert(&mut stdout, format!("{}", resutl_readdir.unwrap_err())).ok();
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
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    AlertMessage::alert(
                        &mut stdout,
                        format!(
                            "Failed to parse Rule file. (Error Rule Title : {})",
                            rule.yaml["title"].as_str().unwrap_or("")
                        ),
                    )
                    .ok();
                    err_msgs.iter().for_each(|err_msg| {
                        AlertMessage::alert(&mut stdout, err_msg.to_string()).ok();
                    });
                    println!("");
                });

                return Option::None;
            })
            .collect();
    }

    // evtxファイルをjsonに変換します。
    fn evtx_to_jsons(&mut self, evtx_files: Vec<PathBuf>) -> Vec<EvtxRecordInfo> {
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
        let json_records = runtime::Runtime::new()
            .unwrap()
            .block_on(self.xml_to_json(xml_records, &evtx_files));

        let mut evtx_file_index = 0;
        return json_records
            .into_iter()
            .map(|json_records_per_evtxfile| {
                let evtx_filepath = evtx_files[evtx_file_index].display().to_string();
                let ret: Vec<EvtxRecordInfo> = json_records_per_evtxfile
                    .into_iter()
                    .map(|json_record| {
                        return EvtxRecordInfo {
                            evtx_filepath: String::from(&evtx_filepath),
                            record: json_record,
                        };
                    })
                    .collect();
                evtx_file_index = evtx_file_index + 1;
                return ret;
            })
            .flatten()
            .collect();
    }

    // evtxファイルからxmlを生成する。
    // ちょっと分かりにくいですが、戻り値の型はVec<SerializedEvtxRecord<String>>ではなくて、Vec<Vec<SerializedEvtxRecord<String>>>になっています。
    // 2次元配列にしている理由は、この後Value型(EvtxのXMLをJSONに変換したやつ)とイベントファイルのパスをEvtxRecordInfo構造体で保持するためです。
    // EvtxParser毎にSerializedEvtxRecord<String>をグルーピングするために2次元配列にしています。
    async fn evtx_to_xml(
        &mut self,
        evtx_parsers: Vec<EvtxParser<File>>,
        evtx_files: &Vec<PathBuf>,
    ) -> Vec<Vec<SerializedEvtxRecord<String>>> {
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
        let mut evtx_file_index = 0;
        for handle in handles {
            let future_result = handle.await;
            if future_result.is_err() {
                let evtx_filepath = &evtx_files[evtx_file_index].display();
                let errmsg = format!(
                    "Failed to parse event file. EventFile:{} Error:{}",
                    evtx_filepath,
                    future_result.unwrap_err()
                );
                AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                continue;
            }

            evtx_file_index = evtx_file_index + 1;
            ret.push(future_result.unwrap());
        }

        // パースに失敗しているレコードを除外して、返す。
        // SerializedEvtxRecord<String>がどのEvtxParserからパースされたのか分かるようにするため、2次元配列のまま返す。
        let mut evtx_file_index = 0;
        return ret
            .into_iter()
            .map(|parse_results| {
                let ret = parse_results
                    .into_iter()
                    .filter_map(|parse_result| {
                        if parse_result.is_err() {
                            let evtx_filepath = &evtx_files[evtx_file_index].display();
                            let errmsg = format!(
                                "Failed to parse event file. EventFile:{} Error:{}",
                                evtx_filepath,
                                parse_result.unwrap_err()
                            );
                            AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                            return Option::None;
                        }
                        return Option::Some(parse_result.unwrap());
                    })
                    .collect();
                evtx_file_index = evtx_file_index + 1;
                return ret;
            })
            .collect();
    }

    // xmlからjsonに変換します。
    async fn xml_to_json(
        &mut self,
        xml_records: Vec<Vec<SerializedEvtxRecord<String>>>,
        evtx_files: &Vec<PathBuf>,
    ) -> Vec<Vec<Value>> {
        // xmlからjsonに変換するJobを作成
        let handles: Vec<Vec<JoinHandle<Result<Value, Error>>>> = xml_records
            .into_iter()
            .map(|xml_records| {
                return xml_records
                    .into_iter()
                    .map(|xml_record| {
                        return spawn(async move {
                            return serde_json::from_str(&xml_record.data);
                        });
                    })
                    .collect();
            })
            .collect();

        // 作成したjobを実行し(handle.awaitの部分)、スレッドの実行時にエラーが発生した場合、標準エラー出力に出しておく
        let mut ret = vec![];
        let mut evtx_file_index = 0;
        for handles_per_evtxfile in handles {
            let mut sub_ret = vec![];
            for handle in handles_per_evtxfile {
                let future_result = handle.await;
                if future_result.is_err() {
                    let evtx_filepath = &evtx_files[evtx_file_index].display();
                    let errmsg = format!(
                        "Failed to serialize from event xml to json. EventFile:{} Error:{}",
                        evtx_filepath,
                        future_result.unwrap_err()
                    );
                    AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                    continue;
                }

                sub_ret.push(future_result.unwrap());
            }
            ret.push(sub_ret);
            evtx_file_index = evtx_file_index + 1;
        }

        // JSONの変換に失敗したものを除外して、返す。
        // ValueがどのEvtxParserからパースされたのか分かるようにするため、2次元配列のまま返す。
        let mut evtx_file_index = 0;
        return ret
            .into_iter()
            .map(|parse_results| {
                let successed = parse_results
                    .into_iter()
                    .filter_map(|parse_result| {
                        if parse_result.is_err() {
                            let evtx_filepath = &evtx_files[evtx_file_index].display();
                            let errmsg = format!(
                                "Failed to serialize from event xml to json. EventFile:{} Error:{}",
                                evtx_filepath,
                                parse_result.unwrap_err()
                            );
                            AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                            return Option::None;
                        }

                        return Option::Some(parse_result.unwrap());
                    })
                    .collect();
                evtx_file_index = evtx_file_index + 1;

                return successed;
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

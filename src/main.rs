extern crate serde;
extern crate serde_derive;

use evtx::{err, EvtxParser, ParserSettings, SerializedEvtxRecord};
use std::{
    fs::{self, File},
    path::PathBuf,
};
use tokio::{spawn, task::JoinHandle};
use yamato_event_analyzer::detections::detection;
use yamato_event_analyzer::detections::detection::EvtxRecordInfo;
use yamato_event_analyzer::detections::print::AlertMessage;
use yamato_event_analyzer::omikuji::Omikuji;
use yamato_event_analyzer::{afterfact::after_fact, detections::utils};
use yamato_event_analyzer::{detections::configs, timeline::timeline::Timeline};

fn main() {
    if let Some(filepath) = configs::CONFIG.read().unwrap().args.value_of("filepath") {
        detect_files(vec![PathBuf::from(filepath)]);
    } else if let Some(directory) = configs::CONFIG.read().unwrap().args.value_of("directory") {
        let evtx_files = collect_evtxfiles(&directory);
        detect_files(evtx_files);
    } else if configs::CONFIG.read().unwrap().args.is_present("credits") {
        print_credits();
    }
}

fn collect_evtxfiles(dirpath: &str) -> Vec<PathBuf> {
    let entries = fs::read_dir(dirpath);
    if entries.is_err() {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        AlertMessage::alert(&mut stdout, format!("{}", entries.unwrap_err())).ok();
        return vec![];
    }

    let mut ret = vec![];
    for e in entries.unwrap() {
        if e.is_err() {
            continue;
        }

        let path = e.unwrap().path();
        if path.is_dir() {
            path.to_str().and_then(|path_str| {
                let subdir_ret = collect_evtxfiles(path_str);
                ret.extend(subdir_ret);
                return Option::Some(());
            });
        } else {
            let path_str = path.to_str().unwrap_or("");
            if path_str.ends_with(".evtx") {
                ret.push(path);
            }
        }
    }

    return ret;
}

fn print_credits() {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    match fs::read_to_string("./credits.txt") {
        Ok(contents) => println!("{}", contents),
        Err(err) => {
            AlertMessage::alert(&mut stdout, format!("{}", err)).ok();
        }
    }
}

fn detect_files(evtx_files: Vec<PathBuf>) {
    let evnt_records = evtx_to_jsons(&evtx_files);

    let mut tl = Timeline::new();
    tl.start(&evnt_records);

    let mut detection = detection::Detection::new();
    &detection.start(evnt_records);

    after_fact();
}

// evtxファイルをjsonに変換します。
fn evtx_to_jsons(evtx_files: &Vec<PathBuf>) -> Vec<EvtxRecordInfo> {
    // EvtxParserを生成する。
    let evtx_parsers: Vec<EvtxParser<File>> = evtx_files
        .clone()
        .into_iter()
        .filter_map(|evtx_file| {
            // convert to evtx parser
            // println!("PathBuf:{}", evtx_file.display());
            match EvtxParser::from_path(evtx_file) {
                Ok(parser) => Option::Some(parser),
                Err(e) => {
                    eprintln!("{}", e);
                    return Option::None;
                }
            }
        })
        .collect();

    let tokio_rt = utils::create_tokio_runtime();
    let ret = tokio_rt.block_on(evtx_to_json(evtx_parsers, &evtx_files));
    tokio_rt.shutdown_background();

    return ret;
}

// evtxファイルからEvtxRecordInfoを生成する。
// 戻り値は「どのイベントファイルから生成されたXMLかを示すindex」と「変換されたXML」のタプルです。
// タプルのindexは、引数で指定されるevtx_filesのindexに対応しています。
async fn evtx_to_json(
    evtx_parsers: Vec<EvtxParser<File>>,
    evtx_files: &Vec<PathBuf>,
) -> Vec<EvtxRecordInfo> {
    // evtx_parser.records_json()でevtxをxmlに変換するJobを作成
    let handles: Vec<JoinHandle<Vec<err::Result<SerializedEvtxRecord<serde_json::Value>>>>> =
        evtx_parsers
            .into_iter()
            .map(|mut evtx_parser| {
                return spawn(async move {
                    let mut parse_config = ParserSettings::default();
                    parse_config = parse_config.separate_json_attributes(true);
                    parse_config = parse_config.num_threads(utils::get_thread_num());

                    evtx_parser = evtx_parser.with_configuration(parse_config);
                    let values = evtx_parser.records_json_value().collect();
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
            // パースに失敗している場合、エラーメッセージを出力
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

            let record_info = EvtxRecordInfo::new(
                evtx_files[parser_idx].display().to_string(),
                parse_result.unwrap().data,
            );
            return Option::Some(record_info);
        })
        .collect();
}

fn _output_with_omikuji(omikuji: Omikuji) {
    let fp = &format!("art/omikuji/{}", omikuji);
    let content = fs::read_to_string(fp).unwrap();
    println!("{}", content);
}

#[cfg(test)]
mod tests {
    use crate::collect_evtxfiles;

    #[test]
    fn test_collect_evtxfiles() {
        let files = collect_evtxfiles("test_files/evtx");
        assert_eq!(3, files.len());

        files.iter().for_each(|file| {
            let is_contains = &vec!["test1.evtx", "test2.evtx", "testtest4.evtx"]
                .into_iter()
                .any(|filepath_str| {
                    return file.file_name().unwrap().to_str().unwrap_or("") == filepath_str;
                });
            assert_eq!(is_contains, &true);
        })
    }
}

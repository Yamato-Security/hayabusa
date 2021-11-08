extern crate serde;
extern crate serde_derive;

use evtx::{EvtxParser, ParserSettings};
use hayabusa::detections::detection;
use hayabusa::detections::detection::EvtxRecordInfo;
use hayabusa::detections::print::AlertMessage;
use hayabusa::omikuji::Omikuji;
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timeline::Timeline};
use std::{
    fs::{self, File},
    path::PathBuf,
    vec,
};

// 一度にtimelineやdetectionを実行する行数
const MAX_DETECT_RECORDS: usize = 40000;

fn main() {
    if configs::CONFIG.read().unwrap().args.args.len() == 0 {
        println!(
            "{}",
            configs::CONFIG.read().unwrap().args.usage().to_string()
        );
        return;
    }

    if let Some(filepath) = configs::CONFIG.read().unwrap().args.value_of("filepath") {
        analysis_files(vec![PathBuf::from(filepath)]);
    } else if let Some(directory) = configs::CONFIG.read().unwrap().args.value_of("directory") {
        let evtx_files = collect_evtxfiles(&directory);
        analysis_files(evtx_files);
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

fn analysis_files(evtx_files: Vec<PathBuf>) {
    let mut detection = detection::Detection::new(detection::Detection::parse_rule_files());

    for evtx_file in evtx_files {
        let ret = analysis_file(evtx_file, detection);
        detection = ret;
    }

    after_fact();
}

// Windowsイベントログファイルを1ファイル分解析する。
fn analysis_file(
    evtx_filepath: PathBuf,
    mut detection: detection::Detection,
) -> detection::Detection {
    let filepath_disp = evtx_filepath.display();
    let parser = evtx_to_jsons(evtx_filepath.clone());
    if parser.is_none() {
        return detection;
    }

    let mut tl = Timeline::new();
    let mut parser = parser.unwrap();
    let mut records = parser.records_json_value();
    let tokio_rt = utils::create_tokio_runtime();

    loop {
        let mut records_per_detect = vec![];
        while records_per_detect.len() < MAX_DETECT_RECORDS {
            // パースに失敗している場合、エラーメッセージを出力
            let next_rec = records.next();
            if next_rec.is_none() {
                break;
            }

            let record_result = next_rec.unwrap();
            if record_result.is_err() {
                let evtx_filepath = &filepath_disp;
                let errmsg = format!(
                    "Failed to parse event file. EventFile:{} Error:{}",
                    evtx_filepath,
                    record_result.unwrap_err()
                );
                AlertMessage::alert(&mut std::io::stdout().lock(), errmsg).ok();
                continue;
            }

            let record_info =
                EvtxRecordInfo::new((&filepath_disp).to_string(), record_result.unwrap().data);
            records_per_detect.push(record_info);
        }
        if records_per_detect.len() == 0 {
            break;
        }

        // timeline機能の実行
        tl.start(&records_per_detect);

        // ruleファイルの検知
        detection = detection.start(&tokio_rt, records_per_detect);
    }

    tokio_rt.shutdown_background();
    detection.add_aggcondtion_msg();
    tl.tm_stats_dsp_msg();

    return detection;
}

fn evtx_to_jsons(evtx_filepath: PathBuf) -> Option<EvtxParser<File>> {
    match EvtxParser::from_path(evtx_filepath) {
        Ok(evtx_parser) => {
            // parserのデフォルト設定を変更
            let mut parse_config = ParserSettings::default();
            parse_config = parse_config.separate_json_attributes(true); // XMLのattributeをJSONに変換する時のルールを設定
            parse_config = parse_config.num_threads(utils::get_thread_num()); // 設定しないと遅かったので、設定しておく。

            let evtx_parser = evtx_parser.with_configuration(parse_config);
            return Option::Some(evtx_parser);
        }
        Err(e) => {
            eprintln!("{}", e);
            return Option::None;
        }
    }
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

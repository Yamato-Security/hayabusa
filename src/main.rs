extern crate serde;
extern crate serde_derive;

use chrono::{DateTime, Utc};
use evtx::{EvtxParser, ParserSettings};
use hayabusa::detections::detection;
use hayabusa::detections::detection::EvtxRecordInfo;
use hayabusa::detections::print::AlertMessage;
use hayabusa::omikuji::Omikuji;
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timeline::Timeline};
use hhmmss::Hhmmss;
use pbr::ProgressBar;
use serde_json::Value;
use std::{
    fs::{self, File},
    path::PathBuf,
    vec,
};

// 一度にtimelineやdetectionを実行する行数
const MAX_DETECT_RECORDS: usize = 40000;

fn main() {
    if !configs::CONFIG.read().unwrap().args.is_present("q") {
        output_logo();
        println!("");
    }
    if configs::CONFIG.read().unwrap().args.args.len() == 0 {
        println!(
            "{}",
            configs::CONFIG.read().unwrap().args.usage().to_string()
        );
        return;
    }
    let analysis_start_time: DateTime<Utc> = Utc::now();
    if let Some(filepath) = configs::CONFIG.read().unwrap().args.value_of("filepath") {
        if !filepath.ends_with(".evtx") {
            AlertMessage::alert(
                &mut std::io::stderr().lock(),
                "--filepath only accepts .evtx files.".to_owned(),
            )
            .ok();
            return;
        }
        analysis_files(vec![PathBuf::from(filepath)]);
    } else if let Some(directory) = configs::CONFIG.read().unwrap().args.value_of("directory") {
        let evtx_files = collect_evtxfiles(&directory);
        if evtx_files.len() == 0 {
            AlertMessage::alert(
                &mut std::io::stderr().lock(),
                "No .evtx files were found.".to_owned(),
            )
            .ok();
            return;
        }
        analysis_files(evtx_files);
    } else if configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("contributors")
    {
        print_contributors();
        return;
    }
    let analysis_end_time: DateTime<Utc> = Utc::now();
    let analysis_duration = analysis_end_time.signed_duration_since(analysis_start_time);
    println!("Elapsed Time: {}", &analysis_duration.hhmmssxxx());
    println!("");
}

fn collect_evtxfiles(dirpath: &str) -> Vec<PathBuf> {
    let entries = fs::read_dir(dirpath);
    if entries.is_err() {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        AlertMessage::alert(&mut stderr, format!("{}", entries.unwrap_err())).ok();
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

fn print_contributors() {
    match fs::read_to_string("./contributors.txt") {
        Ok(contents) => println!("{}", contents),
        Err(err) => {
            AlertMessage::alert(&mut std::io::stderr().lock(), format!("{}", err)).ok();
        }
    }
}

fn analysis_files(evtx_files: Vec<PathBuf>) {
    let level = configs::CONFIG
        .read()
        .unwrap()
        .args
        .value_of("level")
        .unwrap_or("informational")
        .to_uppercase();

    // // TODO: config.rs に移す
    // // ./target/debug/hayabusa -f ./test_files/evtx/test1.evtx --start-time 2014-11-28T12:00:09Z
    // let start_time =
    //     if let Some(s_time) = configs::CONFIG.read().unwrap().args.value_of("start-time") {
    //         match s_time.parse::<DateTime<Utc>>() {
    //             Ok(dt) => Some(dt),
    //             Err(err) => {
    //                 AlertMessage::alert(
    //                     &mut std::io::stderr().lock(),
    //                     format!("start-time field: {}", err),
    //                 )
    //                 .ok();
    //                 None
    //             }
    //         }
    //     } else {
    //         None
    //     };

    // let end_time = if let Some(e_time) = configs::CONFIG.read().unwrap().args.value_of("end-time") {
    //     match e_time.parse::<DateTime<Utc>>() {
    //         Ok(dt) => Some(dt),
    //         Err(err) => {
    //             AlertMessage::alert(
    //                 &mut std::io::stderr().lock(),
    //                 format!("start-time field: {}", err),
    //             )
    //             .ok();
    //             None
    //         }
    //     }
    // } else {
    //     None
    // };

    // println!("TIME: {:?}", start_time);
    println!("Analyzing Event Files: {:?}", evtx_files.len());
    let rule_files = detection::Detection::parse_rule_files(
        level,
        configs::CONFIG.read().unwrap().args.value_of("rules"),
    );
    let mut pb = ProgressBar::new(evtx_files.len() as u64);
    let mut detection = detection::Detection::new(rule_files);
    for evtx_file in evtx_files {
        if configs::CONFIG.read().unwrap().args.is_present("verbose") {
            println!("Checking target evtx FilePath: {:?}", &evtx_file);
        }
        detection = analysis_file(evtx_file, detection);
        pb.inc();
    }
    after_fact();
    detection.print_unique_results();
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

    let target_event_time = configs::TargetEventTime::new();

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
                AlertMessage::alert(&mut std::io::stderr().lock(), errmsg).ok();
                continue;
            }

            let data = record_result.unwrap().data;

            // target_eventids.txtでフィルタする。
            let eventid = utils::get_event_value(&utils::get_event_id_key(), &data);
            if eventid.is_some() {
                let is_target = match eventid.unwrap() {
                    Value::String(s) => utils::is_target_event_id(s),
                    Value::Number(n) => utils::is_target_event_id(&n.to_string()),
                    _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
                };
                if !is_target {
                    continue;
                }
            }

            let eventtime = utils::get_event_value(&utils::get_event_time(), &data);
            if eventtime.is_some() {
                let time = utils::str_time_to_datetime(eventtime.unwrap().as_str().unwrap_or(""));
                if !target_event_time.is_target(&time) {
                    continue;
                }
            }

            // EvtxRecordInfo構造体に変更
            let data_string = data.to_string();
            let record_info = EvtxRecordInfo::new((&filepath_disp).to_string(), data, data_string);
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

fn output_logo() {
    let fp = &format!("art/logo.txt");
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

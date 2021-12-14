extern crate serde;
extern crate serde_derive;

use chrono::Datelike;
use chrono::{DateTime, Local};
use evtx::{EvtxParser, ParserSettings};
use hayabusa::detections::detection;
use hayabusa::detections::detection::EvtxRecordInfo;
use hayabusa::detections::print::AlertMessage;
use hayabusa::filter;
use hayabusa::omikuji::Omikuji;
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timeline::Timeline};
use hhmmss::Hhmmss;
use pbr::ProgressBar;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Display;
use std::{
    fs::{self, File},
    path::PathBuf,
    vec,
};

// 一度にtimelineやdetectionを実行する行数
const MAX_DETECT_RECORDS: usize = 5000;

fn main() {
    let analysis_start_time: DateTime<Local> = Local::now();
    if !configs::CONFIG.read().unwrap().args.is_present("q") {
        output_logo();
        println!("");
        output_eggs(&format!(
            "{:02}/{:02}",
            &analysis_start_time.month().to_owned(),
            &analysis_start_time.day().to_owned()
        ));
    }
    if configs::CONFIG.read().unwrap().args.args.len() == 0 {
        println!(
            "{}",
            configs::CONFIG.read().unwrap().args.usage().to_string()
        );
        return;
    }
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
    let analysis_end_time: DateTime<Local> = Local::now();
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
        .value_of("min-level")
        .unwrap_or("informational")
        .to_uppercase();
    println!("Analyzing event files: {:?}", evtx_files.len());

    let rule_files = detection::Detection::parse_rule_files(
        level,
        configs::CONFIG.read().unwrap().args.value_of("rules"),
        &filter::exclude_ids(),
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
                AlertMessage::alert(&mut std::io::stderr().lock(), errmsg).ok();
                continue;
            }

            // target_eventids.txtでフィルタする。
            let data = record_result.unwrap().data;
            if _is_target_event_id(&data) == false {
                continue;
            }

            // EvtxRecordInfo構造体に変更
            records_per_detect.push(_create_rec_info(data, &filepath_disp));
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
    detection.add_aggcondition_msg();
    tl.tm_stats_dsp_msg();

    return detection;
}

// target_eventids.txtの設定を元にフィルタする。
fn _is_target_event_id(data: &Value) -> bool {
    let eventid = utils::get_event_value(&utils::get_event_id_key(), data);
    if eventid.is_none() {
        return true;
    }

    return match eventid.unwrap() {
        Value::String(s) => utils::is_target_event_id(s),
        Value::Number(n) => utils::is_target_event_id(&n.to_string()),
        _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
    };
}

// EvtxRecordInfoを作成します。
fn _create_rec_info(mut data: Value, path: &dyn Display) -> EvtxRecordInfo {
    // 高速化のための処理
    // RuleNodeでワイルドカードや正規表現のマッチング処理をする際には、
    // Value(JSON)がstring型以外の場合はstringに変換して比較している。
    // RuleNodeでマッチングする毎にstring変換していると、
    // 1回の処理はそこまででもないが相当回数呼び出されれるとボトルネックになりうる。

    // なので、よく使われるstring型ではない値を事前に変換しておくことで、
    // string変換する回数を減らせる。
    // 本当はやりたくないが...
    match &data["Event"]["System"]["EventID"] {
        Value::Number(n) => data["Event"]["System"]["EventID"] = Value::String(n.to_string()),
        _ => (),
    };
    match &data["Event"]["EventData"]["LogonType"] {
        Value::Number(n) => data["Event"]["EventData"]["LogonType"] = Value::String(n.to_string()),
        _ => (),
    }
    match &data["Event"]["EventData"]["DestinationPort"] {
        Value::Number(n) => {
            data["Event"]["EventData"]["DestinationPort"] = Value::String(n.to_string())
        }
        _ => (),
    }

    // EvtxRecordInfoを作る
    let data_str = data.to_string();
    return EvtxRecordInfo::new(path.to_string(), data, data_str);
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

/// output logo
fn output_logo() {
    let fp = &format!("art/logo.txt");
    let content = fs::read_to_string(fp).unwrap_or(String::default());
    println!("{}", content);
}

/// output easter egg arts
fn output_eggs(exec_datestr: &str) {
    let mut eggs: HashMap<&str, &str> = HashMap::new();
    eggs.insert("01/01", "art/happynewyear.txt");
    eggs.insert("02/22", "art/ninja.txt");
    eggs.insert("08/08", "art/takoyaki.txt");
    eggs.insert("12/25", "art/christmas.txt");

    match eggs.get(exec_datestr) {
        None => {}
        Some(path) => {
            let content = fs::read_to_string(path).unwrap_or(String::default());
            println!("{}", content);
        }
    }
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

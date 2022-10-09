extern crate bytesize;
extern crate downcast_rs;
extern crate serde;
extern crate serde_derive;

use bytesize::ByteSize;
use chrono::{DateTime, Datelike, Local};
use evtx::{EvtxParser, ParserSettings};
use hashbrown::{HashMap, HashSet};
use hayabusa::detections::configs::{
    load_pivot_keywords, TargetEventTime, CONFIG, CURRENT_EXE_PATH, TARGET_EXTENSIONS,
};
use hayabusa::detections::detection::{self, EvtxRecordInfo};
use hayabusa::detections::message::{
    AlertMessage, ERROR_LOG_PATH, ERROR_LOG_STACK, LOGONSUMMARY_FLAG, METRICS_FLAG,
    PIVOT_KEYWORD_LIST_FLAG, QUIET_ERRORS_FLAG,
};
use hayabusa::detections::pivot::PivotKeyword;
use hayabusa::detections::pivot::PIVOT_KEYWORD;
use hayabusa::detections::rule::{get_detection_keys, RuleNode};
use hayabusa::omikuji::Omikuji;
use hayabusa::options::htmlreport::{self, HTML_REPORTER};
use hayabusa::options::profile::PROFILES;
use hayabusa::options::{level_tuning::LevelTuning, update::Update};
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timelines::Timeline};
use hayabusa::{detections::utils::write_color_buffer, filter};
use hhmmss::Hhmmss;
use pbr::ProgressBar;
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::{
    env,
    fs::{self, File},
    path::PathBuf,
    vec,
};
use termcolor::{BufferWriter, Color, ColorChoice};
use tokio::runtime::Runtime;
use tokio::spawn;
use tokio::task::JoinHandle;

#[cfg(target_os = "windows")]
use is_elevated::is_elevated;

// 一度にtimelineやdetectionを実行する行数
const MAX_DETECT_RECORDS: usize = 5000;

fn main() {
    let mut app = App::new();
    app.exec();
    app.rt.shutdown_background();
}

pub struct App {
    rt: Runtime,
    rule_keys: Vec<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> App {
        App {
            rt: utils::create_tokio_runtime(),
            rule_keys: Vec::new(),
        }
    }

    fn exec(&mut self) {
        if *PIVOT_KEYWORD_LIST_FLAG {
            load_pivot_keywords(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "config/pivot_keywords.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
        }
        if PROFILES.is_none() {
            return;
        }
        let analysis_start_time: DateTime<Local> = Local::now();
        if configs::CONFIG.read().unwrap().args.html_report.is_some() {
            let output_data = vec![format!(
                "- Start time: {}",
                analysis_start_time.format("%Y/%m/%d %H:%M")
            )];
            htmlreport::add_md_data(
                "General Overview {#general_overview}".to_string(),
                output_data,
            );
        }

        // Show usage when no arguments.
        if std::env::args().len() == 1 {
            self.output_logo();
            configs::CONFIG.write().unwrap().app.print_help().ok();
            println!();
            return;
        }
        if !configs::CONFIG.read().unwrap().args.quiet {
            self.output_logo();
            println!();
            self.output_eggs(&format!(
                "{:02}/{:02}",
                &analysis_start_time.month().to_owned(),
                &analysis_start_time.day().to_owned()
            ));
        }
        if !self.is_matched_architecture_and_binary() {
            AlertMessage::alert(
                "The hayabusa version you ran does not match your PC architecture.\nPlease use the correct architecture. (Binary ending in -x64.exe for 64-bit and -x86.exe for 32-bit.)",
            )
            .ok();
            println!();
            return;
        }

        if configs::CONFIG.read().unwrap().args.update_rules {
            // エラーが出た場合はインターネット接続がそもそもできないなどの問題点もあるためエラー等の出力は行わない
            let latest_version_data = if let Ok(data) = Update::get_latest_hayabusa_version() {
                data
            } else {
                None
            };
            let now_version = &format!(
                "v{}",
                configs::CONFIG.read().unwrap().app.get_version().unwrap()
            );

            match Update::update_rules(configs::CONFIG.read().unwrap().args.rules.to_str().unwrap())
            {
                Ok(output) => {
                    if output != "You currently have the latest rules." {
                        write_color_buffer(
                            &BufferWriter::stdout(ColorChoice::Always),
                            None,
                            "Rules updated successfully.",
                            true,
                        )
                        .ok();
                    }
                }
                Err(e) => {
                    AlertMessage::alert(&format!("Failed to update rules. {:?}  ", e)).ok();
                }
            }
            println!();
            if latest_version_data.is_some()
                && now_version
                    != &latest_version_data
                        .as_ref()
                        .unwrap_or(now_version)
                        .replace('\"', "")
            {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &format!(
                        "There is a new version of Hayabusa: {}",
                        latest_version_data.unwrap().replace('\"', "")
                    ),
                    true,
                )
                .ok();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    "You can download it at https://github.com/Yamato-Security/hayabusa/releases",
                    true,
                )
                .ok();
            }
            println!();

            return;
        }
        // 実行時のexeファイルのパスをベースに変更する必要があるためデフォルトの値であった場合はそのexeファイルと同一階層を探すようにする
        if !CURRENT_EXE_PATH.join("config").exists() && !Path::new("./config").exists() {
            AlertMessage::alert(
                "Hayabusa could not find the config directory.\nPlease make sure that it is in the same directory as the hayabusa executable."
            )
            .ok();
            return;
        }
        // カレントディレクトリ以外からの実行の際にrules-configオプションの指定がないとエラーが発生することを防ぐための処理
        if configs::CONFIG.read().unwrap().args.config == Path::new("./rules/config") {
            configs::CONFIG.write().unwrap().args.config =
                utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "rules/config", true)
                    .unwrap();
        }

        // カレントディレクトリ以外からの実行の際にrulesオプションの指定がないとエラーが発生することを防ぐための処理
        if configs::CONFIG.read().unwrap().args.rules == Path::new("./rules") {
            configs::CONFIG.write().unwrap().args.rules =
                utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "rules", true).unwrap();
        }
        // rule configのフォルダ、ファイルを確認してエラーがあった場合は終了とする
        if let Err(e) = utils::check_rule_config() {
            AlertMessage::alert(&e).ok();
            return;
        }

        // pivot 機能でファイルを出力する際に同名ファイルが既に存在していた場合はエラー文を出して終了する。
        if let Some(csv_path) = &configs::CONFIG.read().unwrap().args.output {
            let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
            pivot_key_unions.iter().for_each(|(key, _)| {
                let keywords_file_name =
                    csv_path.as_path().display().to_string() + "-" + key + ".txt";
                utils::check_file_expect_not_exist(
                    Path::new(&keywords_file_name),
                    format!(
                        " The file {} already exists. Please specify a different filename.",
                        &keywords_file_name
                    ),
                );
            });
            if utils::check_file_expect_not_exist(
                csv_path,
                format!(
                    " The file {} already exists. Please specify a different filename.",
                    csv_path.as_os_str().to_str().unwrap()
                ),
            ) {
                return;
            }
        }

        let time_filter = TargetEventTime::default();
        if !time_filter.is_parse_success() {
            return;
        }

        if *METRICS_FLAG {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Event ID Metrics",
                true,
            )
            .ok();
            println!();
        }
        if *LOGONSUMMARY_FLAG {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Logon Summary",
                true,
            )
            .ok();
            println!();
        }

        if let Some(html_path) = &configs::CONFIG.read().unwrap().args.html_report {
            // if already exists same html report file. output alert message and exit
            if utils::check_file_expect_not_exist(
                html_path.as_path(),
                format!(
                    " The file {} already exists. Please specify a different filename.",
                    html_path.to_str().unwrap()
                ),
            ) {
                return;
            }
        }

        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &format!(
                "Start time: {}\n",
                analysis_start_time.format("%Y/%m/%d %H:%M")
            ),
            true,
        )
        .ok();
        if configs::CONFIG.read().unwrap().args.live_analysis {
            let live_analysis_list = self.collect_liveanalysis_files();
            if live_analysis_list.is_none() {
                return;
            }
            self.analysis_files(live_analysis_list.unwrap(), &time_filter);
        } else if let Some(filepath) = &configs::CONFIG.read().unwrap().args.filepath {
            if !filepath.exists() {
                AlertMessage::alert(&format!(
                    " The file {} does not exist. Please specify a valid file path.",
                    filepath.as_os_str().to_str().unwrap()
                ))
                .ok();
                return;
            }
            if !TARGET_EXTENSIONS.contains(
                filepath
                    .extension()
                    .unwrap_or_else(|| OsStr::new("."))
                    .to_str()
                    .unwrap(),
            ) || filepath
                .as_path()
                .file_stem()
                .unwrap_or_else(|| OsStr::new("."))
                .to_str()
                .unwrap()
                .trim()
                .starts_with('.')
            {
                AlertMessage::alert(
                    "--filepath only accepts .evtx files. Hidden files are ignored.",
                )
                .ok();
                return;
            }
            self.analysis_files(vec![PathBuf::from(filepath)], &time_filter);
        } else if let Some(directory) = &configs::CONFIG.read().unwrap().args.directory {
            let evtx_files = self.collect_evtxfiles(directory.as_os_str().to_str().unwrap());
            if evtx_files.is_empty() {
                AlertMessage::alert("No .evtx files were found.").ok();
                return;
            }
            self.analysis_files(evtx_files, &time_filter);
        } else if configs::CONFIG.read().unwrap().args.contributors {
            self.print_contributors();
            return;
        } else if configs::CONFIG.read().unwrap().args.level_tuning.is_some() {
            let level_tuning_val = &configs::CONFIG
                .read()
                .unwrap()
                .args
                .level_tuning
                .clone()
                .unwrap();
            let level_tuning_config_path = match level_tuning_val {
                Some(path) => path.to_owned(),
                _ => utils::check_setting_path(
                    &CONFIG.read().unwrap().args.config,
                    "level_tuning.txt",
                    false,
                )
                .unwrap_or_else(|| {
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/level_tuning.txt",
                        true,
                    )
                    .unwrap()
                })
                .display()
                .to_string(),
            };

            if Path::new(&level_tuning_config_path).exists() {
                if let Err(err) = LevelTuning::run(
                    &level_tuning_config_path,
                    configs::CONFIG
                        .read()
                        .unwrap()
                        .args
                        .rules
                        .as_os_str()
                        .to_str()
                        .unwrap(),
                ) {
                    AlertMessage::alert(&err).ok();
                }
            } else {
                AlertMessage::alert(
                    "Need rule_levels.txt file to use --level-tuning option [default: ./rules/config/level_tuning.txt]",
                )
                .ok();
            }
            return;
        } else {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                &configs::CONFIG.read().unwrap().headless_help,
                true,
            )
            .ok();
            return;
        }

        let analysis_end_time: DateTime<Local> = Local::now();
        let analysis_duration = analysis_end_time.signed_duration_since(analysis_start_time);
        let elapsed_output_str = format!("Elapsed Time: {}", &analysis_duration.hhmmssxxx());
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &elapsed_output_str,
            true,
        )
        .ok();
        println!();
        if configs::CONFIG.read().unwrap().args.html_report.is_some() {
            let output_data = vec![format!("- {}", elapsed_output_str)];
            htmlreport::add_md_data(
                "General Overview {#general_overview}".to_string(),
                output_data,
            );
        }
        // Qオプションを付けた場合もしくはパースのエラーがない場合はerrorのstackが0となるのでエラーログファイル自体が生成されない。
        if ERROR_LOG_STACK.lock().unwrap().len() > 0 {
            AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());
        }

        if *PIVOT_KEYWORD_LIST_FLAG {
            let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
            let create_output = |mut output: String, key: &String, pivot_keyword: &PivotKeyword| {
                write!(output, "{}: ", key).ok();

                write!(output, "( ").ok();
                for i in pivot_keyword.fields.iter() {
                    write!(output, "%{}% ", i).ok();
                }
                writeln!(output, "):").ok();

                for i in pivot_keyword.keywords.iter() {
                    writeln!(output, "{}", i).ok();
                }
                writeln!(output).ok();

                output
            };

            //ファイル出力の場合
            if let Some(pivot_file) = &configs::CONFIG.read().unwrap().args.output {
                pivot_key_unions.iter().for_each(|(key, pivot_keyword)| {
                    let mut f = BufWriter::new(
                        fs::File::create(
                            pivot_file.as_path().display().to_string() + "-" + key + ".txt",
                        )
                        .unwrap(),
                    );
                    f.write_all(create_output(String::default(), key, pivot_keyword).as_bytes())
                        .unwrap();
                });
                //output to stdout
                let mut output =
                    "Pivot keyword results saved to the following files:\n".to_string();

                pivot_key_unions.iter().for_each(|(key, _)| {
                    writeln!(
                        output,
                        "{}",
                        &(pivot_file.as_path().display().to_string() + "-" + key + ".txt")
                    )
                    .ok();
                });
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &output,
                    true,
                )
                .ok();
            } else {
                //標準出力の場合
                let output = "The following pivot keywords were found:".to_string();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &output,
                    true,
                )
                .ok();

                pivot_key_unions.iter().for_each(|(key, pivot_keyword)| {
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        None,
                        &create_output(String::default(), key, pivot_keyword),
                        true,
                    )
                    .ok();
                });
            }
        }
        if configs::CONFIG.read().unwrap().args.html_report.is_some() {
            let html_str = HTML_REPORTER.read().unwrap().clone().create_html();
            htmlreport::create_html_file(
                html_str,
                configs::CONFIG
                    .read()
                    .unwrap()
                    .args
                    .html_report
                    .as_ref()
                    .unwrap()
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn collect_liveanalysis_files(&self) -> Option<Vec<PathBuf>> {
        AlertMessage::alert("-l / --liveanalysis needs to be run as Administrator on Windows.")
            .ok();
        println!();
        None
    }

    #[cfg(target_os = "windows")]
    fn collect_liveanalysis_files(&self) -> Option<Vec<PathBuf>> {
        if is_elevated() {
            let log_dir = env::var("windir").expect("windir is not found");
            let evtx_files =
                self.collect_evtxfiles(&[log_dir, "System32\\winevt\\Logs".to_string()].join("/"));
            if evtx_files.is_empty() {
                AlertMessage::alert("No .evtx files were found.").ok();
                return None;
            }
            Some(evtx_files)
        } else {
            AlertMessage::alert("-l / --liveanalysis needs to be run as Administrator on Windows.")
                .ok();
            println!();
            None
        }
    }

    fn collect_evtxfiles(&self, dirpath: &str) -> Vec<PathBuf> {
        let entries = fs::read_dir(dirpath);
        if entries.is_err() {
            let errmsg = format!("{}", entries.unwrap_err());
            if configs::CONFIG.read().unwrap().args.verbose {
                AlertMessage::alert(&errmsg).ok();
            }
            if !*QUIET_ERRORS_FLAG {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {}", errmsg));
            }
            return vec![];
        }

        let mut ret = vec![];
        for e in entries.unwrap() {
            if e.is_err() {
                continue;
            }

            let path = e.unwrap().path();
            if path.is_dir() {
                path.to_str().map(|path_str| {
                    let subdir_ret = self.collect_evtxfiles(path_str);
                    ret.extend(subdir_ret);
                    Option::Some(())
                });
            } else if TARGET_EXTENSIONS.contains(
                path.extension()
                    .unwrap_or_else(|| OsStr::new(""))
                    .to_str()
                    .unwrap(),
            ) && !path
                .file_stem()
                .unwrap_or_else(|| OsStr::new("."))
                .to_str()
                .unwrap()
                .starts_with('.')
            {
                ret.push(path);
            }
        }

        ret
    }

    fn print_contributors(&self) {
        match fs::read_to_string(
            utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "contributors.txt", true)
                .unwrap(),
        ) {
            Ok(contents) => {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &contents,
                    true,
                )
                .ok();
            }
            Err(err) => {
                AlertMessage::alert(&format!("{}", err)).ok();
            }
        }
    }
    fn analysis_files(&mut self, evtx_files: Vec<PathBuf>, time_filter: &TargetEventTime) {
        let level = configs::CONFIG
            .read()
            .unwrap()
            .args
            .min_level
            .to_uppercase();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &format!("Analyzing event files: {:?}", evtx_files.len()),
            true,
        )
        .ok();

        let mut total_file_size = ByteSize::b(0);
        for file_path in &evtx_files {
            let meta = fs::metadata(file_path).ok();
            total_file_size += ByteSize::b(meta.unwrap().len());
        }
        let total_size_output = format!("Total file size: {}", total_file_size.to_string_as(false));
        println!("{}", total_size_output);
        println!();
        if !(configs::CONFIG.read().unwrap().args.metrics
            || configs::CONFIG.read().unwrap().args.logon_summary)
        {
            println!("Loading detections rules. Please wait.");
            println!();
        }

        if configs::CONFIG.read().unwrap().args.html_report.is_some() {
            let output_data = vec![
                format!("- Analyzed event files: {}", evtx_files.len()),
                format!("- {}", total_size_output),
            ];
            htmlreport::add_md_data(
                "General Overview #{general_overview}".to_string(),
                output_data,
            );
        }

        let rule_files = detection::Detection::parse_rule_files(
            level,
            &configs::CONFIG.read().unwrap().args.rules,
            &filter::exclude_ids(),
        );

        if rule_files.is_empty() {
            AlertMessage::alert(
                "No rules were loaded. Please download the latest rules with the --update-rules option.\r\n",
            )
            .ok();
            return;
        }

        let mut pb = ProgressBar::new(evtx_files.len() as u64);
        pb.show_speed = false;
        self.rule_keys = self.get_all_keys(&rule_files);
        let mut detection = detection::Detection::new(rule_files);
        let mut total_records: usize = 0;
        let mut tl = Timeline::new();
        for evtx_file in evtx_files {
            if configs::CONFIG.read().unwrap().args.verbose {
                println!("Checking target evtx FilePath: {:?}", &evtx_file);
            }
            let cnt_tmp: usize;
            (detection, cnt_tmp, tl) =
                self.analysis_file(evtx_file, detection, time_filter, tl.clone());
            total_records += cnt_tmp;
            pb.inc();
        }
        if *METRICS_FLAG {
            tl.tm_stats_dsp_msg();
        }
        if *LOGONSUMMARY_FLAG {
            tl.tm_logon_stats_dsp_msg();
        }
        if configs::CONFIG.read().unwrap().args.output.is_some() {
            println!();
            println!();
            println!("Analysis finished. Please wait while the results are being saved.");
        }
        println!();
        detection.add_aggcondition_msges(&self.rt);
        if !(*METRICS_FLAG || *LOGONSUMMARY_FLAG || *PIVOT_KEYWORD_LIST_FLAG) {
            after_fact(total_records);
        }
    }

    // Windowsイベントログファイルを1ファイル分解析する。
    fn analysis_file(
        &self,
        evtx_filepath: PathBuf,
        mut detection: detection::Detection,
        time_filter: &TargetEventTime,
        mut tl: Timeline,
    ) -> (detection::Detection, usize, Timeline) {
        let path = evtx_filepath.display();
        let parser = self.evtx_to_jsons(evtx_filepath.clone());
        let mut record_cnt = 0;
        if parser.is_none() {
            return (detection, record_cnt, tl);
        }

        let mut parser = parser.unwrap();
        let mut records = parser.records_json_value();

        loop {
            let mut records_per_detect = vec![];
            while records_per_detect.len() < MAX_DETECT_RECORDS {
                // パースに失敗している場合、エラーメッセージを出力
                let next_rec = records.next();
                if next_rec.is_none() {
                    break;
                }
                record_cnt += 1;

                let record_result = next_rec.unwrap();
                if record_result.is_err() {
                    let evtx_filepath = &path;
                    let errmsg = format!(
                        "Failed to parse event file. EventFile:{} Error:{}",
                        evtx_filepath,
                        record_result.unwrap_err()
                    );
                    if configs::CONFIG.read().unwrap().args.verbose {
                        AlertMessage::alert(&errmsg).ok();
                    }
                    if !*QUIET_ERRORS_FLAG {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[ERROR] {}", errmsg));
                    }
                    continue;
                }

                let data = record_result.as_ref().unwrap().data.clone();
                // channelがnullである場合もしくは、target_eventids.txtでイベントIDベースでフィルタする。
                if !self._is_valid_channel(&data) | !self._is_target_event_id(&data)
                    && !configs::CONFIG.read().unwrap().args.deep_scan
                {
                    continue;
                }

                // EventID側の条件との条件の混同を防ぐため時間でのフィルタリングの条件分岐を分離した
                let timestamp = record_result.unwrap().timestamp;
                if !time_filter.is_target(&Some(timestamp)) {
                    continue;
                }

                records_per_detect.push(data);
            }
            if records_per_detect.is_empty() {
                break;
            }

            let records_per_detect = self.rt.block_on(App::create_rec_infos(
                records_per_detect,
                &path,
                self.rule_keys.clone(),
            ));

            // timeline機能の実行
            tl.start(&records_per_detect);

            if !(*METRICS_FLAG || *LOGONSUMMARY_FLAG) {
                // ruleファイルの検知
                detection = detection.start(&self.rt, records_per_detect);
            }
        }

        (detection, record_cnt, tl)
    }

    async fn create_rec_infos(
        records_per_detect: Vec<Value>,
        path: &dyn Display,
        rule_keys: Vec<String>,
    ) -> Vec<EvtxRecordInfo> {
        let path = Arc::new(path.to_string());
        let rule_keys = Arc::new(rule_keys);
        let threads: Vec<JoinHandle<EvtxRecordInfo>> = {
            let this = records_per_detect
                .into_iter()
                .map(|rec| -> JoinHandle<EvtxRecordInfo> {
                    let arc_rule_keys = Arc::clone(&rule_keys);
                    let arc_path = Arc::clone(&path);
                    spawn(async move {
                        utils::create_rec_info(rec, arc_path.to_string(), &arc_rule_keys)
                    })
                });
            FromIterator::from_iter(this)
        };

        let mut ret = vec![];
        for thread in threads.into_iter() {
            ret.push(thread.await.unwrap());
        }

        ret
    }

    fn get_all_keys(&self, rules: &[RuleNode]) -> Vec<String> {
        let mut key_set = HashSet::new();
        for rule in rules {
            let keys = get_detection_keys(rule);
            key_set.extend(keys);
        }

        let ret: Vec<String> = key_set.into_iter().collect();
        ret
    }

    // target_eventids.txtの設定を元にフィルタする。
    fn _is_target_event_id(&self, data: &Value) -> bool {
        let eventid = utils::get_event_value(&utils::get_event_id_key(), data);
        if eventid.is_none() {
            return true;
        }

        match eventid.unwrap() {
            Value::String(s) => utils::is_target_event_id(&s.replace('\"', "")),
            Value::Number(n) => utils::is_target_event_id(&n.to_string().replace('\"', "")),
            _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
        }
    }

    /// レコードのチャンネルの値が正しい(Stringの形でありnullでないもの)ことを判定する関数
    fn _is_valid_channel(&self, data: &Value) -> bool {
        let channel = utils::get_event_value("Event.System.Channel", data);
        if channel.is_none() {
            return false;
        }
        match channel.unwrap() {
            Value::String(s) => s != "null",
            _ => false, // channelの値は文字列を想定しているため、それ以外のデータが来た場合はfalseを返す
        }
    }

    fn evtx_to_jsons(&self, evtx_filepath: PathBuf) -> Option<EvtxParser<File>> {
        match EvtxParser::from_path(evtx_filepath) {
            Ok(evtx_parser) => {
                // parserのデフォルト設定を変更
                let mut parse_config = ParserSettings::default();
                parse_config = parse_config.separate_json_attributes(true); // XMLのattributeをJSONに変換する時のルールを設定
                parse_config = parse_config.num_threads(0); // 設定しないと遅かったので、設定しておく。

                let evtx_parser = evtx_parser.with_configuration(parse_config);
                Option::Some(evtx_parser)
            }
            Err(e) => {
                eprintln!("{}", e);
                Option::None
            }
        }
    }

    fn _output_with_omikuji(&self, omikuji: Omikuji) {
        let fp = &format!("art/omikuji/{}", omikuji);
        let content = fs::read_to_string(fp).unwrap();
        println!("{}", content);
    }

    /// output logo
    fn output_logo(&self) {
        let fp = utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "art/logo.txt", true)
            .unwrap();
        let content = fs::read_to_string(fp).unwrap_or_default();
        let output_color = if configs::CONFIG.read().unwrap().args.no_color {
            None
        } else {
            Some(Color::Green)
        };
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            output_color,
            &content,
            true,
        )
        .ok();
    }

    /// output easter egg arts
    fn output_eggs(&self, exec_datestr: &str) {
        let mut eggs: HashMap<&str, &str> = HashMap::new();
        eggs.insert("01/01", "art/happynewyear.txt");
        eggs.insert("02/22", "art/ninja.txt");
        eggs.insert("08/08", "art/takoyaki.txt");
        eggs.insert("12/25", "art/christmas.txt");

        match eggs.get(exec_datestr) {
            None => {}
            Some(path) => {
                let egg_path =
                    utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), path, true).unwrap();
                let content = fs::read_to_string(egg_path).unwrap_or_default();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &content,
                    true,
                )
                .ok();
            }
        }
    }

    /// check architecture
    fn is_matched_architecture_and_binary(&self) -> bool {
        if cfg!(target_os = "windows") {
            let is_processor_arch_32bit = env::var_os("PROCESSOR_ARCHITECTURE")
                .unwrap_or_default()
                .eq("x86");
            // PROCESSOR_ARCHITEW6432は32bit環境には存在しないため、環境変数存在しなかった場合は32bit環境であると判断する
            let not_wow_flag = env::var_os("PROCESSOR_ARCHITEW6432")
                .unwrap_or_else(|| OsString::from("x86"))
                .eq("x86");
            return (cfg!(target_pointer_width = "64") && !is_processor_arch_32bit)
                || (cfg!(target_pointer_width = "32") && is_processor_arch_32bit && not_wow_flag);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::App;

    #[test]
    fn test_collect_evtxfiles() {
        let app = App::new();
        let files = app.collect_evtxfiles("test_files/evtx");
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

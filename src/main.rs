extern crate bytesize;
extern crate downcast_rs;
extern crate serde;
extern crate serde_derive;

#[cfg(target_os = "windows")]
extern crate static_vcruntime;

use bytesize::ByteSize;
use chrono::{DateTime, Datelike, Local, TimeZone};
use evtx::{EvtxParser, ParserSettings};
use git2::Repository;
use hashbrown::{HashMap, HashSet};
use hayabusa::detections::configs::CURRENT_EXE_PATH;
use hayabusa::detections::configs::{load_pivot_keywords, TargetEventTime, TARGET_EXTENSIONS};
use hayabusa::detections::detection::{self, EvtxRecordInfo};
use hayabusa::detections::pivot::PivotKeyword;
use hayabusa::detections::pivot::PIVOT_KEYWORD;
use hayabusa::detections::print::{
    AlertMessage, ERROR_LOG_PATH, ERROR_LOG_STACK, LOGONSUMMARY_FLAG, PIVOT_KEYWORD_LIST_FLAG,
    QUIET_ERRORS_FLAG, STATISTICS_FLAG,
};
use hayabusa::detections::rule::{get_detection_keys, RuleNode};
use hayabusa::omikuji::Omikuji;
use hayabusa::options::level_tuning::LevelTuning;
use hayabusa::yaml::ParseYaml;
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timelines::Timeline};
use hayabusa::{detections::utils::write_color_buffer, filter};
use hhmmss::Hhmmss;
use pbr::ProgressBar;
use serde_json::Value;
use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::fmt::Write as _;
use std::fs::create_dir;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
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
                CURRENT_EXE_PATH
                    .join("config/pivot_keywords.txt")
                    .to_str()
                    .unwrap(),
            );
        }

        let analysis_start_time: DateTime<Local> = Local::now();
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
            match self.update_rules() {
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
            return;
        }
        // 実行時のexeファイルのパスをベースに変更する必要があるためデフォルトの値であった場合はそのexeファイルと同一階層を探すようにする
        if !CURRENT_EXE_PATH.join("config").exists() {
            AlertMessage::alert(
                "Hayabusa could not find the config directory.\nPlease make sure that it is in the same directory as the hayabusa executable."
            )
            .ok();
            return;
        }
        // ワーキングディレクトリ以外からの実行の際にrules-configオプションの指定がないとエラーが発生することを防ぐための処理
        if configs::CONFIG
            .read()
            .unwrap()
            .args
            .config
            .to_str()
            .unwrap()
            == "./rules/config"
        {
            configs::CONFIG.write().unwrap().args.config = CURRENT_EXE_PATH.join("rules/config");
        }
        // ワーキングディレクトリ以外からの実行の際にrules-configオプションの指定がないとエラーが発生することを防ぐための処理
        if configs::CONFIG.read().unwrap().args.rules.to_str().unwrap() == "./rules" {
            configs::CONFIG.write().unwrap().args.rules = CURRENT_EXE_PATH.join("rules");
        }

        if let Some(csv_path) = &configs::CONFIG.read().unwrap().args.output {
            let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
            pivot_key_unions.iter().for_each(|(key, _)| {
                let keywords_file_name =
                    csv_path.as_path().display().to_string() + "-" + key + ".txt";
                if Path::new(&keywords_file_name).exists() {
                    AlertMessage::alert(&format!(
                        " The file {} already exists. Please specify a different filename.",
                        &keywords_file_name
                    ))
                    .ok();
                }
            });
            if csv_path.exists() {
                AlertMessage::alert(&format!(
                    " The file {} already exists. Please specify a different filename.",
                    csv_path.as_os_str().to_str().unwrap()
                ))
                .ok();
                return;
            }
        }

        let time_filter = TargetEventTime::default();
        if !time_filter.is_parse_success() {
            return;
        }

        if *STATISTICS_FLAG {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Event ID Statistics",
                true,
            )
            .ok();
            println!();
        }
        if *LOGONSUMMARY_FLAG {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Logons Summary",
                true,
            )
            .ok();
            println!();
        }

        if configs::CONFIG.read().unwrap().args.live_analysis {
            let live_analysis_list = self.collect_liveanalysis_files();
            if live_analysis_list.is_none() {
                return;
            }
            self.analysis_files(live_analysis_list.unwrap(), &time_filter);
        } else if let Some(filepath) = &configs::CONFIG.read().unwrap().args.filepath {
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
                _ => CURRENT_EXE_PATH
                    .join("./rules/config/level_tuning.txt")
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
        println!();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &format!("Elapsed Time: {}", &analysis_duration.hhmmssxxx()),
            true,
        )
        .ok();
        println!();

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
        match fs::read_to_string(CURRENT_EXE_PATH.join("contributors.txt")) {
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
        println!("Total file size: {}", total_file_size.to_string_as(false));
        println!();
        println!("Loading detections rules. Please wait.");
        println!();

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
        for evtx_file in evtx_files {
            if configs::CONFIG.read().unwrap().args.verbose {
                println!("Checking target evtx FilePath: {:?}", &evtx_file);
            }
            let cnt_tmp: usize;
            (detection, cnt_tmp) = self.analysis_file(evtx_file, detection, time_filter);
            total_records += cnt_tmp;
            pb.inc();
        }
        if configs::CONFIG.read().unwrap().args.output.is_some() {
            println!();
            println!();
            println!("Analysis finished. Please wait while the results are being saved.");
        }
        println!();
        detection.add_aggcondition_msges(&self.rt);
        if !(*STATISTICS_FLAG || *LOGONSUMMARY_FLAG || *PIVOT_KEYWORD_LIST_FLAG) {
            after_fact(total_records);
        }
    }

    // Windowsイベントログファイルを1ファイル分解析する。
    fn analysis_file(
        &self,
        evtx_filepath: PathBuf,
        mut detection: detection::Detection,
        time_filter: &TargetEventTime,
    ) -> (detection::Detection, usize) {
        let path = evtx_filepath.display();
        let parser = self.evtx_to_jsons(evtx_filepath.clone());
        let mut record_cnt = 0;
        if parser.is_none() {
            return (detection, record_cnt);
        }

        let mut tl = Timeline::new();
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

                // target_eventids.txtでイベントIDベースでフィルタする。
                let data = record_result.as_ref().unwrap().data.clone();
                if !self._is_target_event_id(&data)
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

            record_cnt += records_per_detect.len();

            let records_per_detect = self.rt.block_on(App::create_rec_infos(
                records_per_detect,
                &path,
                self.rule_keys.clone(),
            ));

            // timeline機能の実行
            tl.start(&records_per_detect);

            if !(*STATISTICS_FLAG || *LOGONSUMMARY_FLAG) {
                // ruleファイルの検知
                detection = detection.start(&self.rt, records_per_detect);
            }
        }

        tl.tm_stats_dsp_msg();
        tl.tm_logon_stats_dsp_msg();

        (detection, record_cnt)
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
            Value::String(s) => utils::is_target_event_id(s),
            Value::Number(n) => utils::is_target_event_id(&n.to_string()),
            _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
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
        let fp = CURRENT_EXE_PATH.join("art/logo.txt");
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
                let egg_path = CURRENT_EXE_PATH.join(path);
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

    /// update rules(hayabusa-rules subrepository)
    fn update_rules(&self) -> Result<String, git2::Error> {
        let mut result;
        let mut prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let mut prev_modified_rules: HashSet<String> = HashSet::default();
        let hayabusa_repo = Repository::open(CURRENT_EXE_PATH.as_path());
        let rules_path = CURRENT_EXE_PATH.join("rules");
        let hayabusa_rule_repo = Repository::open(&rules_path);
        if hayabusa_repo.is_err() && hayabusa_rule_repo.is_err() {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Attempting to git clone the hayabusa-rules repository into the rules folder.",
                true,
            )
            .ok();
            // execution git clone of hayabusa-rules repository when failed open hayabusa repository.
            result = self.clone_rules();
        } else if hayabusa_rule_repo.is_ok() {
            // case of exist hayabusa-rules repository
            self._repo_main_reset_hard(hayabusa_rule_repo.as_ref().unwrap())?;
            // case of failed fetching origin/main, git clone is not executed so network error has occurred possibly.
            prev_modified_rules =
                self.get_updated_rules(rules_path.to_str().unwrap(), &prev_modified_time);
            prev_modified_time = fs::metadata(&rules_path).unwrap().modified().unwrap();
            result = self.pull_repository(&hayabusa_rule_repo.unwrap());
        } else {
            // case of no exist hayabusa-rules repository in rules.
            // execute update because submodule information exists if hayabusa repository exists submodule information.

            prev_modified_time = fs::metadata(&rules_path).unwrap().modified().unwrap();
            if !&rules_path.exists() {
                create_dir(&rules_path).ok();
            }
            let hayabusa_repo = hayabusa_repo.unwrap();
            let submodules = hayabusa_repo.submodules()?;
            let mut is_success_submodule_update = true;
            // submodule rules erase path is hard coding to avoid unintentional remove folder.
            fs::remove_dir_all(CURRENT_EXE_PATH.join(".git/.submodule/rules")).ok();
            for mut submodule in submodules {
                submodule.update(true, None)?;
                let submodule_repo = submodule.open()?;
                if let Err(e) = self.pull_repository(&submodule_repo) {
                    AlertMessage::alert(&format!("Failed submodule update. {}", e)).ok();
                    is_success_submodule_update = false;
                }
            }
            if is_success_submodule_update {
                result = Ok("Successed submodule update".to_string());
            } else {
                result = Err(git2::Error::from_str(&String::default()));
            }
        }
        if result.is_ok() {
            let updated_modified_rules =
                self.get_updated_rules(rules_path.to_str().unwrap(), &prev_modified_time);
            result =
                self.print_diff_modified_rule_dates(prev_modified_rules, updated_modified_rules);
        }
        result
    }

    /// hard reset in main branch
    fn _repo_main_reset_hard(&self, input_repo: &Repository) -> Result<(), git2::Error> {
        let branch = input_repo
            .find_branch("main", git2::BranchType::Local)
            .unwrap();
        let local_head = branch.get().target().unwrap();
        let object = input_repo.find_object(local_head, None).unwrap();
        match input_repo.reset(&object, git2::ResetType::Hard, None) {
            Ok(()) => Ok(()),
            _ => Err(git2::Error::from_str("Failed reset main branch in rules")),
        }
    }

    /// Pull(fetch and fast-forward merge) repositoryto input_repo.
    fn pull_repository(&self, input_repo: &Repository) -> Result<String, git2::Error> {
        match input_repo
            .find_remote("origin")?
            .fetch(&["main"], None, None)
            .map_err(|e| {
                AlertMessage::alert(&format!("Failed git fetch to rules folder. {}", e)).ok();
            }) {
            Ok(it) => it,
            Err(_err) => return Err(git2::Error::from_str(&String::default())),
        };
        let fetch_head = input_repo.find_reference("FETCH_HEAD")?;
        let fetch_commit = input_repo.reference_to_annotated_commit(&fetch_head)?;
        let analysis = input_repo.merge_analysis(&[&fetch_commit])?;
        if analysis.0.is_up_to_date() {
            Ok("Already up to date".to_string())
        } else if analysis.0.is_fast_forward() {
            let mut reference = input_repo.find_reference("refs/heads/main")?;
            reference.set_target(fetch_commit.id(), "Fast-Forward")?;
            input_repo.set_head("refs/heads/main")?;
            input_repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
            Ok("Finished fast forward merge.".to_string())
        } else if analysis.0.is_normal() {
            AlertMessage::alert(
            "update-rules option is git Fast-Forward merge only. please check your rules folder."
                ,
            ).ok();
            Err(git2::Error::from_str(&String::default()))
        } else {
            Err(git2::Error::from_str(&String::default()))
        }
    }

    /// git clone でhauyabusa-rules レポジトリをrulesフォルダにgit cloneする関数
    fn clone_rules(&self) -> Result<String, git2::Error> {
        match Repository::clone(
            "https://github.com/Yamato-Security/hayabusa-rules.git",
            CURRENT_EXE_PATH.join("rules"),
        ) {
            Ok(_repo) => {
                println!("Finished cloning the hayabusa-rules repository.");
                Ok("Finished clone".to_string())
            }
            Err(e) => {
                AlertMessage::alert(
                    &format!(
                        "Failed to git clone into the rules folder. Please rename your rules folder name. {}",
                        e
                    ),
                )
                .ok();
                Err(git2::Error::from_str(&String::default()))
            }
        }
    }

    /// Create rules folder files Hashset. Format is "[rule title in yaml]|[filepath]|[filemodified date]|[rule type in yaml]"
    fn get_updated_rules(
        &self,
        rule_folder_path: &str,
        target_date: &SystemTime,
    ) -> HashSet<String> {
        let mut rulefile_loader = ParseYaml::new();
        // level in read_dir is hard code to check all rules.
        rulefile_loader
            .read_dir(
                rule_folder_path,
                "INFORMATIONAL",
                &filter::RuleExclude::default(),
            )
            .ok();

        let hash_set_keys: HashSet<String> = rulefile_loader
            .files
            .into_iter()
            .filter_map(|(filepath, yaml)| {
                let file_modified_date = fs::metadata(&filepath).unwrap().modified().unwrap();

                if file_modified_date.cmp(target_date).is_gt() {
                    let yaml_date = yaml["date"].as_str().unwrap_or("-");
                    return Option::Some(format!(
                        "{}|{}|{}|{}",
                        yaml["title"].as_str().unwrap_or(&String::default()),
                        yaml["modified"].as_str().unwrap_or(yaml_date),
                        &filepath,
                        yaml["ruletype"].as_str().unwrap_or("Other")
                    ));
                }
                Option::None
            })
            .collect();
        hash_set_keys
    }

    /// print updated rule files.
    fn print_diff_modified_rule_dates(
        &self,
        prev_sets: HashSet<String>,
        updated_sets: HashSet<String>,
    ) -> Result<String, git2::Error> {
        let diff = updated_sets.difference(&prev_sets);
        let mut update_count_by_rule_type: HashMap<String, u128> = HashMap::new();
        let mut latest_update_date = Local.timestamp(0, 0);
        for diff_key in diff {
            let tmp: Vec<&str> = diff_key.split('|').collect();
            let file_modified_date = fs::metadata(&tmp[2]).unwrap().modified().unwrap();

            let dt_local: DateTime<Local> = file_modified_date.into();

            if latest_update_date.cmp(&dt_local) == Ordering::Less {
                latest_update_date = dt_local;
            }
            *update_count_by_rule_type
                .entry(tmp[3].to_string())
                .or_insert(0b0) += 1;
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                &format!(
                    "[Updated] {} (Modified: {} | Path: {})",
                    tmp[0], tmp[1], tmp[2]
                ),
                true,
            )
            .ok();
        }
        println!();
        for (key, value) in &update_count_by_rule_type {
            println!("Updated {} rules: {}", key, value);
        }
        if !&update_count_by_rule_type.is_empty() {
            Ok("Rule updated".to_string())
        } else {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "You currently have the latest rules.",
                true,
            )
            .ok();
            Ok("You currently have the latest rules.".to_string())
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
    use std::time::SystemTime;

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

    #[test]
    fn test_get_updated_rules() {
        let app = App::new();

        let prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;

        let prev_modified_rules =
            app.get_updated_rules("test_files/rules/level_yaml", &prev_modified_time);
        assert_eq!(prev_modified_rules.len(), 5);

        let target_time: SystemTime = SystemTime::now();
        let prev_modified_rules2 =
            app.get_updated_rules("test_files/rules/level_yaml", &target_time);
        assert_eq!(prev_modified_rules2.len(), 0);
    }
}

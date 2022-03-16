extern crate downcast_rs;
extern crate serde;
extern crate serde_derive;

#[cfg(target_os = "windows")]
extern crate static_vcruntime;

use chrono::Datelike;
use chrono::{DateTime, Local};
use evtx::{EvtxParser, ParserSettings};
use git2::Repository;
use hashbrown::{HashMap, HashSet};
use hayabusa::detections::detection::{self, EvtxRecordInfo};
use hayabusa::detections::print::{
    AlertMessage, ERROR_LOG_PATH, ERROR_LOG_STACK, QUIET_ERRORS_FLAG, STATISTICS_FLAG,
};
use hayabusa::detections::rule::{get_detection_keys, RuleNode};
use hayabusa::filter;
use hayabusa::omikuji::Omikuji;
use hayabusa::yaml::ParseYaml;
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timelines::Timeline};
use hhmmss::Hhmmss;
use pbr::ProgressBar;
use serde_json::Value;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs::create_dir;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use std::{
    fs::{self, File},
    path::PathBuf,
    vec,
};
use tokio::runtime::Runtime;
use tokio::spawn;
use tokio::task::JoinHandle;

#[cfg(target_os = "windows")]
use {is_elevated::is_elevated, std::env};

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
        let analysis_start_time: DateTime<Local> = Local::now();
        if !configs::CONFIG.read().unwrap().args.is_present("quiet") {
            self.output_logo();
            println!();
            self.output_eggs(&format!(
                "{:02}/{:02}",
                &analysis_start_time.month().to_owned(),
                &analysis_start_time.day().to_owned()
            ));
        }
        if configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("update-rules")
        {
            match self.update_rules() {
                Ok(_ok) => println!("Rules updated successfully."),
                Err(e) => {
                    AlertMessage::alert(
                        &mut BufWriter::new(std::io::stderr().lock()),
                        &format!("Failed to update rules. {:?}  ", e),
                    )
                    .ok();
                }
            }
            return;
        }
        if !Path::new("./config").exists() {
            AlertMessage::alert(
                &mut BufWriter::new(std::io::stderr().lock()),
                &"Hayabusa could not find the config directory.\nPlease run it from the Hayabusa root directory.\nExample: ./hayabusa-1.0.0-windows-x64.exe".to_string()
            )
            .ok();
            return;
        }
        if configs::CONFIG.read().unwrap().args.args.is_empty() {
            println!(
                "{}",
                configs::CONFIG.read().unwrap().args.usage().to_string()
            );
            println!();
            return;
        }
        if let Some(csv_path) = configs::CONFIG.read().unwrap().args.value_of("output") {
            if Path::new(csv_path).exists() {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &format!(
                        " The file {} already exists. Please specify a different filename.",
                        csv_path
                    ),
                )
                .ok();
                return;
            }
        }
        if *STATISTICS_FLAG {
            println!("Generating Event ID Statistics");
            println!();
        }
        if configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("live-analysis")
        {
            let live_analysis_list = self.collect_liveanalysis_files();
            if live_analysis_list.is_none() {
                return;
            }
            self.analysis_files(live_analysis_list.unwrap());
        } else if let Some(filepath) = configs::CONFIG.read().unwrap().args.value_of("filepath") {
            if !filepath.ends_with(".evtx")
                || Path::new(filepath)
                    .file_stem()
                    .unwrap_or_else(|| OsStr::new("."))
                    .to_str()
                    .unwrap()
                    .trim()
                    .starts_with('.')
            {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &"--filepath only accepts .evtx files. Hidden files are ignored.".to_string(),
                )
                .ok();
                return;
            }
            self.analysis_files(vec![PathBuf::from(filepath)]);
        } else if let Some(directory) = configs::CONFIG.read().unwrap().args.value_of("directory") {
            let evtx_files = self.collect_evtxfiles(directory);
            if evtx_files.is_empty() {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &"No .evtx files were found.".to_string(),
                )
                .ok();
                return;
            }
            self.analysis_files(evtx_files);
        } else if configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("contributors")
        {
            self.print_contributors();
            return;
        }
        let analysis_end_time: DateTime<Local> = Local::now();
        let analysis_duration = analysis_end_time.signed_duration_since(analysis_start_time);
        println!();
        println!("Elapsed Time: {}", &analysis_duration.hhmmssxxx());
        println!();

        // Qオプションを付けた場合もしくはパースのエラーがない場合はerrorのstackが9となるのでエラーログファイル自体が生成されない。
        if ERROR_LOG_STACK.lock().unwrap().len() > 0 {
            AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn collect_liveanalysis_files(&self) -> Option<Vec<PathBuf>> {
        AlertMessage::alert(
            &mut BufWriter::new(std::io::stderr().lock()),
            &"-l / --liveanalysis needs to be run as Administrator on Windows.\r\n".to_string(),
        )
        .ok();
        return None;
    }

    #[cfg(target_os = "windows")]
    fn collect_liveanalysis_files(&self) -> Option<Vec<PathBuf>> {
        if is_elevated() {
            let log_dir = env::var("windir").expect("windir is not found");
            let evtx_files =
                self.collect_evtxfiles(&[log_dir, "System32\\winevt\\Logs".to_string()].join("/"));
            if evtx_files.is_empty() {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &"No .evtx files were found.".to_string(),
                )
                .ok();
                return None;
            }
            Some(evtx_files)
        } else {
            AlertMessage::alert(
                &mut BufWriter::new(std::io::stderr().lock()),
                &"-l / --liveanalysis needs to be run as Administrator on Windows.\r\n".to_string(),
            )
            .ok();
            None
        }
    }

    fn collect_evtxfiles(&self, dirpath: &str) -> Vec<PathBuf> {
        let entries = fs::read_dir(dirpath);
        if entries.is_err() {
            let errmsg = format!("{}", entries.unwrap_err());
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::alert(&mut BufWriter::new(std::io::stderr().lock()), &errmsg).ok();
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
            } else {
                let path_str = path.to_str().unwrap_or("");
                if path_str.ends_with(".evtx")
                    && !Path::new(path_str)
                        .file_stem()
                        .unwrap_or_else(|| OsStr::new("."))
                        .to_str()
                        .unwrap()
                        .starts_with('.')
                {
                    ret.push(path);
                }
            }
        }

        ret
    }

    fn print_contributors(&self) {
        match fs::read_to_string("./contributors.txt") {
            Ok(contents) => println!("{}", contents),
            Err(err) => {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &format!("{}", err),
                )
                .ok();
            }
        }
    }

    fn analysis_files(&mut self, evtx_files: Vec<PathBuf>) {
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

        if rule_files.is_empty() {
            AlertMessage::alert(
                &mut BufWriter::new(std::io::stderr().lock()),
                &"No rules were loaded. Please download the latest rules with the --update-rules option.\r\n".to_string(),
            )
            .ok();
            return;
        }

        let mut pb = ProgressBar::new(evtx_files.len() as u64);
        pb.show_speed = false;
        self.rule_keys = self.get_all_keys(&rule_files);
        let mut detection = detection::Detection::new(rule_files);
        for evtx_file in evtx_files {
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                println!("Checking target evtx FilePath: {:?}", &evtx_file);
            }
            detection = self.analysis_file(evtx_file, detection);
            pb.inc();
        }
        detection.add_aggcondition_msges(&self.rt);
        if !*STATISTICS_FLAG {
            after_fact();
        }
    }

    // Windowsイベントログファイルを1ファイル分解析する。
    fn analysis_file(
        &self,
        evtx_filepath: PathBuf,
        mut detection: detection::Detection,
    ) -> detection::Detection {
        let path = evtx_filepath.display();
        let parser = self.evtx_to_jsons(evtx_filepath.clone());
        if parser.is_none() {
            return detection;
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
                    if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                        AlertMessage::alert(&mut BufWriter::new(std::io::stderr().lock()), &errmsg)
                            .ok();
                    }
                    if !*QUIET_ERRORS_FLAG {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[ERROR] {}", errmsg));
                    }
                    continue;
                }

                // target_eventids.txtでフィルタする。
                let data = record_result.unwrap().data;
                if !self._is_target_event_id(&data) {
                    continue;
                }

                // EvtxRecordInfo構造体に変更
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

            if !*STATISTICS_FLAG {
                // ruleファイルの検知
                detection = detection.start(&self.rt, records_per_detect);
            }
        }

        tl.tm_stats_dsp_msg();

        detection
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
        let fp = &"art/logo.txt".to_string();
        let content = fs::read_to_string(fp).unwrap_or_default();
        println!("{}", content);
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
                let content = fs::read_to_string(path).unwrap_or_default();
                println!("{}", content);
            }
        }
    }

    /// update rules(hayabusa-rules subrepository)
    fn update_rules(&self) -> Result<(), git2::Error> {
        let result;
        let mut prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let mut prev_modified_rules: HashSet<String> = HashSet::default();
        let hayabusa_repo = Repository::open(Path::new("."));
        let hayabusa_rule_repo = Repository::open(Path::new("./rules"));
        if hayabusa_repo.is_err() && hayabusa_rule_repo.is_err() {
            println!(
                "Attempting to git clone the hayabusa-rules repository into the rules folder."
            );
            // レポジトリが開けなかった段階でhayabusa rulesのgit cloneを実施する
            result = self.clone_rules();
        } else if hayabusa_rule_repo.is_ok() {
            // rulesのrepositoryが確認できる場合
            // origin/mainのfetchができなくなるケースはネットワークなどのケースが考えられるため、git cloneは実施しない
            prev_modified_rules = self.get_updated_rules("./rules", &prev_modified_time);
            prev_modified_time = fs::metadata("./rules").unwrap().modified().unwrap();
            result = self.pull_repository(hayabusa_rule_repo.unwrap());
        } else {
            // hayabusa-rulesのrepositoryがrulesに存在しない場合
            // hayabusa repositoryがあればsubmodule情報もあると思われるのでupdate
            prev_modified_time = fs::metadata("./rules").unwrap().modified().unwrap();
            let rules_path = Path::new("./rules");
            if !rules_path.exists() {
                create_dir(rules_path).ok();
            }
            let hayabusa_repo = hayabusa_repo.unwrap();
            let submodules = hayabusa_repo.submodules()?;
            let mut is_success_submodule_update = true;
            // submoduleのname参照だと参照先を変えることで意図しないフォルダを削除する可能性があるためハードコーディングする
            fs::remove_dir_all(".git/.submodule/rules").ok();
            for mut submodule in submodules {
                submodule.update(true, None)?;
                let submodule_repo = submodule.open()?;
                match self.pull_repository(submodule_repo) {
                    Ok(it) => it,
                    Err(e) => {
                        AlertMessage::alert(
                            &mut BufWriter::new(std::io::stderr().lock()),
                            &format!("Failed submodule update. {}", e),
                        )
                        .ok();
                        is_success_submodule_update = false;
                    }
                }
            }
            if is_success_submodule_update {
                result = Ok(());
            } else {
                result = Err(git2::Error::from_str(&String::default()));
            }
        }
        if result.is_ok() {
            let updated_modified_rules = self.get_updated_rules("./rules", &prev_modified_time);
            self.print_diff_modified_rule_dates(prev_modified_rules, updated_modified_rules);
        }
        result
    }

    /// Pull(fetch and fast-forward merge) repositoryto input_repo.
    fn pull_repository(&self, input_repo: Repository) -> Result<(), git2::Error> {
        match input_repo
            .find_remote("origin")?
            .fetch(&["main"], None, None)
            .map_err(|e| {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &format!("Failed git fetch to rules folder. {}", e),
                )
                .ok();
            }) {
            Ok(it) => it,
            Err(_err) => return Err(git2::Error::from_str(&String::default())),
        };
        let fetch_head = input_repo.find_reference("FETCH_HEAD")?;
        let fetch_commit = input_repo.reference_to_annotated_commit(&fetch_head)?;
        let analysis = input_repo.merge_analysis(&[&fetch_commit])?;
        if analysis.0.is_up_to_date() {
            Ok(())
        } else if analysis.0.is_fast_forward() {
            let mut reference = input_repo.find_reference("refs/heads/main")?;
            reference.set_target(fetch_commit.id(), "Fast-Forward")?;
            input_repo.set_head("refs/heads/main")?;
            input_repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
            Ok(())
        } else if analysis.0.is_normal() {
            AlertMessage::alert(
            &mut BufWriter::new(std::io::stderr().lock()),
            "update-rules option is git Fast-Forward merge only. please check your rules folder.",
            ).ok();
            Err(git2::Error::from_str(&String::default()))
        } else {
            Err(git2::Error::from_str(&String::default()))
        }
    }

    /// git clone でhauyabusa-rules レポジトリをrulesフォルダにgit cloneする関数
    fn clone_rules(&self) -> Result<(), git2::Error> {
        match Repository::clone(
            "https://github.com/Yamato-Security/hayabusa-rules.git",
            "rules",
        ) {
            Ok(_repo) => {
                println!("Finished cloning the hayabusa-rules repository.");
                Ok(())
            }
            Err(e) => {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
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
                &filter::RuleExclude {
                    no_use_rule: HashSet::new(),
                },
            )
            .ok();

        let hash_set_keys: HashSet<String> = rulefile_loader
            .files
            .into_iter()
            .filter_map(|(filepath, yaml)| {
                let file_modified_date = fs::metadata(&filepath).unwrap().modified().unwrap();
                if file_modified_date.cmp(target_date).is_gt() {
                    return Option::Some(format!(
                        "{}|{}|{:?}|{}",
                        yaml["title"].as_str().unwrap_or(&String::default()),
                        &filepath,
                        file_modified_date,
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
    ) {
        let diff = updated_sets.difference(&prev_sets);
        let mut update_count_by_rule_type: HashMap<String, u128> = HashMap::new();
        for diff_key in diff {
            let mut tmp = diff_key.split('|');
            *update_count_by_rule_type
                .entry(tmp.nth(4).unwrap().to_string())
                .or_insert(0b1) += 1;
            println!(
                "[Update Files] {} (Modified date: {} | FilePath: {})",
                tmp.nth(1).unwrap(),
                tmp.nth(2).unwrap(),
                tmp.nth(3).unwrap()
            );
        }
        println!();
        for (key, value) in update_count_by_rule_type {
            println!("Updated {} rules count: {}", key, value);
        }
        println!(
            "Current latest rule: {:?}",
            fs::metadata("./rules").unwrap().modified().unwrap()
        );
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

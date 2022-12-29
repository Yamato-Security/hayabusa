extern crate bytesize;
extern crate downcast_rs;
extern crate serde;
extern crate serde_derive;

use bytesize::ByteSize;
use chrono::{DateTime, Datelike, Local};
use clap::Command;
use evtx::{EvtxParser, ParserSettings};
use hashbrown::{HashMap, HashSet};
use hayabusa::debug::checkpoint_process_timer::CHECKPOINT;
use hayabusa::detections::configs::{
    load_pivot_keywords, Action, ConfigReader, EventInfoConfig, EventKeyAliasConfig, StoredStatic,
    TargetEventIds, TargetEventTime, CURRENT_EXE_PATH, STORED_EKEY_ALIAS, STORED_STATIC,
};
use hayabusa::detections::detection::{self, EvtxRecordInfo};
use hayabusa::detections::message::{AlertMessage, ERROR_LOG_STACK};
use hayabusa::detections::pivot::PivotKeyword;
use hayabusa::detections::pivot::PIVOT_KEYWORD;
use hayabusa::detections::rule::{get_detection_keys, RuleNode};
use hayabusa::detections::utils::{check_setting_path, output_and_data_stack_for_html};
use hayabusa::options;
use hayabusa::options::htmlreport::{self, HTML_REPORTER};
use hayabusa::options::profile::set_default_profile;
use hayabusa::options::{level_tuning::LevelTuning, update::Update};
use hayabusa::{afterfact::after_fact, detections::utils};
use hayabusa::{detections::configs, timeline::timelines::Timeline};
use hayabusa::{detections::utils::write_color_buffer, filter};
use hhmmss::Hhmmss;
use libmimalloc_sys::mi_stats_print_out;
use mimalloc::MiMalloc;
use nested::Nested;
use pbr::ProgressBar;
use serde_json::Value;
use std::borrow::Borrow;
use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::ptr::null_mut;
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

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// 一度にtimelineやdetectionを実行する行数
const MAX_DETECT_RECORDS: usize = 5000;

fn main() {
    let mut config_reader = ConfigReader::new();
    // コマンドのパース情報を作成してstatic変数に格納する
    let mut stored_static = StoredStatic::create_static_data(config_reader.config);
    config_reader.config = None;
    let mut app = App::new(stored_static.thread_number);
    app.exec(&mut config_reader.app, &mut stored_static);
    app.rt.shutdown_background();
}

pub struct App {
    rt: Runtime,
    rule_keys: Nested<String>,
}

impl App {
    pub fn new(thread_number: Option<usize>) -> App {
        App {
            rt: utils::create_tokio_runtime(thread_number),
            rule_keys: Nested::<String>::new(),
        }
    }

    fn exec(&mut self, app: &mut Command, stored_static: &mut StoredStatic) {
        if stored_static.profiles.is_none() {
            return;
        }

        let analysis_start_time: DateTime<Local> = Local::now();
        if stored_static.html_report_flag {
            let mut output_data = Nested::<String>::new();
            output_data.extend(vec![format!(
                "- Start time: {}",
                analysis_start_time.format("%Y/%m/%d %H:%M")
            )]);
            htmlreport::add_md_data("General Overview {#general_overview}", output_data);
        }

        // 引数がなかった時にhelpを出力するためのサブコマンド出力。引数がなくても動作するサブコマンドはhelpを出力しない
        let subcommand_name = Action::get_action_name(stored_static.config.action.as_ref());
        if stored_static.config.action.is_some()
            && !self.check_is_valid_args_num(stored_static.config.action.as_ref())
        {
            if !stored_static.config.quiet {
                self.output_logo(stored_static);
                println!();
            }
            app.find_subcommand(subcommand_name)
                .unwrap()
                .clone()
                .print_help()
                .ok();
            println!();
            return;
        }

        // Show usage when no arguments.
        if stored_static.config.action.is_none() {
            if !stored_static.config.quiet {
                self.output_logo(stored_static);
                println!();
            }
            app.print_help().ok();
            println!();
            return;
        }
        if !stored_static.config.quiet {
            self.output_logo(stored_static);
            println!();
            self.output_eggs(&format!(
                "{:02}/{:02}",
                &analysis_start_time.month(),
                &analysis_start_time.day()
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

        // 実行時のexeファイルのパスをベースに変更する必要があるためデフォルトの値であった場合はそのexeファイルと同一階層を探すようにする
        if !CURRENT_EXE_PATH.join("config").exists() && !Path::new("./config").exists() {
            AlertMessage::alert(
                "Hayabusa could not find the config directory.\nPlease make sure that it is in the same directory as the hayabusa executable."
            )
            .ok();
            return;
        }
        // カレントディレクトリ以外からの実行の際にrules-configオプションの指定がないとエラーが発生することを防ぐための処理
        if stored_static.config_path == Path::new("./rules/config") {
            stored_static.config_path =
                utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "rules/config", true)
                    .unwrap();
        }

        let time_filter = TargetEventTime::new(stored_static);
        if !time_filter.is_parse_success() {
            return;
        }

        if stored_static.metrics_flag {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Event ID Metrics",
                true,
            )
            .ok();
            println!();
        }
        if stored_static.logon_summary_flag {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Generating Logon Summary",
                true,
            )
            .ok();
            println!();
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
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .set_checkpoint(analysis_start_time);
        let target_extensions = if stored_static.output_option.is_some() {
            configs::get_target_extensions(
                stored_static
                    .output_option
                    .as_ref()
                    .unwrap()
                    .input_args
                    .evtx_file_ext
                    .as_ref(),
            )
        } else {
            HashSet::default()
        };

        match &stored_static.config.action.as_ref().unwrap() {
            Action::CsvTimeline(_) | Action::JsonTimeline(_) => {
                // カレントディレクトリ以外からの実行の際にrulesオプションの指定がないとエラーが発生することを防ぐための処理
                if stored_static.output_option.as_ref().unwrap().rules == Path::new("./rules") {
                    stored_static.output_option.as_mut().unwrap().rules =
                        utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "rules", true)
                            .unwrap();
                }
                // rule configのフォルダ、ファイルを確認してエラーがあった場合は終了とする
                if let Err(e) = utils::check_rule_config(&stored_static.config_path) {
                    AlertMessage::alert(&e).ok();
                    return;
                }

                if stored_static.profiles.is_none() {
                    return;
                }
                if let Some(html_path) = &stored_static.output_option.as_ref().unwrap().html_report
                {
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
                if let Some(path) = &stored_static.output_option.as_ref().unwrap().output {
                    if utils::check_file_expect_not_exist(
                        path.as_path(),
                        format!(
                            " The file {} already exists. Please specify a different filename.",
                            path.as_os_str().to_str().unwrap()
                        ),
                    ) {
                        return;
                    }
                }
                self.analysis_start(&target_extensions, &time_filter, stored_static);

                if let Some(path) = &stored_static.output_option.as_ref().unwrap().output {
                    if let Ok(metadata) = fs::metadata(path) {
                        let output_saved_str = format!(
                            "Saved file: {} ({})",
                            path.display(),
                            ByteSize::b(metadata.len()).to_string_as(false)
                        );
                        output_and_data_stack_for_html(
                            &output_saved_str,
                            "General Overview {#general_overview}",
                            stored_static.html_report_flag,
                        );
                    }
                }
                if stored_static.html_report_flag {
                    let html_str = HTML_REPORTER.read().unwrap().to_owned().create_html();
                    htmlreport::create_html_file(
                        html_str,
                        stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .html_report
                            .as_ref()
                            .unwrap()
                            .to_str()
                            .unwrap_or(""),
                    )
                }
            }
            Action::ListContributors => {
                self.print_contributors();
                return;
            }
            Action::LogonSummary(_) | Action::Metrics(_) => {
                self.analysis_start(&target_extensions, &time_filter, stored_static);
                if let Some(path) = &stored_static.output_option.as_ref().unwrap().output {
                    if let Ok(metadata) = fs::metadata(path) {
                        let output_saved_str = format!(
                            "Saved file: {} ({})",
                            path.display(),
                            ByteSize::b(metadata.len()).to_string_as(false)
                        );
                        output_and_data_stack_for_html(
                            &output_saved_str,
                            "General Overview {#general_overview}",
                            stored_static.html_report_flag,
                        );
                    }
                }
            }
            Action::PivotKeywordsList(_) => {
                // pivot 機能でファイルを出力する際に同名ファイルが既に存在していた場合はエラー文を出して終了する。
                if let Some(csv_path) = &stored_static.output_option.as_ref().unwrap().output {
                    let mut error_flag = false;
                    let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
                    pivot_key_unions.iter().for_each(|(key, _)| {
                        let keywords_file_name =
                            csv_path.as_path().display().to_string() + "-" + key + ".txt";
                        if utils::check_file_expect_not_exist(
                            Path::new(&keywords_file_name),
                            format!(
                                " The file {} already exists. Please specify a different filename.",
                                &keywords_file_name
                            ),
                        ) {
                            error_flag = true
                        };
                    });
                    if error_flag {
                        return;
                    }
                }
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

                self.analysis_start(&target_extensions, &time_filter, stored_static);

                // pivotのファイルの作成。pivot.rsに投げたい
                let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
                let create_output =
                    |mut output: String, key: &String, pivot_keyword: &PivotKeyword| {
                        write!(output, "{}: ( ", key).ok();
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
                if let Some(pivot_file) = &stored_static.output_option.as_ref().unwrap().output {
                    pivot_key_unions.iter().for_each(|(key, pivot_keyword)| {
                        let mut f = BufWriter::new(
                            fs::File::create(
                                pivot_file.as_path().display().to_string() + "-" + key + ".txt",
                            )
                            .unwrap(),
                        );
                        f.write_all(
                            create_output(String::default(), key, pivot_keyword).as_bytes(),
                        )
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
                    let output = "The following pivot keywords were found:";
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        None,
                        output,
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
            Action::UpdateRules(_) => {
                let update_target = match &stored_static.config.action.as_ref().unwrap() {
                    Action::UpdateRules(option) => Some(option.rules.to_owned()),
                    _ => None,
                };
                // エラーが出た場合はインターネット接続がそもそもできないなどの問題点もあるためエラー等の出力は行わない
                let latest_version_data = if let Ok(data) = Update::get_latest_hayabusa_version() {
                    data
                } else {
                    None
                };
                let now_version = &format!("v{}", env!("CARGO_PKG_VERSION"));

                match Update::update_rules(update_target.unwrap().to_str().unwrap(), stored_static)
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
                        if e.message().is_empty() {
                            AlertMessage::alert("Failed to update rules.").ok();
                        } else {
                            AlertMessage::alert(&format!("Failed to update rules. {:?}  ", e)).ok();
                        }
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
                    println!();
                }

                return;
            }
            Action::LevelTuning(option) => {
                let level_tuning_config_path = if option.level_tuning.to_str().unwrap()
                    != "./rules/config/level_tuning.txt"
                {
                    utils::check_setting_path(
                        option
                            .level_tuning
                            .parent()
                            .unwrap_or_else(|| Path::new("")),
                        option
                            .level_tuning
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap_or_default(),
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
                    .to_string()
                } else {
                    utils::check_setting_path(&stored_static.config_path, "level_tuning.txt", false)
                        .unwrap_or_else(|| {
                            utils::check_setting_path(
                                &CURRENT_EXE_PATH.to_path_buf(),
                                "rules/config/level_tuning.txt",
                                true,
                            )
                            .unwrap()
                        })
                        .display()
                        .to_string()
                };

                let rules_path = if stored_static.output_option.as_ref().is_some() {
                    stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .rules
                        .as_os_str()
                        .to_str()
                        .unwrap()
                } else {
                    "./rules"
                };

                if Path::new(&level_tuning_config_path).exists() {
                    if let Err(err) =
                        LevelTuning::run(&level_tuning_config_path, rules_path, stored_static)
                    {
                        AlertMessage::alert(&err).ok();
                    }
                } else {
                    AlertMessage::alert(
                        "Need rule_levels.txt file to use --level-tuning option [default: ./rules/config/level_tuning.txt]",
                    )
                    .ok();
                }
                return;
            }
            Action::SetDefaultProfile(_) => {
                if let Err(e) = set_default_profile(
                    check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "config/default_profile.yaml",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                    check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "config/profiles.yaml",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                    stored_static,
                ) {
                    AlertMessage::alert(&e).ok();
                } else {
                    println!("Successfully updated the default profile.");
                }
                return;
            }
            Action::ListProfiles => {
                let profile_list =
                    options::profile::get_profile_list("config/profiles.yaml", stored_static);
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    "List of available profiles:",
                    true,
                )
                .ok();
                for profile in profile_list.iter() {
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        Some(Color::Green),
                        &format!("- {:<25}", &format!("{}:", profile[0])),
                        false,
                    )
                    .ok();
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        None,
                        &profile[1],
                        true,
                    )
                    .ok();
                }
                println!();
                return;
            }
        }

        // 処理時間の出力
        let analysis_end_time: DateTime<Local> = Local::now();
        let analysis_duration = analysis_end_time.signed_duration_since(analysis_start_time);
        let elapsed_output_str = format!("Elapsed time: {}", &analysis_duration.hhmmssxxx());
        output_and_data_stack_for_html(
            &elapsed_output_str,
            "General Overview {#general_overview}",
            stored_static.html_report_flag,
        );

        // Qオプションを付けた場合もしくはパースのエラーがない場合はerrorのstackが0となるのでエラーログファイル自体が生成されない。
        if ERROR_LOG_STACK.lock().unwrap().len() > 0 {
            AlertMessage::create_error_log(stored_static.quiet_errors_flag);
        }

        // Debugフラグをつけていた時にはメモリ利用情報などの統計情報を画面に出力する
        if stored_static.config.debug {
            CHECKPOINT.lock().as_ref().unwrap().output_stocked_result();
            println!();
            println!("Memory usage stats:");
            unsafe {
                mi_stats_print_out(None, null_mut());
            }
        }
        println!();
    }

    fn analysis_start(
        &mut self,
        target_extensions: &HashSet<String>,
        time_filter: &TargetEventTime,
        stored_static: &StoredStatic,
    ) {
        if stored_static.output_option.is_none() {
        } else if stored_static
            .output_option
            .as_ref()
            .unwrap()
            .input_args
            .live_analysis
        {
            let live_analysis_list =
                self.collect_liveanalysis_files(target_extensions, stored_static);
            if live_analysis_list.is_none() {
                return;
            }
            self.analysis_files(
                live_analysis_list.unwrap(),
                time_filter,
                &stored_static.event_timeline_config,
                &stored_static.target_eventids,
                stored_static,
            );
        } else if let Some(directory) = &stored_static
            .output_option
            .as_ref()
            .unwrap()
            .input_args
            .directory
        {
            let evtx_files = Self::collect_evtxfiles(
                directory.as_os_str().to_str().unwrap(),
                target_extensions,
                stored_static,
            );
            if evtx_files.is_empty() {
                AlertMessage::alert("No .evtx files were found.").ok();
                return;
            }
            self.analysis_files(
                evtx_files,
                time_filter,
                &stored_static.event_timeline_config,
                &stored_static.target_eventids,
                stored_static,
            );
        } else {
            // directory, live_analysis以外はfilepathの指定の場合
            if let Some(filepath) = &stored_static
                .output_option
                .as_ref()
                .unwrap()
                .input_args
                .filepath
            {
                let mut replaced_filepath = filepath.display().to_string();
                if replaced_filepath.starts_with('"') {
                    replaced_filepath.remove(0);
                }
                if replaced_filepath.ends_with('"') {
                    replaced_filepath.remove(replaced_filepath.len() - 1);
                }
                let check_path = Path::new(&replaced_filepath);
                if !check_path.exists() {
                    AlertMessage::alert(&format!(
                        " The file {} does not exist. Please specify a valid file path.",
                        filepath.as_os_str().to_str().unwrap()
                    ))
                    .ok();
                    return;
                }
                if !target_extensions.contains(
                    check_path
                        .extension()
                        .unwrap_or_else(|| OsStr::new("."))
                        .to_str()
                        .unwrap(),
                ) || check_path
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
                self.analysis_files(
                    vec![check_path.to_path_buf()],
                    time_filter,
                    &stored_static.event_timeline_config,
                    &stored_static.target_eventids,
                    stored_static,
                );
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn collect_liveanalysis_files(
        &self,
        _target_extensions: &HashSet<String>,
        _stored_static: &StoredStatic,
    ) -> Option<Vec<PathBuf>> {
        AlertMessage::alert("-l / --liveanalysis needs to be run as Administrator on Windows.")
            .ok();
        println!();
        None
    }

    #[cfg(target_os = "windows")]
    fn collect_liveanalysis_files(
        &self,
        target_extensions: &HashSet<String>,
        stored_static: &StoredStatic,
    ) -> Option<Vec<PathBuf>> {
        if is_elevated() {
            let log_dir = env::var("windir").expect("windir is not found");
            let evtx_files = Self::collect_evtxfiles(
                &[log_dir, "System32\\winevt\\Logs".to_string()].join("/"),
                target_extensions,
                stored_static,
            );
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

    fn collect_evtxfiles(
        dir_path: &str,
        target_extensions: &HashSet<String>,
        stored_static: &StoredStatic,
    ) -> Vec<PathBuf> {
        let mut dirpath = dir_path.to_string();
        if dirpath.starts_with('"') {
            dirpath.remove(0);
        }
        if dirpath.ends_with('"') {
            dirpath.remove(dirpath.len() - 1);
        }
        let entries = fs::read_dir(dirpath);
        if entries.is_err() {
            let errmsg = format!("{}", entries.unwrap_err());
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
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
                    let subdir_ret =
                        Self::collect_evtxfiles(path_str, target_extensions, stored_static);
                    ret.extend(subdir_ret);
                    Option::Some(())
                });
            } else if target_extensions.contains(
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

    fn analysis_files(
        &mut self,
        evtx_files: Vec<PathBuf>,
        time_filter: &TargetEventTime,
        event_timeline_config: &EventInfoConfig,
        target_event_ids: &TargetEventIds,
        stored_static: &StoredStatic,
    ) {
        let level = stored_static
            .output_option
            .as_ref()
            .unwrap()
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
        if !(stored_static.metrics_flag || stored_static.logon_summary_flag) {
            println!("Loading detections rules. Please wait.");
            println!();
        }

        if stored_static.html_report_flag {
            let mut output_data = Nested::<String>::new();
            output_data.extend(vec![
                format!("- Analyzed event files: {}", evtx_files.len()),
                format!("- {}", total_size_output),
            ]);
            htmlreport::add_md_data("General Overview #{general_overview}", output_data);
        }

        let rule_files = detection::Detection::parse_rule_files(
            level.as_str(),
            &stored_static.output_option.as_ref().unwrap().rules,
            &filter::exclude_ids(stored_static),
            stored_static,
        );
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .rap_check_point("Rule Parse Processing Time");

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

        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        for evtx_file in evtx_files {
            if stored_static.verbose_flag {
                println!("Checking target evtx FilePath: {:?}", &evtx_file);
            }
            let cnt_tmp: usize;
            (detection, cnt_tmp, tl) = self.analysis_file(
                evtx_file,
                detection,
                time_filter,
                tl.to_owned(),
                target_event_ids,
                stored_static,
            );
            total_records += cnt_tmp;
            pb.inc();
        }
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .rap_check_point("Analysis Processing Time");
        if stored_static.metrics_flag {
            tl.tm_stats_dsp_msg(event_timeline_config, stored_static);
        }
        if stored_static.logon_summary_flag {
            tl.tm_logon_stats_dsp_msg(stored_static);
        }
        if stored_static
            .output_option
            .as_ref()
            .unwrap()
            .output
            .is_some()
        {
            println!();
            println!();
            println!("Analysis finished. Please wait while the results are being saved.");
        }
        println!();
        detection.add_aggcondition_msges(&self.rt, stored_static);
        if !(stored_static.metrics_flag
            || stored_static.logon_summary_flag
            || stored_static.pivot_keyword_list_flag)
        {
            after_fact(
                total_records,
                stored_static.output_option.as_ref().unwrap(),
                stored_static.config.no_color,
                stored_static,
            );
        }
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .rap_check_point("Output Processing Time");
    }

    // Windowsイベントログファイルを1ファイル分解析する。
    fn analysis_file(
        &self,
        evtx_filepath: PathBuf,
        mut detection: detection::Detection,
        time_filter: &TargetEventTime,
        mut tl: Timeline,
        target_event_ids: &TargetEventIds,
        stored_static: &StoredStatic,
    ) -> (detection::Detection, usize, Timeline) {
        let path = evtx_filepath.display();
        let parser = self.evtx_to_jsons(&evtx_filepath);
        let mut record_cnt = 0;
        if parser.is_none() {
            return (detection, record_cnt, tl);
        }

        let mut parser = parser.unwrap();
        let mut records = parser.records_json_value();

        let verbose_flag = stored_static.verbose_flag;
        let quiet_errors_flag = stored_static.quiet_errors_flag;
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
                    if verbose_flag {
                        AlertMessage::alert(&errmsg).ok();
                    }
                    if !quiet_errors_flag {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[ERROR] {}", errmsg));
                    }
                    continue;
                }

                let data = record_result.as_ref().unwrap().data.borrow();
                // channelがnullである場合とEventID Filter optionが指定されていない場合は、target_eventids.txtでイベントIDベースでフィルタする。
                if !self._is_valid_channel(data, &stored_static.eventkey_alias)
                    || (stored_static.output_option.as_ref().unwrap().eid_filter
                        && !self._is_target_event_id(
                            data,
                            target_event_ids,
                            &stored_static.eventkey_alias,
                        ))
                {
                    continue;
                }

                // EventID側の条件との条件の混同を防ぐため時間でのフィルタリングの条件分岐を分離した
                let timestamp = record_result.as_ref().unwrap().timestamp;
                if !time_filter.is_target(&Some(timestamp)) {
                    continue;
                }

                records_per_detect.push(data.to_owned());
            }
            if records_per_detect.is_empty() {
                break;
            }

            let records_per_detect = self.rt.block_on(App::create_rec_infos(
                records_per_detect,
                &path,
                self.rule_keys.to_owned(),
            ));

            // timeline機能の実行
            tl.start(
                &records_per_detect,
                stored_static.metrics_flag,
                stored_static.logon_summary_flag,
                &stored_static.eventkey_alias,
            );

            if !(stored_static.metrics_flag || stored_static.logon_summary_flag) {
                // ruleファイルの検知
                detection = detection.start(&self.rt, records_per_detect);
            }
        }

        (detection, record_cnt, tl)
    }

    async fn create_rec_infos(
        records_per_detect: Vec<Value>,
        path: &dyn Display,
        rule_keys: Nested<String>,
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

    fn get_all_keys(&self, rules: &[RuleNode]) -> Nested<String> {
        let mut key_set = HashSet::new();
        for rule in rules {
            let keys = get_detection_keys(rule);
            key_set.extend(keys.iter().map(|x| x.to_string()));
        }

        key_set.into_iter().collect::<Nested<String>>()
    }

    /// target_eventids.txtの設定を元にフィルタする。 trueであれば検知確認対象のEventIDであることを意味する。
    fn _is_target_event_id(
        &self,
        data: &Value,
        target_event_ids: &TargetEventIds,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> bool {
        let eventid = utils::get_event_value(&utils::get_event_id_key(), data, eventkey_alias);
        if eventid.is_none() {
            return true;
        }

        match eventid.unwrap() {
            Value::String(s) => target_event_ids.is_target(&s.replace('\"', "")),
            Value::Number(n) => target_event_ids.is_target(&n.to_string().replace('\"', "")),
            _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
        }
    }

    /// レコードのチャンネルの値が正しい(Stringの形でありnullでないもの)ことを判定する関数
    fn _is_valid_channel(&self, data: &Value, eventkey_alias: &EventKeyAliasConfig) -> bool {
        let channel = utils::get_event_value("Event.System.Channel", data, eventkey_alias);
        if channel.is_none() {
            return false;
        }
        match channel.unwrap() {
            Value::String(s) => s != "null",
            _ => false, // channelの値は文字列を想定しているため、それ以外のデータが来た場合はfalseを返す
        }
    }

    fn evtx_to_jsons(&self, evtx_filepath: &PathBuf) -> Option<EvtxParser<File>> {
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

    /// output logo
    fn output_logo(&self, stored_static: &StoredStatic) {
        let fp = utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "art/logo.txt", true)
            .unwrap();
        let content = fs::read_to_string(fp).unwrap_or_default();
        let output_color = if stored_static.config.no_color {
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
        let mut eggs: HashMap<&str, (&str, Color)> = HashMap::new();
        eggs.insert("01/01", ("art/happynewyear.txt", Color::Rgb(255, 0, 0))); // Red
        eggs.insert("02/22", ("art/ninja.txt", Color::Rgb(0, 171, 240))); // Cerulean
        eggs.insert("08/08", ("art/takoyaki.txt", Color::Rgb(181, 101, 29))); // Light Brown
        eggs.insert("12/24", ("art/christmas.txt", Color::Rgb(70, 192, 22))); // Green
        eggs.insert("12/25", ("art/christmas.txt", Color::Rgb(70, 192, 22))); // Green

        match eggs.get(exec_datestr) {
            None => {}
            Some((path, color)) => {
                let egg_path =
                    utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), path, true).unwrap();
                let content = fs::read_to_string(egg_path).unwrap_or_default();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    Some(color.to_owned()),
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

    fn check_is_valid_args_num(&self, action: Option<&Action>) -> bool {
        match action.as_ref().unwrap() {
            Action::CsvTimeline(_)
            | Action::JsonTimeline(_)
            | Action::LogonSummary(_)
            | Action::Metrics(_)
            | Action::PivotKeywordsList(_)
            | Action::SetDefaultProfile(_) => {
                if std::env::args().len() == 2 {
                    return false;
                }
                true
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::App;
    use hashbrown::HashSet;
    use hayabusa::detections::configs::{Action, Config, ConfigReader, StoredStatic, UpdateOption};

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
            })),
            no_color: false,
            quiet: false,
            debug: false,
        }))
    }

    #[test]
    fn test_collect_evtxfiles() {
        let files = App::collect_evtxfiles(
            "test_files/evtx",
            &HashSet::from(["evtx".to_string()]),
            &create_dummy_stored_static(),
        );
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
    fn test_exec_none_storedstatic() {
        let mut app = App::new(None);
        let mut config_reader = ConfigReader::new();
        let mut stored_static = StoredStatic::create_static_data(config_reader.config);
        config_reader.config = None;
        stored_static.profiles = None;
        app.exec(&mut config_reader.app, &mut stored_static);
    }
}

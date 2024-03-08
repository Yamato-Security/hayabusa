extern crate bytesize;
extern crate downcast_rs;
extern crate maxminddb;
extern crate serde;
extern crate serde_derive;

use bytesize::ByteSize;
use chrono::{DateTime, Datelike, Local, NaiveDateTime, Utc};
use clap::Command;
use compact_str::CompactString;
use console::{style, Style};
use dialoguer::Confirm;
use dialoguer::{theme::ColorfulTheme, Select};
use evtx::{EvtxParser, ParserSettings, RecordAllocation};
use hashbrown::{HashMap, HashSet};
use hayabusa::afterfact::{self, AfterfactInfo, AfterfactWriter};
use hayabusa::debug::checkpoint_process_timer::CHECKPOINT;
use hayabusa::detections::configs::{
    load_pivot_keywords, Action, ConfigReader, EventKeyAliasConfig, StoredStatic, TargetEventTime,
    TargetIds, CURRENT_EXE_PATH, STORED_EKEY_ALIAS, STORED_STATIC,
};
use hayabusa::detections::detection::{self, EvtxRecordInfo};
use hayabusa::detections::message::{AlertMessage, DetectInfo, ERROR_LOG_STACK};
use hayabusa::detections::rule::{get_detection_keys, RuleNode};
use hayabusa::detections::utils;
use hayabusa::detections::utils::{
    check_setting_path, get_writable_color, output_and_data_stack_for_html, output_profile_name,
};
use hayabusa::options::htmlreport::{self, HTML_REPORTER};
use hayabusa::options::pivot::create_output;
use hayabusa::options::pivot::PIVOT_KEYWORD;
use hayabusa::options::profile::set_default_profile;
use hayabusa::options::{level_tuning::LevelTuning, update::Update};
use hayabusa::timeline::computer_metrics::countup_event_by_computer;
use hayabusa::{detections::configs, timeline::timelines::Timeline};
use hayabusa::{detections::utils::write_color_buffer, filter};
use hayabusa::{options, yaml};
use indicatif::ProgressBar;
use indicatif::{ProgressDrawTarget, ProgressStyle};
use itertools::Itertools;
use libmimalloc_sys::mi_stats_print_out;
use mimalloc::MiMalloc;
use nested::Nested;
use serde_json::{Map, Value};
use std::borrow::BorrowMut;
use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Duration;
use std::u128;
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

// 一度に読み込んで、スキャンするレコード数
// The number of records to load and scan at a time. 1000 gave the fastest results and lowest memory usage in test benchmarks.
const MAX_DETECT_RECORDS: usize = 1000;

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
            output_data.extend(vec![
                format!("- Command line: {}", std::env::args().join(" ")),
                format!(
                    "- Start time: {}",
                    analysis_start_time.format("%Y/%m/%d %H:%M")
                ),
            ]);
            htmlreport::add_md_data("General Overview {#general_overview}", output_data);
        }

        // 引数がなかった時にhelpを出力するためのサブコマンド出力。引数がなくても動作するサブコマンドはhelpを出力しない
        let subcommand_name = Action::get_action_name(stored_static.config.action.as_ref());
        if stored_static.config.action.is_some()
            && !self.check_is_valid_args_num(stored_static.config.action.as_ref())
        {
            if !stored_static.common_options.quiet {
                self.output_logo(stored_static);
                write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", true).ok();
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
            if !stored_static.common_options.quiet {
                self.output_logo(stored_static);
                write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", true).ok();
            }
            app.print_help().ok();
            println!();
            return;
        }
        if !stored_static.common_options.quiet {
            self.output_logo(stored_static);
            write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", true).ok();
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
        if stored_static.search_flag {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Searching...",
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
                    .detect_common_options
                    .evtx_file_ext
                    .as_ref(),
                stored_static.json_input_flag,
            )
        } else {
            HashSet::default()
        };

        let output_saved_file =
            |output_path: &Option<PathBuf>, message: &str, html_report_flag: &bool| {
                if let Some(path) = output_path {
                    if let Ok(metadata) = fs::metadata(path) {
                        let output_saved_str = format!(
                            "{message}: {} ({})",
                            path.display(),
                            ByteSize::b(metadata.len()).to_string_as(false)
                        );
                        output_and_data_stack_for_html(
                            &output_saved_str,
                            "General Overview {#general_overview}",
                            html_report_flag,
                        );
                    }
                }
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
                    if !(stored_static.output_option.as_ref().unwrap().clobber)
                        && utils::check_file_expect_not_exist(
                            html_path.as_path(),
                            format!(
                                " The file {} already exists. Please specify a different filename or add the -C, --clobber option to overwrite.\n",
                                html_path.to_str().unwrap()
                            ),
                        )
                    {
                        return;
                    }
                }
                if let Some(path) = &stored_static.output_path {
                    if !(stored_static.output_option.as_ref().unwrap().clobber)
                        && utils::check_file_expect_not_exist(
                            path.as_path(),
                            format!(
                                " The file {} already exists. Please specify a different filename or add the -C, --clobber option to overwrite.\n",
                                path.as_os_str().to_str().unwrap()
                            ),
                        )
                    {
                        return;
                    }
                }
                self.analysis_start(&target_extensions, &time_filter, stored_static);

                output_profile_name(&stored_static.output_option, false);
                output_saved_file(
                    &stored_static.output_path,
                    "Saved file",
                    &stored_static.html_report_flag,
                );
                println!();
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
            Action::ListContributors(_) => {
                self.print_contributors();
                return;
            }
            Action::LogonSummary(_) => {
                let mut target_output_path = Nested::<String>::new();
                if let Some(path) = &stored_static.output_path {
                    for suffix in &["-successful.csv", "-failed.csv"] {
                        let output_file = format!("{}{suffix}", path.to_str().unwrap());
                        if !(stored_static.output_option.as_ref().unwrap().clobber)
                            && utils::check_file_expect_not_exist(
                                Path::new(output_file.as_str()),
                                format!(
                                " The files with a base name of {} already exist. Please specify a different base filename or add the -C, --clobber option to overwrite.\n",
                                path.as_os_str().to_str().unwrap()
                            ),
                            )
                        {
                            return;
                        }
                        target_output_path.push(output_file);
                    }
                }
                self.analysis_start(&target_extensions, &time_filter, stored_static);
                for target_path in target_output_path.iter() {
                    let mut msg = "";
                    if target_path.ends_with("-successful.csv") {
                        msg = "Successful logon results"
                    }
                    if target_path.ends_with("-failed.csv") {
                        msg = "Failed logon results"
                    }
                    output_saved_file(
                        &Some(Path::new(target_path).to_path_buf()),
                        msg,
                        &stored_static.html_report_flag,
                    );
                }
                println!();
            }
            Action::EidMetrics(_) | Action::Search(_) => {
                if let Some(path) = &stored_static.output_path {
                    if !(stored_static.output_option.as_ref().unwrap().clobber)
                        && utils::check_file_expect_not_exist(
                            path.as_path(),
                            format!(
                                " The file {} already exists. Please specify a different filename or add the -C, --clobber option to overwrite.\n",
                                path.as_os_str().to_str().unwrap()
                            ),
                        )
                    {
                        return;
                    }
                }
                self.analysis_start(&target_extensions, &time_filter, stored_static);
                output_saved_file(
                    &stored_static.output_path,
                    "Saved results",
                    &stored_static.html_report_flag,
                );
                println!();
            }
            Action::ComputerMetrics(_) => {
                if let Some(path) = &stored_static.output_path {
                    if !(stored_static.output_option.as_ref().unwrap().clobber)
                        && utils::check_file_expect_not_exist(
                            path.as_path(),
                            format!(
                                " The file {} already exists. Please specify a different filename or add the -C, --clobber option to overwrite.\n",
                                path.as_os_str().to_str().unwrap()
                            ),
                        )
                    {
                        return;
                    }
                }
                self.analysis_start(&target_extensions, &time_filter, stored_static);
                output_saved_file(
                    &stored_static.output_path,
                    "Saved results",
                    &stored_static.html_report_flag,
                );
                println!();
            }
            Action::PivotKeywordsList(_) => {
                load_pivot_keywords(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/pivot_keywords.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                );

                // pivot 機能でファイルを出力する際に同名ファイルが既に存在していた場合はエラー文を出して終了する。
                let mut error_flag = false;
                if let Some(csv_path) = &stored_static.output_path {
                    let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
                    pivot_key_unions.iter().for_each(|(key, _)| {
                        let keywords_file_name =
                            csv_path.as_path().display().to_string() + "-" + key + ".txt";
                        if !(stored_static.output_option.as_ref().unwrap().clobber) && utils::check_file_expect_not_exist(
                            Path::new(&keywords_file_name),
                            format!(
                                " The file {} already exists. Please specify a different filename or add the -C, --clobber option to overwrite.",
                                &keywords_file_name
                            ),
                        ) {
                            error_flag = true
                        };
                    });
                }
                if error_flag {
                    println!();
                    return;
                }

                self.analysis_start(&target_extensions, &time_filter, stored_static);

                let pivot_key_unions = PIVOT_KEYWORD.read().unwrap();
                if let Some(pivot_file) = &stored_static.output_path {
                    //ファイル出力の場合
                    pivot_key_unions.iter().for_each(|(key, pivot_keyword)| {
                        let mut f = BufWriter::new(
                            fs::File::create(
                                pivot_file.as_path().display().to_string() + "-" + key + ".txt",
                            )
                            .unwrap(),
                        );
                        f.write_all(
                            create_output(
                                String::default(),
                                key,
                                pivot_keyword,
                                "file",
                                stored_static,
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    });
                    let mut output =
                        "Pivot keyword results were saved to the following files:\n".to_string();

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
                    let output = "\nThe following pivot keywords were found:\n";
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        None,
                        output,
                        true,
                    )
                    .ok();

                    pivot_key_unions.iter().for_each(|(key, pivot_keyword)| {
                        create_output(
                            String::default(),
                            key,
                            pivot_keyword,
                            "standard",
                            stored_static,
                        );

                        if pivot_keyword.keywords.is_empty() {
                            write_color_buffer(
                                &BufferWriter::stdout(ColorChoice::Always),
                                get_writable_color(
                                    Some(Color::Red),
                                    stored_static.common_options.no_color,
                                ),
                                "No keywords found\n",
                                true,
                            )
                            .ok();
                        }
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
                stored_static.include_status.insert("*".into());
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
                            AlertMessage::alert(&format!("Failed to update rules. {e:?}  ")).ok();
                        }
                    }
                }
                println!();
                let split_now_version = &now_version
                    .replace("-dev", "")
                    .split('.')
                    .filter_map(|x| x.parse().ok())
                    .collect::<Vec<i8>>();
                let split_latest_version = &latest_version_data
                    .as_ref()
                    .unwrap_or(now_version)
                    .replace('"', "")
                    .split('.')
                    .filter_map(|x| x.parse().ok())
                    .collect::<Vec<i8>>();
                if split_latest_version > split_now_version {
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
            Action::ListProfiles(_) => {
                let profile_list = options::profile::get_profile_list("config/profiles.yaml");
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
        let elapsed_output_str = format!(
            "Elapsed time: {}",
            CHECKPOINT
                .lock()
                .as_mut()
                .unwrap()
                .calculate_all_stocked_results()
        );
        output_and_data_stack_for_html(
            &elapsed_output_str,
            "General Overview {#general_overview}",
            &stored_static.html_report_flag,
        );
        match stored_static.config.action {
            Some(Action::CsvTimeline(_)) | Some(Action::JsonTimeline(_)) => {
                println!();
                println!("Please report any issues with Hayabusa rules to: https://github.com/Yamato-Security/hayabusa-rules/issues");
                println!("Please report any false positives with Sigma rules to: https://github.com/SigmaHQ/sigma/issues");
                println!("Please submit new Sigma rules with pull requests to: https://github.com/SigmaHQ/sigma/pulls");
            }
            _ => {}
        }

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
        stored_static: &mut StoredStatic,
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
                stored_static.borrow_mut(),
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
            self.analysis_files(evtx_files, time_filter, stored_static.borrow_mut());
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
                    stored_static.borrow_mut(),
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
        AlertMessage::alert("-l, --live-analysis needs to be run as Administrator on Windows.")
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
            AlertMessage::alert("-l, --live-analysis needs to be run as Administrator on Windows.")
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
            let mut errmsg = format!("{}", entries.unwrap_err());
            if errmsg.ends_with("123)") {
                errmsg = format!("{errmsg}. You may not be able to load evtx files when there are spaces in the directory path. Please enclose the path with double quotes and remove any trailing slash at the end of the path.");
            }
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
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
                AlertMessage::alert(&format!("{err}")).ok();
            }
        }
    }

    fn analysis_files(
        &mut self,
        evtx_files: Vec<PathBuf>,
        time_filter: &TargetEventTime,
        stored_static: &mut StoredStatic,
    ) {
        let event_timeline_config = &stored_static.event_timeline_config;
        let target_event_ids = &stored_static.target_eventids;
        let target_level = stored_static
            .output_option
            .as_ref()
            .unwrap()
            .exact_level
            .as_ref()
            .unwrap_or(&String::default())
            .to_uppercase();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &format!("Total event log files: {:?}", evtx_files.len()),
            true,
        )
        .ok();
        let mut total_file_size = ByteSize::b(0);
        for file_path in &evtx_files {
            let file_size = match fs::metadata(file_path) {
                Ok(res) => res.len(),
                Err(err) => {
                    if stored_static.verbose_flag {
                        AlertMessage::warn(&err.to_string()).ok();
                    }
                    if !stored_static.quiet_errors_flag {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {err}"));
                    }
                    0
                }
            };
            total_file_size += ByteSize::b(file_size);
        }
        let total_size_output = format!("Total file size: {}", total_file_size.to_string_as(false));
        println!("{total_size_output}");
        let mut status_append_output = None;
        if !(stored_static.metrics_flag
            || stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.computer_metrics_flag
            || stored_static.output_option.as_ref().unwrap().no_wizard)
        {
            CHECKPOINT
                .lock()
                .as_mut()
                .unwrap()
                .rap_checkpoint("Rule Parse Processing Time");
            let mut rule_counter_wizard_map = HashMap::new();
            yaml::count_rules(
                &stored_static.output_option.as_ref().unwrap().rules,
                &filter::exclude_ids(stored_static),
                stored_static,
                &mut rule_counter_wizard_map,
            );
            let level_map: HashMap<&str, u128> = HashMap::from([
                ("INFORMATIONAL", 1),
                ("LOW", 2),
                ("MEDIUM", 3),
                ("HIGH", 4),
                ("CRITICAL", 5),
            ]);
            println!();
            println!("Scan wizard:");
            println!();
            let calcurate_wizard_rule_count = |exclude_noisytarget_flag: bool,
                                               exclude_noisy_status: Vec<&str>,
                                               min_level: &str,
                                               target_status: Vec<&str>,
                                               target_tags: Vec<&str>|
             -> HashMap<CompactString, i128> {
                let mut ret = HashMap::new();
                if exclude_noisytarget_flag {
                    for s in exclude_noisy_status {
                        let mut ret_cnt = 0;
                        if let Some(target_status_count) = rule_counter_wizard_map.get(s) {
                            target_status_count.iter().for_each(|(rule_level, value)| {
                                let doc_level_num = level_map
                                    .get(rule_level.to_uppercase().as_str())
                                    .unwrap_or(&1);
                                let args_level_num = level_map
                                    .get(min_level.to_uppercase().as_str())
                                    .unwrap_or(&1);
                                if doc_level_num >= args_level_num {
                                    ret_cnt += value.iter().map(|(_, cnt)| cnt).sum::<i128>()
                                }
                            });
                        }
                        if ret_cnt > 0 {
                            ret.insert(CompactString::from(s), ret_cnt);
                        }
                    }
                } else {
                    let all_status_flag = target_status.contains(&"*");
                    for s in rule_counter_wizard_map.keys() {
                        // 指定されたstatusに合致しないものは集計をスキップする
                        if (exclude_noisy_status.contains(&s.as_str())
                            || !target_status.contains(&s.as_str()))
                            && !all_status_flag
                        {
                            continue;
                        }
                        let mut ret_cnt = 0;
                        if let Some(target_status_count) = rule_counter_wizard_map.get(s) {
                            target_status_count.iter().for_each(|(rule_level, value)| {
                                let doc_level_num = level_map
                                    .get(rule_level.to_uppercase().as_str())
                                    .unwrap_or(&1);
                                let args_level_num = level_map
                                    .get(min_level.to_uppercase().as_str())
                                    .unwrap_or(&1);
                                if doc_level_num >= args_level_num {
                                    if !target_tags.is_empty() {
                                        for (tag, cnt) in value.iter() {
                                            if target_tags.contains(&tag.as_str()) {
                                                let matched_tag_cnt = ret.entry(tag.clone());
                                                *matched_tag_cnt.or_insert(0) += cnt;
                                            }
                                        }
                                    } else {
                                        ret_cnt += value.iter().map(|(_, cnt)| cnt).sum::<i128>()
                                    }
                                }
                            });
                            if ret_cnt > 0 {
                                ret.insert(s.clone(), ret_cnt);
                            }
                        }
                    }
                }
                ret
            };
            let selections_status = &[
                ("1. Core ( status: test, stable | level: high, critical )", (vec!["test", "stable"], "high")),
                ("2. Core+ ( status: test, stable | level: medium, high, critical )", (vec!["test", "stable"], "medium")),
                ("3. Core++ ( status: experimental, test, stable | level: medium, high, critical )", (vec!["experimental", "test", "stable"], "medium")),
                ("4. All alert rules ( status: * | level: low+ )", (vec!["*"], "low")),
                ("5. All event and alert rules ( status: * | level: informational+ )", (vec!["*"], "informational")),
            ];

            let sections_rule_cnt = selections_status
                .iter()
                .map(|(_, (status, min_level))| {
                    calcurate_wizard_rule_count(
                        false,
                        ["excluded", "deprecated", "unsupported", "noisy"].to_vec(),
                        min_level,
                        status.to_vec(),
                        [].to_vec(),
                    )
                })
                .collect_vec();
            let selection_status_items = &[
                format!("1. Core ({} rules) ( status: test, stable | level: high, critical )", sections_rule_cnt[0].iter().map(|(_, cnt)| cnt).sum::<i128>() - sections_rule_cnt[0].get("excluded").unwrap_or(&0)),
                format!("2. Core+ ({} rules) ( status: test, stable | level: medium, high, critical )", sections_rule_cnt[1].iter().map(|(_, cnt)| cnt).sum::<i128>() - sections_rule_cnt[1].get("excluded").unwrap_or(&0)),
                format!("3. Core++ ({} rules) ( status: experimental, test, stable | level: medium, high, critical )", sections_rule_cnt[2].iter().map(|(_, cnt)| cnt).sum::<i128>() - sections_rule_cnt[2].get("excluded").unwrap_or(&0)),
                format!("4. All alert rules ({} rules) ( status: * | level: low+ )", sections_rule_cnt[3].iter().map(|(_, cnt)| cnt).sum::<i128>() - sections_rule_cnt[3].get("excluded").unwrap_or(&0)),
                format!("5. All event and alert rules ({} rules) ( status: * | level: informational+ )", sections_rule_cnt[4].iter().map(|(_, cnt)| cnt).sum::<i128>() - sections_rule_cnt[4].get("excluded").unwrap_or(&0))
            ];

            let color_theme = if stored_static.common_options.no_color {
                ColorfulTheme {
                    defaults_style: Style::new().for_stderr(),
                    prompt_style: Style::new().for_stderr().bold(),
                    prompt_prefix: style("?".to_string()).for_stderr(),
                    prompt_suffix: style("›".to_string()).for_stderr(),
                    success_prefix: style("✔".to_string()).for_stderr(),
                    success_suffix: style("·".to_string()).for_stderr(),
                    error_prefix: style("✘".to_string()).for_stderr(),
                    error_style: Style::new().for_stderr(),
                    hint_style: Style::new().for_stderr(),
                    values_style: Style::new().for_stderr(),
                    active_item_style: Style::new().for_stderr(),
                    inactive_item_style: Style::new().for_stderr(),
                    active_item_prefix: style("❯".to_string()).for_stderr(),
                    inactive_item_prefix: style(" ".to_string()).for_stderr(),
                    checked_item_prefix: style("✔".to_string()).for_stderr(),
                    unchecked_item_prefix: style("⬚".to_string()).for_stderr(),
                    picked_item_prefix: style("❯".to_string()).for_stderr(),
                    unpicked_item_prefix: style(" ".to_string()).for_stderr(),
                }
            } else {
                ColorfulTheme::default()
            };
            let selected_index = Select::with_theme(&color_theme)
                .with_prompt("Which set of detection rules would you like to load?")
                .default(0)
                .items(selection_status_items.as_slice())
                .interact()
                .unwrap();
            status_append_output = Some(format!(
                "- selected detection rule sets: {}",
                selections_status[selected_index].0
            ));
            stored_static.output_option.as_mut().unwrap().min_level =
                selections_status[selected_index].1 .1.into();

            let exclude_noisy_cnt = calcurate_wizard_rule_count(
                true,
                ["excluded", "noisy", "deprecated", "unsupported"].to_vec(),
                selections_status[selected_index].1 .1,
                [].to_vec(),
                [].to_vec(),
            );

            stored_static.include_status.extend(
                selections_status[selected_index]
                    .1
                     .0
                    .iter()
                    .map(|x| x.to_owned().into()),
            );

            let mut output_option = stored_static.output_option.clone().unwrap();
            let exclude_tags = output_option.exclude_tag.get_or_insert_with(Vec::new);
            let tags_cnt = calcurate_wizard_rule_count(
                false,
                [].to_vec(),
                selections_status[selected_index].1 .1,
                selections_status[selected_index].1 .0.clone(),
                [
                    "detection.emerging_threats",
                    "detection.threat_hunting",
                    "sysmon",
                ]
                .to_vec(),
            );
            // If anything other than "4. All alert rules" or "5. All event and alert rules" was selected, ask questions about tags.
            if selected_index < 3 {
                if let Some(et_cnt) = tags_cnt.get("detection.emerging_threats") {
                    let prompt_fmt = format!("Include Emerging Threats rules? ({} rules)", et_cnt);
                    let et_rules_load_flag = Confirm::with_theme(&color_theme)
                        .with_prompt(prompt_fmt)
                        .default(true)
                        .show_default(true)
                        .interact()
                        .unwrap();
                    // If no is selected, then add "--exclude-tags detection.emerging_threats"
                    if !et_rules_load_flag {
                        exclude_tags.push("detection.emerging_threats".into());
                    }
                }
                if let Some(th_cnt) = tags_cnt.get("detection.threat_hunting") {
                    let prompt_fmt = format!("Include Threat Hunting rules? ({} rules)", th_cnt);
                    let th_rules_load_flag = Confirm::with_theme(&color_theme)
                        .with_prompt(prompt_fmt)
                        .default(false)
                        .show_default(true)
                        .interact()
                        .unwrap();
                    // If no is selected, then add "--exclude-tags detection.threat_hunting"
                    if !th_rules_load_flag {
                        exclude_tags.push("detection.threat_hunting".into());
                    }
                }
            } else {
                // If "4. All alert rules" or "5. All event and alert rules" was selected, ask questions about deprecated and unsupported rules.
                if let Some(dep_cnt) = exclude_noisy_cnt.get("deprecated") {
                    // deprecated rules load prompt
                    let prompt_fmt = format!("Include deprecated rules? ({} rules)", dep_cnt);
                    let dep_rules_load_flag = Confirm::with_theme(&color_theme)
                        .with_prompt(prompt_fmt)
                        .default(false)
                        .show_default(true)
                        .interact()
                        .unwrap();
                    if dep_rules_load_flag {
                        stored_static
                            .output_option
                            .as_mut()
                            .unwrap()
                            .enable_deprecated_rules = true;
                    }
                }
                if let Some(unsup_cnt) = exclude_noisy_cnt.get("unsupported") {
                    // unsupported rules load prompt
                    let prompt_fmt = format!("Include unsupported rules? ({} rules)", unsup_cnt);
                    let unsupported_rules_load_flag = Confirm::with_theme(&color_theme)
                        .with_prompt(prompt_fmt)
                        .default(false)
                        .show_default(true)
                        .interact()
                        .unwrap();
                    if unsupported_rules_load_flag {
                        stored_static
                            .output_option
                            .as_mut()
                            .unwrap()
                            .enable_unsupported_rules = true;
                    }
                }
            }

            CHECKPOINT
                .lock()
                .as_mut()
                .unwrap()
                .set_checkpoint(Local::now());

            if let Some(noisy_cnt) = exclude_noisy_cnt.get("noisy") {
                // noisy rules load prompt
                let prompt_fmt = format!("Include noisy rules? ({} rules)", noisy_cnt);
                let noisy_rules_load_flag = Confirm::with_theme(&color_theme)
                    .with_prompt(prompt_fmt)
                    .default(false)
                    .show_default(true)
                    .interact()
                    .unwrap();
                if noisy_rules_load_flag {
                    stored_static
                        .output_option
                        .as_mut()
                        .unwrap()
                        .enable_noisy_rules = true;
                }
            }

            if let Some(sysmon_cnt) = tags_cnt.get("sysmon") {
                let prompt_fmt = format!("Include sysmon rules? ({} rules)", sysmon_cnt);
                let sysmon_rules_load_flag = Confirm::with_theme(&color_theme)
                    .with_prompt(prompt_fmt)
                    .default(true)
                    .show_default(true)
                    .interact()
                    .unwrap();

                // If no is selected, then add "--exclude-tags sysmon"
                if !sysmon_rules_load_flag {
                    exclude_tags.push("sysmon".into());
                }
            }

            if !exclude_tags.is_empty() {
                stored_static.output_option.as_mut().unwrap().exclude_tag =
                    Some(exclude_tags.to_owned());
            }
        } else if stored_static.include_status.is_empty() {
            stored_static.include_status.insert("*".into());
        }

        if stored_static.html_report_flag {
            let mut output_data = Nested::<String>::new();
            let mut html_report_data = Nested::<String>::from_iter(vec![
                format!("- Analyzed event files: {}", evtx_files.len()),
                format!("- {total_size_output}"),
            ]);
            if let Some(status_report) = status_append_output {
                html_report_data.push(format!("- Selected deteciton rule set: {status_report}"));
            }
            let exclude_tags_data = stored_static
                .output_option
                .as_ref()
                .unwrap()
                .exclude_tag
                .clone()
                .unwrap_or_default()
                .join(" / ");
            if !exclude_tags_data.is_empty() {
                html_report_data.push(format!("- Excluded tags: {}", exclude_tags_data));
            }
            output_data.extend(html_report_data.iter());
            htmlreport::add_md_data("General Overview #{general_overview}", output_data);
        }

        let level = stored_static
            .output_option
            .as_ref()
            .unwrap()
            .min_level
            .to_uppercase();

        println!();
        if !(stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.metrics_flag
            || stored_static.computer_metrics_flag)
        {
            println!("Loading detection rules. Please wait.");
        } else if stored_static.logon_summary_flag {
            println!("Currently scanning for the logon summary. Please wait.");
        } else if stored_static.search_flag {
            println!("Currently searching. Please wait.");
        } else if stored_static.metrics_flag {
            println!("Currently scanning for event ID metrics. Please wait.");
        } else if stored_static.computer_metrics_flag {
            println!("Currently scanning for computer metrics. Please wait.");
        }
        println!();

        let mut rule_files = vec![];
        if !(stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.metrics_flag
            || stored_static.computer_metrics_flag)
        {
            rule_files = detection::Detection::parse_rule_files(
                &level,
                &target_level,
                &stored_static.output_option.as_ref().unwrap().rules,
                &filter::exclude_ids(stored_static),
                stored_static,
            );
            CHECKPOINT
                .lock()
                .as_mut()
                .unwrap()
                .rap_checkpoint("Rule Parse Processing Time");
            CHECKPOINT
                .lock()
                .as_mut()
                .unwrap()
                .set_checkpoint(Local::now());
            let unused_rules_option = stored_static.logon_summary_flag
                || stored_static.search_flag
                || stored_static.computer_metrics_flag
                || stored_static.metrics_flag;
            if !unused_rules_option && rule_files.is_empty() {
                AlertMessage::alert(
                        "No rules were loaded. Please download the latest rules with the update-rules command.\r\n",
                    )
                    .ok();
                return;
            }
        }

        let template = if stored_static.common_options.no_color {
            "[{elapsed_precise}] {human_pos} / {human_len} {spinner} [{bar:40}] {percent}%\r\n\r\n{msg}"
        } else {
            "[{elapsed_precise}] {human_pos} / {human_len} {spinner:.green} [{bar:40.green}] {percent}%\r\n\r\n{msg}"
        };
        let progress_style = ProgressStyle::with_template(template)
            .unwrap()
            .progress_chars("=> ");
        let pb = ProgressBar::with_draw_target(
            Some(evtx_files.len() as u64),
            ProgressDrawTarget::stdout_with_hz(10),
        )
        .with_tab_width(55);
        pb.set_style(progress_style);
        // I tried progress bar with low memory option(output log on detection) but it seemts that progress bar didn't go well with low memory option.
        // I disabled progress bar if low memory option is specified.
        let is_show_progress = !stored_static.is_low_memory || stored_static.output_path.is_some();
        if is_show_progress {
            pb.enable_steady_tick(Duration::from_millis(300));
        }
        self.rule_keys = self.get_all_keys(&rule_files);
        let mut detection = detection::Detection::new(rule_files);
        let mut tl = Timeline::new();

        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut afterfact_info = AfterfactInfo::default();
        let mut all_detect_infos = vec![];
        let mut afterfact_writer = afterfact::init_writer(stored_static);
        for evtx_file in evtx_files {
            if is_show_progress {
                let pb_msg = format!(
                    "{:?}",
                    &evtx_file.to_str().unwrap_or_default().replace('\\', "/")
                );
                pb.set_message(pb_msg);
            }

            let (detection_tmp, cnt_tmp, tl_tmp, recover_cnt_tmp, mut detect_infos) =
                if evtx_file.extension().unwrap() == "json" {
                    self.analysis_json_file(
                        (evtx_file, time_filter, target_event_ids, stored_static),
                        detection,
                        tl.to_owned(),
                        &mut afterfact_writer,
                        &mut afterfact_info,
                    )
                } else {
                    self.analysis_file(
                        (evtx_file, time_filter, target_event_ids, stored_static),
                        detection,
                        tl.to_owned(),
                        &mut afterfact_writer,
                        &mut afterfact_info,
                    )
                };
            detection = detection_tmp;
            tl = tl_tmp;
            afterfact_info.record_cnt += cnt_tmp as u128;
            afterfact_info.recover_record_cnt += recover_cnt_tmp as u128;
            all_detect_infos.append(&mut detect_infos);
            if is_show_progress {
                pb.inc(1);
            }
        }
        pb.finish_with_message(
            "Scanning finished. Please wait while the results are being saved.\r\n",
        );
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .rap_checkpoint("Analysis Processing Time");
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .set_checkpoint(Local::now());

        if stored_static.metrics_flag {
            tl.tm_stats_dsp_msg(event_timeline_config, stored_static);
        } else if stored_static.logon_summary_flag {
            tl.tm_logon_stats_dsp_msg(stored_static);
        } else if stored_static.search_flag {
            tl.search_dsp_msg(event_timeline_config, stored_static);
        } else if stored_static.computer_metrics_flag {
            tl.computer_metrics_dsp_msg(stored_static)
        }
        if !(stored_static.metrics_flag
            || stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.pivot_keyword_list_flag
            || stored_static.computer_metrics_flag)
        {
            println!();
            let mut log_records = detection.add_aggcondition_msges(&self.rt, stored_static);
            if stored_static.is_low_memory {
                let empty_ids = HashSet::new();
                afterfact::emit_csv(
                    &log_records,
                    &empty_ids,
                    stored_static,
                    &mut afterfact_writer,
                    &mut afterfact_info,
                );
            } else {
                all_detect_infos.append(&mut log_records);
            }
            afterfact_info.tl_starttime = tl.stats.start_time;
            afterfact_info.tl_endtime = tl.stats.end_time;

            // output afterfact
            if stored_static.is_low_memory {
                afterfact::output_additional_afterfact(
                    stored_static,
                    &mut afterfact_writer,
                    &afterfact_info,
                );
            } else {
                afterfact::output_afterfact(
                    &mut all_detect_infos,
                    &mut afterfact_writer,
                    stored_static,
                    &mut afterfact_info,
                );
            }
        }
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .rap_checkpoint("Output Processing Time");
        CHECKPOINT
            .lock()
            .as_mut()
            .unwrap()
            .set_checkpoint(Local::now());
    }

    // Windowsイベントログファイルを1ファイル分解析する。
    fn analysis_file(
        &self,
        (evtx_filepath, time_filter, target_event_ids, stored_static): (
            PathBuf,
            &TargetEventTime,
            &TargetIds,
            &StoredStatic,
        ),
        mut detection: detection::Detection,
        mut tl: Timeline,
        afterfact_writer: &mut AfterfactWriter,
        afterfact_info: &mut AfterfactInfo,
    ) -> (
        detection::Detection,
        usize,
        Timeline,
        usize,
        Vec<DetectInfo>,
    ) {
        let path = evtx_filepath.display();
        let parser = self.evtx_to_jsons(&evtx_filepath, stored_static.enable_recover_records);
        let mut record_cnt = 0;
        let mut recover_records_cnt = 0;
        let mut detect_infos: Vec<DetectInfo> = vec![];
        if parser.is_none() {
            return (detection, record_cnt, tl, 0, detect_infos);
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

                if record_result.is_ok()
                    && record_result.as_ref().unwrap().allocation == RecordAllocation::EmptyPage
                {
                    recover_records_cnt += 1;
                }

                if record_result.is_err() {
                    let evtx_filepath = &path;
                    let errmsg = format!(
                        "Failed to parse event file.\nEventFile: {}\nError: {}\n",
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
                            .push(format!("[ERROR] {errmsg}"));
                    }
                    continue;
                }

                let data = &record_result.as_ref().unwrap().data;
                if stored_static.computer_metrics_flag {
                    countup_event_by_computer(data, &stored_static.eventkey_alias, &mut tl);
                    // computer-metricsコマンドでは検知は行わないためカウントのみ行い次のレコードを確認する
                    continue;
                }

                // Searchならすべてのフィルタを無視
                if !stored_static.search_flag {
                    // Computer名がinclude_computerで指定されたものに合致しないまたはexclude_computerで指定されたものに合致した場合はフィルタリングする。
                    if utils::is_filtered_by_computer_name(
                        utils::get_event_value(
                            "Event.System.Computer",
                            data,
                            &stored_static.eventkey_alias,
                        ),
                        (
                            &stored_static.include_computer,
                            &stored_static.exclude_computer,
                        ),
                    ) {
                        continue;
                    }

                    // EventIDがinclude_eidで指定されたものに合致しないまたはexclude_eidで指定されたものに合致した場合、target_eventids.txtで指定されたEventIDではない場合はフィルタリングする。
                    if self.is_filtered_by_eid(
                        data,
                        &stored_static.eventkey_alias,
                        (&stored_static.include_eid, &stored_static.exclude_eid),
                        stored_static.output_option.as_ref().unwrap().eid_filter,
                        target_event_ids,
                    ) {
                        continue;
                    }

                    // channelがnullである場合はフィルタリングする。
                    if !self._is_valid_channel(
                        data,
                        &stored_static.eventkey_alias,
                        "Event.System.Channel",
                    ) {
                        continue;
                    }
                }
                // EventID側の条件との条件の混同を防ぐため時間でのフィルタリングの条件分岐を分離した
                let timestamp = record_result.as_ref().unwrap().timestamp;
                if !time_filter.is_target(&Some(timestamp)) {
                    continue;
                }

                let recover_record_flag = record_result.is_ok()
                    && record_result.as_ref().unwrap().allocation == RecordAllocation::EmptyPage;
                records_per_detect.push((data.to_owned(), recover_record_flag));
            }
            if records_per_detect.is_empty() {
                break;
            }

            let records_per_detect = self.rt.block_on(App::create_rec_infos(
                records_per_detect,
                &path,
                self.rule_keys.to_owned(),
                stored_static.no_pwsh_field_extraction,
            ));

            // timeline機能の実行
            tl.start(&records_per_detect, stored_static);
            if !(stored_static.metrics_flag
                || stored_static.logon_summary_flag
                || stored_static.search_flag)
            {
                // detect event record by rule file
                let (detection_tmp, mut log_records) =
                    detection.start(&self.rt, records_per_detect);
                if stored_static.is_low_memory {
                    let empty_ids = HashSet::new();
                    afterfact::emit_csv(
                        &log_records,
                        &empty_ids,
                        stored_static,
                        afterfact_writer,
                        afterfact_info,
                    );
                } else {
                    detect_infos.append(&mut log_records);
                }
                detection = detection_tmp;
            }
        }
        tl.total_record_cnt += record_cnt;
        (detection, record_cnt, tl, recover_records_cnt, detect_infos)
    }

    // JSON形式のイベントログファイルを1ファイル分解析する。
    fn analysis_json_file(
        &self,
        (filepath, time_filter, target_event_ids, stored_static): (
            PathBuf,
            &TargetEventTime,
            &TargetIds,
            &StoredStatic,
        ),
        mut detection: detection::Detection,
        mut tl: Timeline,
        afterfact_writer: &mut AfterfactWriter,
        afterfact_info: &mut AfterfactInfo,
    ) -> (
        detection::Detection,
        usize,
        Timeline,
        usize,
        Vec<DetectInfo>,
    ) {
        let path = filepath.display();
        let mut record_cnt = 0;
        let recover_records_cnt = 0;
        let filename = filepath.to_str().unwrap_or_default();
        let filepath = if filename.starts_with("./") {
            check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), filename, true)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        } else {
            filename.to_string()
        };
        let jsonl_value_iter = utils::read_jsonl_to_value(&filepath);
        let mut detect_infos: Vec<DetectInfo> = vec![];
        let mut records = match jsonl_value_iter {
            // JSONL形式の場合
            Ok(values) => values,
            // JSONL形式以外(JSON(Array or jq)形式)の場合
            Err(_) => {
                let json_value_iter = utils::read_json_to_value(&filepath);
                match json_value_iter {
                    Ok(values) => values,
                    Err(e) => {
                        AlertMessage::alert(&e).ok();
                        return (detection, record_cnt, tl, recover_records_cnt, detect_infos);
                    }
                }
            }
        };

        loop {
            let mut records_per_detect = vec![];
            while records_per_detect.len() < MAX_DETECT_RECORDS {
                // パースに失敗している場合、エラーメッセージを出力
                let next_rec = records.next();
                if next_rec.is_none() {
                    break;
                }
                record_cnt += 1;
                let mut data = next_rec.unwrap();
                let is_splunk_json = data["Event"]["EventData"]["result"].is_object();
                // ChannelなどのデータはEvent -> Systemに存在する必要があるが、他処理のことも考え、Event -> EventDataのデータをそのまま投入する形にした。cloneを利用しているのはCopy trait実装がserde_json::Valueにないため

                if is_splunk_json {
                    data["Event"]["System"] = data["Event"]["EventData"]["result"].clone();
                    data["Event"]["EventData"] = data["Event"]["EventData"]["result"].clone();
                }
                if data["Event"]["EventData"].is_object() {
                    data["Event"]["System"] = data["Event"]["EventData"].clone();
                } else if data["Event"]["EventData"].is_array() {
                    data["Event"]["System"] =
                        data["Event"]["EventData"].as_array().unwrap()[0].clone();
                }
                data["Event"]["System"]
                    .as_object_mut()
                    .unwrap()
                    .insert("EventRecordID".to_string(), Value::from(1));
                data["Event"]["System"]["EventRecordID"] =
                    data["Event"]["EventData"]["RecordNumber"].clone();
                data["Event"]["System"].as_object_mut().unwrap().insert(
                    "Provider_attributes".to_string(),
                    Value::Object(Map::from_iter(vec![("Name".to_string(), Value::from(1))])),
                );
                data["Event"]["UserData"] = data["Event"]["EventData"].clone();

                if is_splunk_json {
                    data["Event"]["EventData"]["@timestamp"] =
                        data["Event"]["EventData"]["_time"].clone();
                    data["Event"]["System"]["@timestamp"] =
                        data["Event"]["EventData"]["_time"].clone();
                    data["Event"]["System"]["Provider_attributes"]["Name"] =
                        data["Event"]["EventData"]["Name"].clone();
                } else {
                    data["Event"]["System"]["Provider_attributes"]["Name"] =
                        data["Event"]["EventData"]["SourceName"].clone();
                    // Computer名に対応する内容はHostnameであることがわかったためデータをクローンして投入
                    data["Event"]["System"]["Computer"] =
                        data["Event"]["EventData"]["Hostname"].clone();
                }

                if stored_static.computer_metrics_flag {
                    countup_event_by_computer(&data, &stored_static.eventkey_alias, &mut tl);
                    // computer-metricsコマンドでは検知は行わないためカウントのみ行い次のレコードを確認する
                    continue;
                }

                // Computer名がinclude_computerで指定されたものに合致しないまたはexclude_computerで指定されたものに合致した場合はフィルタリングする。
                if utils::is_filtered_by_computer_name(
                    utils::get_event_value(
                        "Event.System.Computer",
                        &data,
                        &stored_static.eventkey_alias,
                    ),
                    (
                        &stored_static.include_computer,
                        &stored_static.exclude_computer,
                    ),
                ) {
                    continue;
                }

                // EventIDがinclude_eidで指定されたものに合致しないまたはexclude_eidで指定されたものに合致した場合、EventID Filter optionが指定されていないかつtarget_eventids.txtで指定されたEventIDではない場合はフィルタリングする。
                if self.is_filtered_by_eid(
                    &data,
                    &stored_static.eventkey_alias,
                    (&stored_static.include_eid, &stored_static.exclude_eid),
                    stored_static.output_option.as_ref().unwrap().eid_filter,
                    target_event_ids,
                ) {
                    continue;
                }

                // channelがnullである場合はフィルタリングする。
                if !self._is_valid_channel(
                    &data,
                    &stored_static.eventkey_alias,
                    "Event.EventData.Channel",
                ) {
                    continue;
                }
                let target_timestamp = if data["Event"]["EventData"]["@timestamp"].is_null() {
                    &data["Event"]["EventData"]["TimeGenerated"]
                } else {
                    &data["Event"]["EventData"]["@timestamp"]
                };
                let time_fmt = if is_splunk_json {
                    "%Y-%m-%dT%H:%M:%S%.3f%:z"
                } else {
                    "%Y-%m-%dT%H:%M:%S%.3fZ"
                };
                // EventID側の条件との条件の混同を防ぐため時間でのフィルタリングの条件分岐を分離した
                let timestamp = match NaiveDateTime::parse_from_str(
                    &target_timestamp
                        .to_string()
                        .replace("\\\"", "")
                        .replace('"', ""),
                    time_fmt,
                ) {
                    Ok(without_timezone_datetime) => Some(
                        DateTime::<Utc>::from_naive_utc_and_offset(without_timezone_datetime, Utc),
                    ),
                    Err(e) => {
                        AlertMessage::alert(&format!(
                            "timestamp parse error. filepath:{},{} {}",
                            path,
                            &target_timestamp
                                .to_string()
                                .replace("\\\"", "")
                                .replace('"', ""),
                            e
                        ))
                        .ok();
                        None
                    }
                };
                if !time_filter.is_target(&timestamp) {
                    continue;
                }

                records_per_detect.push((data.to_owned(), false));
            }
            if records_per_detect.is_empty() {
                break;
            }

            let records_per_detect = self.rt.block_on(App::create_rec_infos(
                records_per_detect,
                &path,
                self.rule_keys.to_owned(),
                stored_static.no_pwsh_field_extraction,
            ));

            // timeline機能の実行
            tl.start(&records_per_detect, stored_static);

            // 以下のコマンドの際にはルールにかけない
            if !(stored_static.metrics_flag
                || stored_static.logon_summary_flag
                || stored_static.search_flag)
            {
                // ruleファイルの検知
                let (detection_tmp, mut log_records) =
                    detection.start(&self.rt, records_per_detect);
                if stored_static.is_low_memory {
                    let empty_ids = HashSet::new();
                    afterfact::emit_csv(
                        &log_records,
                        &empty_ids,
                        stored_static,
                        afterfact_writer,
                        afterfact_info,
                    );
                } else {
                    detect_infos.append(&mut log_records);
                }
                detection = detection_tmp;
            }
        }
        tl.total_record_cnt += record_cnt;
        (detection, record_cnt, tl, recover_records_cnt, detect_infos)
    }

    async fn create_rec_infos(
        records_per_detect: Vec<(Value, bool)>,
        path: &dyn Display,
        rule_keys: Nested<String>,
        no_pwsh_field_extraction: bool,
    ) -> Vec<EvtxRecordInfo> {
        let no_pwsh_field_extraction = Arc::new(no_pwsh_field_extraction);
        let path = Arc::new(path.to_string());
        let rule_keys = Arc::new(rule_keys);
        let threads: Vec<JoinHandle<EvtxRecordInfo>> = {
            let this = records_per_detect.into_iter().map(
                |(rec, recovered_record_flag)| -> JoinHandle<EvtxRecordInfo> {
                    let arc_rule_keys = Arc::clone(&rule_keys);
                    let arc_path = Arc::clone(&path);
                    let arc_no_pwsh_field_extraction = Arc::clone(&no_pwsh_field_extraction);
                    spawn(async move {
                        utils::create_rec_info(
                            rec,
                            arc_path.to_string(),
                            &arc_rule_keys,
                            &recovered_record_flag,
                            &arc_no_pwsh_field_extraction,
                        )
                    })
                },
            );
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
        target_event_ids: &TargetIds,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> bool {
        let eventid = utils::get_event_value(&utils::get_event_id_key(), data, eventkey_alias);
        if eventid.is_none() {
            return true;
        }

        match eventid.unwrap() {
            Value::String(s) => target_event_ids.is_target(&s.replace('\"', ""), true),
            Value::Number(n) => target_event_ids.is_target(&n.to_string().replace('\"', ""), true),
            _ => true, // レコードからEventIdが取得できない場合は、特にフィルタしない
        }
    }

    /// レコードのチャンネルの値が正しい(Stringの形でありnullでないもの)ことを判定する関数
    fn _is_valid_channel(
        &self,
        data: &Value,
        eventkey_alias: &EventKeyAliasConfig,
        channel_key: &str,
    ) -> bool {
        let channel = utils::get_event_value(channel_key, data, eventkey_alias);
        if channel.is_none() {
            return false;
        }
        match channel.unwrap() {
            Value::String(s) => s != "null",
            _ => false, // channelの値は文字列を想定しているため、それ以外のデータが来た場合はfalseを返す
        }
    }

    fn is_filtered_by_eid(
        &self,
        data: &Value,
        eventkey_alias: &EventKeyAliasConfig,
        (include_eid, exclude_eid): (&HashSet<CompactString>, &HashSet<CompactString>),
        eid_filter: bool,
        target_event_ids: &TargetIds,
    ) -> bool {
        let target_eid = if !include_eid.is_empty() || !exclude_eid.is_empty() {
            if let Some(eid_record) =
                utils::get_event_value(&utils::get_event_id_key(), data, eventkey_alias)
            {
                utils::get_serde_number_to_string(eid_record, false).unwrap_or_default()
            } else {
                CompactString::default()
            }
        } else {
            CompactString::default()
        };
        // 以下の場合はフィルタリングする。
        // 1. include_eidが指定されているが、include_eidに含まれていない場合
        // 2. exclude_eidが指定されていて、exclude_eidに含まれている場合
        // 3. eid_filterが指定されていて、target_eventids.txtで指定されたEventIDでない場合
        (!include_eid.is_empty() && !include_eid.contains(&target_eid))
            || (!exclude_eid.is_empty() && exclude_eid.contains(&target_eid))
            || (eid_filter && !self._is_target_event_id(data, target_event_ids, eventkey_alias))
    }

    fn evtx_to_jsons(
        &self,
        evtx_filepath: &PathBuf,
        enable_recover_records: bool,
    ) -> Option<EvtxParser<File>> {
        match EvtxParser::from_path(evtx_filepath) {
            Ok(evtx_parser) => {
                // parserのデフォルト設定を変更
                let mut parse_config =
                    ParserSettings::default().parse_empty_chunks(enable_recover_records);
                parse_config = parse_config.separate_json_attributes(true); // XMLのattributeをJSONに変換する時のルールを設定
                parse_config = parse_config.num_threads(0); // 設定しないと遅かったので、設定しておく。

                let evtx_parser = evtx_parser.with_configuration(parse_config);
                Option::Some(evtx_parser)
            }
            Err(e) => {
                eprintln!("{e}");
                Option::None
            }
        }
    }

    /// output logo
    fn output_logo(&self, stored_static: &StoredStatic) {
        let fp = utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "art/logo.txt", true)
            .unwrap();
        let content = fs::read_to_string(fp).unwrap_or_default();
        let output_color = if stored_static.common_options.no_color {
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
        eggs.insert("10/31", ("art/halloween.txt", Color::Rgb(255, 87, 51))); // Pumpkin Orange
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
            | Action::EidMetrics(_)
            | Action::PivotKeywordsList(_)
            | Action::SetDefaultProfile(_)
            | Action::Search(_)
            | Action::ComputerMetrics(_) => std::env::args().len() != 2,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, remove_file, File},
        path::Path,
    };

    use crate::App;
    use chrono::Local;
    use hashbrown::HashSet;
    use hayabusa::{
        afterfact::{self, AfterfactInfo},
        detections::{
            configs::{
                Action, CommonOptions, ComputerMetricsOption, Config, ConfigReader,
                CsvOutputOption, DetectCommonOption, EidMetricsOption, InputOption,
                JSONOutputOption, LogonSummaryOption, OutputOption, StoredStatic, TargetEventTime,
                TargetIds, STORED_EKEY_ALIAS, STORED_STATIC,
            },
            detection,
            rule::create_rule,
        },
        options::htmlreport::HTML_REPORTER,
        timeline::timelines::Timeline,
    };
    use itertools::Itertools;
    use yaml_rust::YamlLoader;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        timeline_offset: None,
                    },
                    profile: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    exact_level: None,
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                    common_options: CommonOptions {
                        no_color: false,
                        quiet: false,
                        help: None,
                    },
                    detect_common_options: DetectCommonOption {
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                        json_input: true,
                        include_computer: None,
                        exclude_computer: None,
                    },
                    enable_unsupported_rules: false,
                    clobber: false,
                    proven_rules: false,
                    include_tag: None,
                    exclude_tag: None,
                    include_category: None,
                    exclude_category: None,
                    include_eid: None,
                    exclude_eid: None,
                    no_field: false,
                    no_pwsh_field_extraction: false,
                    remove_duplicate_data: false,
                    remove_duplicate_detections: false,
                    no_wizard: true,
                    include_status: None,
                    low_memory_mode: false,
                },
                geo_ip: None,
                output: None,
                multiline: false,
            })),
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

    #[test]
    fn test_exec_general_html_output() {
        let mut app = App::new(None);
        let mut config_reader = ConfigReader::new();
        let mut stored_static = StoredStatic::create_static_data(config_reader.config);
        config_reader.config = None;
        stored_static.config.action = None;
        stored_static.html_report_flag = true;
        app.exec(&mut config_reader.app, &mut stored_static);
        let expect_general_contents = [
            format!("- Command line: {}", std::env::args().join(" ")),
            format!("- Start time: {}", Local::now().format("%Y/%m/%d %H:%M")),
        ];

        let actual = &HTML_REPORTER.read().unwrap().md_datas;
        let general_contents = actual.get("General Overview {#general_overview}").unwrap();
        assert_eq!(expect_general_contents.len(), general_contents.len());

        for actual_general_contents in general_contents.iter() {
            assert!(expect_general_contents.contains(&actual_general_contents.to_string()));
        }
    }

    #[test]
    fn test_analysis_json_file() {
        let mut app = App::new(None);
        let stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());

        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
            condition: selection1
        details: testdata
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let mut rule = create_rule("testpath".to_string(), test_yaml_data);
        let rule_init = rule.init(&stored_static);
        assert!(rule_init.is_ok());
        let rule_files = vec![rule];
        app.rule_keys = app.get_all_keys(&rule_files);
        let detection = detection::Detection::new(rule_files);
        let target_time_filter = TargetEventTime::new(&stored_static);
        let tl = Timeline::default();
        let target_event_ids = TargetIds::default();
        let mut afterfact_info = AfterfactInfo::default();
        let mut afterfact_writer = afterfact::init_writer(&stored_static);

        let actual = app.analysis_json_file(
            (
                Path::new("test_files/evtx/test.jsonl").to_path_buf(),
                &target_time_filter,
                &target_event_ids,
                &stored_static,
            ),
            detection,
            tl,
            &mut afterfact_writer,
            &mut afterfact_info,
        );
        assert_eq!(actual.1, 2);
        // TODO add check
        //assert_eq!(MESSAGES.len(), 2);
    }

    #[test]
    fn test_same_file_output_csv_exit() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite.csv").ok();
        let action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("test_files/evtx/test.json").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./test_files/rules/yaml/test_json_detect.yml").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: true,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                low_memory_mode: false,
            },
            geo_ip: None,
            output: Some(Path::new("overwrite.csv").to_path_buf()),
            multiline: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        // TODO add check
        // assert_eq!(MESSAGES.len(), 0);

        // テストファイルの作成
        remove_file("overwrite.csv").ok();
    }

    #[test]
    fn test_overwrite_csv() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite.csv").ok();
        let action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("test_files/evtx/test.json").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("test_files/rules/yaml/test_json_detect.yml").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: true,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: true,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                low_memory_mode: false,
            },
            geo_ip: None,
            output: Some(Path::new("overwrite.csv").to_path_buf()),
            multiline: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        // TODO add check
        // assert_ne!(MESSAGES.len(), 0);
        // テストファイルの作成
        remove_file("overwrite.csv").ok();
    }

    #[test]
    fn test_same_file_output_json_exit() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite.json").ok();
        let action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("test_files/evtx/test.json").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./test_files/rules/yaml/test_json_detect.yml").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: true,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                low_memory_mode: false,
            },
            geo_ip: None,
            output: Some(Path::new("overwrite.json").to_path_buf()),
            jsonl_timeline: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        // TODO add check
        // assert_eq!(MESSAGES.len(), 0);

        // テストファイルの作成
        remove_file("overwrite.json").ok();
    }

    #[test]
    fn test_overwrite_json() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite.csv").ok();
        let action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("test_files/evtx/test.json").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("test_files/rules/yaml/test_json_detect.yml").to_path_buf(),
                html_report: None,
                no_summary: true,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: true,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: true,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                low_memory_mode: false,
            },
            geo_ip: None,
            output: Some(Path::new("overwrite.json").to_path_buf()),
            jsonl_timeline: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        // TODO add check
        // assert_ne!(MESSAGES.len(), 0);
        // テストファイルの削除
        remove_file("overwrite.json").ok();
    }

    #[test]
    fn test_same_file_output_metric_csv_exit() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-metric.csv").ok();
        let action = Action::EidMetrics(EidMetricsOption {
            output: Some(Path::new("overwrite-metric.csv").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                recover_records: false,
                timeline_offset: None,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: true,
                include_computer: None,
                exclude_computer: None,
            },
            european_time: false,
            iso_8601: false,
            rfc_2822: false,
            rfc_3339: false,
            us_military_time: false,
            us_time: false,
            utc: false,
            clobber: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-metric.csv").unwrap();
        assert_eq!(meta.len(), 0);

        // テストファイルの削除
        remove_file("overwrite-metric.csv").ok();
        remove_file("overwrite-metric").ok();
    }

    #[test]
    fn test_same_file_output_metric_csv() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-metric.csv").ok();
        let action = Action::EidMetrics(EidMetricsOption {
            output: Some(Path::new("overwrite-metric.csv").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                recover_records: false,
                timeline_offset: None,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: true,
                include_computer: None,
                exclude_computer: None,
            },
            european_time: false,
            iso_8601: false,
            rfc_2822: false,
            rfc_3339: false,
            us_military_time: false,
            us_time: false,
            utc: false,
            clobber: true,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-metric.csv").unwrap();
        assert_ne!(meta.len(), 0);
        // テストファイルの削除
        remove_file("overwrite-metric.csv").ok();
    }

    #[test]
    fn test_same_file_output_logon_summary_csv_exit() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-metric-successful.csv").ok();
        let action = Action::LogonSummary(LogonSummaryOption {
            output: Some(Path::new("overwrite-metric").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                timeline_offset: None,
                recover_records: false,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: true,
                include_computer: None,
                exclude_computer: None,
            },
            european_time: false,
            iso_8601: false,
            rfc_2822: false,
            rfc_3339: false,
            us_military_time: false,
            us_time: false,
            utc: false,
            clobber: false,
            end_timeline: None,
            start_timeline: None,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-metric-successful.csv").unwrap();
        assert_eq!(meta.len(), 0);

        // テストファイルの削除
        remove_file("overwrite-metric-successful.csv").ok();
    }

    #[test]
    fn test_same_file_output_logon_summary_csv() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-metric-successful.csv").ok();
        let action = Action::LogonSummary(LogonSummaryOption {
            output: Some(Path::new("overwrite-metric").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                recover_records: false,
                timeline_offset: None,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: true,
                include_computer: None,
                exclude_computer: None,
            },
            european_time: false,
            iso_8601: false,
            rfc_2822: false,
            rfc_3339: false,
            us_military_time: false,
            us_time: false,
            utc: false,
            clobber: true,
            end_timeline: None,
            start_timeline: None,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-metric-successful.csv").unwrap();
        assert_ne!(meta.len(), 0);
        // テストファイルの削除
        remove_file("overwrite-metric-successful").ok();
    }

    #[test]
    fn test_same_file_output_computer_metrics_exit() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-computer-metrics.csv").ok();
        let action = Action::ComputerMetrics(ComputerMetricsOption {
            output: Some(Path::new("overwrite-computer-metrics.csv").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                recover_records: false,
                timeline_offset: None,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            evtx_file_ext: None,
            thread_number: None,
            quiet_errors: false,
            config: Path::new("./rules/config").to_path_buf(),
            verbose: false,
            json_input: true,
            clobber: false,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-computer-metrics.csv").unwrap();
        assert_eq!(meta.len(), 0);
        // テストファイルの削除
        remove_file("overwrite-computer-metrics").ok();
        remove_file("overwrite-computer-metrics.csv").ok();
    }

    #[test]
    fn test_same_file_output_computer_metrics_csv() {
        // 先に空ファイルを作成する
        let mut app = App::new(None);
        File::create("overwrite-computer-metrics.csv").ok();
        let action = Action::ComputerMetrics(ComputerMetricsOption {
            output: Some(Path::new("overwrite-computer-metrics.csv").to_path_buf()),
            input_args: InputOption {
                directory: None,
                filepath: Some(Path::new("test_files/evtx/test_metrics.json").to_path_buf()),
                live_analysis: false,
                recover_records: false,
                timeline_offset: None,
            },
            common_options: CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
            evtx_file_ext: None,
            thread_number: None,
            quiet_errors: false,
            config: Path::new("./rules/config").to_path_buf(),
            verbose: false,
            json_input: true,
            clobber: true,
        });
        let config = Some(Config {
            action: Some(action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(config);
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());
        let mut config_reader = ConfigReader::new();
        app.exec(&mut config_reader.app, &mut stored_static);
        let meta = fs::metadata("overwrite-computer-metrics.csv").unwrap();
        assert_ne!(meta.len(), 0);
        // テストファイルの削除
        remove_file("overwrite-computer-metrics.csv").ok();
    }

    #[test]
    fn test_analysis_json_file_include_eid() {
        let mut app = App::new(None);
        let mut stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        stored_static.include_eid = HashSet::from_iter(vec!["10".into()]);
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());

        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
            condition: selection1
        details: testdata
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let mut rule = create_rule("testpath".to_string(), test_yaml_data);
        let rule_init = rule.init(&stored_static);
        assert!(rule_init.is_ok());
        let rule_files = vec![rule];
        app.rule_keys = app.get_all_keys(&rule_files);
        let detection = detection::Detection::new(rule_files);
        let target_time_filter = TargetEventTime::new(&stored_static);
        let tl = Timeline::default();
        let target_event_ids = TargetIds::default();
        let mut afterfact_info = AfterfactInfo::default();
        let mut afterfact_writer = afterfact::init_writer(&stored_static);

        let actual = app.analysis_json_file(
            (
                Path::new("test_files/evtx/test.jsonl").to_path_buf(),
                &target_time_filter,
                &target_event_ids,
                &stored_static,
            ),
            detection,
            tl,
            &mut afterfact_writer,
            &mut afterfact_info,
        );
        assert_eq!(actual.1, 2);
        assert_eq!(actual.4.len(), 1);
    }

    #[test]
    fn test_analysis_json_file_exclude_eid() {
        let mut app = App::new(None);
        let mut stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(stored_static.eventkey_alias.clone());
        stored_static.exclude_eid = HashSet::from_iter(vec!["10".into(), "11".into()]);
        *STORED_STATIC.write().unwrap() = Some(stored_static.clone());

        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
            condition: selection1
        details: testdata
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let mut rule = create_rule("testpath".to_string(), test_yaml_data);
        let rule_init = rule.init(&stored_static);
        assert!(rule_init.is_ok());
        let rule_files = vec![rule];
        app.rule_keys = app.get_all_keys(&rule_files);
        let detection = detection::Detection::new(rule_files);
        let target_time_filter = TargetEventTime::new(&stored_static);
        let tl = Timeline::default();
        let target_event_ids = TargetIds::default();
        let mut afterfact_info = AfterfactInfo::default();
        let mut afterfact_writer = afterfact::init_writer(&stored_static);

        let actual = app.analysis_json_file(
            (
                Path::new("test_files/evtx/test.jsonl").to_path_buf(),
                &target_time_filter,
                &target_event_ids,
                &stored_static,
            ),
            detection,
            tl,
            &mut afterfact_writer,
            &mut afterfact_info,
        );
        assert_eq!(actual.1, 2);
        assert_eq!(actual.4.len(), 0);
    }
}

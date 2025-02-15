use super::message::create_output_filter_config;
use super::utils::check_setting_path;
use crate::detections::field_data_map::{create_field_data_map, FieldDataMap};
use crate::detections::message::AlertMessage;
use crate::detections::utils;
use crate::level::LEVEL;
use crate::options::geoip_search::GeoIPSearch;
use crate::options::htmlreport;
use crate::options::pivot::PIVOT_KEYWORD;
use crate::options::profile::{load_profile, Profile};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use chrono::{DateTime, Days, Duration, Local, Months, Utc};
use clap::{ArgAction, ArgGroup, Args, ColorChoice, Command, CommandFactory, Parser, Subcommand};
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use std::cmp::PartialEq;
use std::env::current_exe;
use std::fs::File;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::{fs, io, process};
use strum::IntoEnumIterator;
use terminal_size::{terminal_size, Width};
use yaml_rust2::{Yaml, YamlLoader};

lazy_static! {
    pub static ref STORED_STATIC: RwLock<Option<StoredStatic>> = RwLock::new(None);
    pub static ref STORED_EKEY_ALIAS: RwLock<Option<EventKeyAliasConfig>> = RwLock::new(None);
    pub static ref GEOIP_DB_PARSER: RwLock<Option<GeoIPSearch>> = RwLock::new(None);
    pub static ref GEOIP_DB_YAML: RwLock<Option<HashMap<CompactString, Yaml>>> = RwLock::new(None);
    pub static ref GEOIP_FILTER: RwLock<Option<Vec<Yaml>>> = RwLock::new(None);
    pub static ref CURRENT_EXE_PATH: PathBuf =
        current_exe().unwrap().parent().unwrap().to_path_buf();
    pub static ref IDS_REGEX: Regex =
        Regex::new(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$").unwrap();
    pub static ref CONTROL_CHAT_REPLACE_MAP: HashMap<char, CompactString> =
        create_control_chat_replace_map();
    pub static ref ALLFIELDINFO_SPECIAL_CHARS: AhoCorasick = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(["🛂r", "🛂n", "🛂t"])
        .unwrap();
    pub static ref ONE_CONFIG_MAP: HashMap<String, String> =
        read_one_config_file(Path::new("rules_config_files.txt")).unwrap_or_default();
    pub static ref WINDASH_CHARACTERS: Vec<char> = load_windash_characters(
        check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "rules/config/windash_characters.txt",
            true,
        )
        .unwrap()
        .to_str()
        .unwrap(),
    );
}

fn read_one_config_file(file_path: &Path) -> io::Result<HashMap<String, String>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);

    let mut sections = HashMap::new();
    let mut current_path = String::new();
    let mut current_content = String::new();
    let mut in_content = false;

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("---FILE_START---") {
            current_path.clear();
            current_content.clear();
            in_content = false;
        } else if let Some(path) = line.strip_prefix("path: ") {
            current_path = path.to_string();
        } else if line.starts_with("---CONTENT---") {
            in_content = true;
        } else if line.starts_with("---FILE_END---") {
            sections.insert(current_path.clone(), current_content.clone());
        } else if in_content {
            current_content.push_str(&line);
            current_content.push('\n');
        }
    }
    Ok(sections)
}

pub struct ConfigReader {
    pub app: Command,
    pub config: Option<Config>,
}

impl Default for ConfigReader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StoredStatic {
    pub config: Config,
    pub config_path: PathBuf,
    pub eventkey_alias: EventKeyAliasConfig,
    pub ch_config: HashMap<CompactString, CompactString>,
    pub disp_abbr_generic: AhoCorasick,
    pub disp_abbr_general_values: Vec<CompactString>,
    pub provider_abbr_config: HashMap<CompactString, CompactString>,
    pub quiet_errors_flag: bool,
    pub verbose_flag: bool,
    pub metrics_flag: bool,
    pub logon_summary_flag: bool,
    pub search_flag: bool,
    pub computer_metrics_flag: bool,
    pub log_metrics_flag: bool,
    pub extract_base64_flag: bool,
    pub search_option: Option<SearchOption>,
    pub output_option: Option<OutputOption>,
    pub pivot_keyword_list_flag: bool,
    pub default_details: HashMap<CompactString, CompactString>,
    pub html_report_flag: bool,
    pub profiles: Option<Vec<(CompactString, Profile)>>,
    pub event_timeline_config: EventInfoConfig,
    pub target_eventids: TargetIds,
    pub target_ruleids: TargetIds,
    pub thread_number: Option<usize>,
    pub json_input_flag: bool,
    pub output_path: Option<PathBuf>,
    pub common_options: CommonOptions,
    pub multiline_flag: bool,
    pub include_computer: HashSet<CompactString>,
    pub exclude_computer: HashSet<CompactString>,
    pub include_eid: HashSet<CompactString>,
    pub exclude_eid: HashSet<CompactString>,
    pub include_status: HashSet<CompactString>, // 読み込み対象ルールのステータスのセット。*はすべてのステータスを読み込む
    pub field_data_map: Option<FieldDataMap>,
    pub no_pwsh_field_extraction: bool,
    pub enable_recover_records: bool,
    pub time_offset: Option<String>,
    pub is_low_memory: bool,
    pub enable_all_rules: bool,
    pub scan_all_evtx_files: bool,
    pub metrics_remove_duplication: bool,
}

impl StoredStatic {
    /// main.rsでパースした情報からデータを格納する関数
    pub fn create_static_data(input_config: Option<Config>) -> StoredStatic {
        let action_id = Action::to_usize(input_config.as_ref().unwrap().action.as_ref());
        let quiet_errors_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.detect_common_options.quiet_errors,
            Some(Action::JsonTimeline(opt)) => {
                opt.output_options.detect_common_options.quiet_errors
            }
            Some(Action::LogonSummary(opt)) => opt.detect_common_options.quiet_errors,
            Some(Action::EidMetrics(opt)) => opt.detect_common_options.quiet_errors,
            Some(Action::ExpandList(opt)) => opt.common_options.quiet,
            Some(Action::ExtractBase64(opt)) => opt.detect_common_options.quiet_errors,
            Some(Action::PivotKeywordsList(opt)) => opt.detect_common_options.quiet_errors,
            Some(Action::Search(opt)) => opt.quiet_errors,
            Some(Action::ComputerMetrics(opt)) => opt.quiet_errors,
            Some(Action::LogMetrics(opt)) => opt.detect_common_options.quiet_errors,
            _ => false,
        };
        let common_options = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.common_options,
            Some(Action::JsonTimeline(opt)) => opt.output_options.common_options,
            Some(Action::LevelTuning(opt)) => opt.common_options,
            Some(Action::LogonSummary(opt)) => opt.common_options,
            Some(Action::EidMetrics(opt)) => opt.common_options,
            Some(Action::ExtractBase64(opt)) => opt.common_options,
            Some(Action::PivotKeywordsList(opt)) => opt.common_options,
            Some(Action::SetDefaultProfile(opt)) => opt.common_options,
            Some(Action::ListContributors(opt)) | Some(Action::ListProfiles(opt)) => *opt,
            Some(Action::UpdateRules(opt)) => opt.common_options,
            Some(Action::Search(opt)) => opt.common_options,
            Some(Action::ComputerMetrics(opt)) => opt.common_options,
            Some(Action::LogMetrics(opt)) => opt.common_options,
            Some(Action::ExpandList(opt)) => opt.common_options,
            Some(Action::ConfigCriticalSystems(opt)) => opt.common_options,
            None => CommonOptions {
                no_color: false,
                quiet: false,
                help: None,
            },
        };
        let binding = Path::new("./rules/config").to_path_buf();
        let config_path = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => &opt.output_options.detect_common_options.config,
            Some(Action::JsonTimeline(opt)) => &opt.output_options.detect_common_options.config,
            Some(Action::LogonSummary(opt)) => &opt.detect_common_options.config,
            Some(Action::EidMetrics(opt)) => &opt.detect_common_options.config,
            Some(Action::ExtractBase64(opt)) => &opt.detect_common_options.config,
            Some(Action::PivotKeywordsList(opt)) => &opt.detect_common_options.config,
            Some(Action::Search(opt)) => &opt.config,
            Some(Action::ComputerMetrics(opt)) => &opt.config,
            Some(Action::LogMetrics(opt)) => &opt.detect_common_options.config,
            _ => &binding,
        };
        let verbose_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.detect_common_options.verbose,
            Some(Action::JsonTimeline(opt)) => opt.output_options.detect_common_options.verbose,
            Some(Action::LogonSummary(opt)) => opt.detect_common_options.verbose,
            Some(Action::EidMetrics(opt)) => opt.detect_common_options.verbose,
            Some(Action::ExtractBase64(opt)) => opt.detect_common_options.verbose,
            Some(Action::PivotKeywordsList(opt)) => opt.detect_common_options.verbose,
            Some(Action::Search(opt)) => opt.verbose,
            Some(Action::ComputerMetrics(opt)) => opt.verbose,
            Some(Action::LogMetrics(opt)) => opt.detect_common_options.verbose,
            _ => false,
        };
        let json_input_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.detect_common_options.json_input,
            Some(Action::JsonTimeline(opt)) => opt.output_options.detect_common_options.json_input,
            Some(Action::LogonSummary(opt)) => opt.detect_common_options.json_input,
            Some(Action::EidMetrics(opt)) => opt.detect_common_options.json_input,
            Some(Action::ExtractBase64(opt)) => opt.detect_common_options.json_input,
            Some(Action::PivotKeywordsList(opt)) => opt.detect_common_options.json_input,
            Some(Action::ComputerMetrics(opt)) => opt.json_input,
            Some(Action::LogMetrics(opt)) => opt.detect_common_options.json_input,
            _ => false,
        };
        let is_valid_min_level = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => LEVEL::iter()
                .any(|level| level.eq(opt.output_options.min_level.to_lowercase().as_str())),
            Some(Action::JsonTimeline(opt)) => LEVEL::iter()
                .any(|level| level.eq(opt.output_options.min_level.to_lowercase().as_str())),
            Some(Action::PivotKeywordsList(opt)) => {
                LEVEL::iter().any(|level| level.eq(opt.min_level.to_lowercase().as_str()))
            }
            _ => true,
        };
        let is_valid_exact_level = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => {
                opt.output_options.exact_level.is_none()
                    || LEVEL::iter().any(|level| {
                        level.eq(opt
                            .output_options
                            .exact_level
                            .as_ref()
                            .unwrap()
                            .to_lowercase()
                            .as_str())
                    })
            }
            Some(Action::JsonTimeline(opt)) => {
                opt.output_options.exact_level.is_none()
                    || LEVEL::iter().any(|level| {
                        level.eq(opt
                            .output_options
                            .exact_level
                            .as_ref()
                            .unwrap()
                            .to_lowercase()
                            .as_str())
                    })
            }
            Some(Action::PivotKeywordsList(opt)) => {
                opt.exact_level.is_none()
                    || LEVEL::iter().any(|level| {
                        level.eq(opt.exact_level.as_ref().unwrap().to_lowercase().as_str())
                    })
            }
            _ => true,
        };
        if !is_valid_min_level || !is_valid_exact_level {
            AlertMessage::alert(" You specified an invalid level. Please specify informational, low, medium, high or critical.").ok();
            process::exit(1);
        }

        let geo_ip_db_result = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => GeoIPSearch::check_exist_geo_ip_files(
                &opt.geo_ip,
                vec![
                    "GeoLite2-ASN.mmdb",
                    "GeoLite2-Country.mmdb",
                    "GeoLite2-City.mmdb",
                ],
            ),
            Some(Action::JsonTimeline(opt)) => GeoIPSearch::check_exist_geo_ip_files(
                &opt.geo_ip,
                vec![
                    "GeoLite2-ASN.mmdb",
                    "GeoLite2-Country.mmdb",
                    "GeoLite2-City.mmdb",
                ],
            ),
            _ => Ok(None),
        };
        if let Err(err_msg) = geo_ip_db_result {
            AlertMessage::alert(&err_msg).ok();
            process::exit(1);
        }
        if let Some(geo_ip_db_path) = geo_ip_db_result.unwrap() {
            *GEOIP_DB_PARSER.write().unwrap() = Some(GeoIPSearch::new(
                &geo_ip_db_path,
                vec![
                    "GeoLite2-ASN.mmdb",
                    "GeoLite2-Country.mmdb",
                    "GeoLite2-City.mmdb",
                ],
            ));
            let geo_ip_file_path = check_setting_path(config_path, "geoip_field_mapping", false)
                .unwrap_or_else(|| {
                    check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/geoip_field_mapping.yaml",
                        true,
                    )
                    .unwrap()
                });
            if !geo_ip_file_path.exists()
                && !ONE_CONFIG_MAP.contains_key("geoip_field_mapping.yaml")
            {
                AlertMessage::alert(
                    "Could not find the geoip_field_mapping.yaml config file. Please run update-rules."
                )
                .ok();
                process::exit(1);
            }
            let contents = if ONE_CONFIG_MAP.contains_key("geoip_field_mapping.yaml") {
                ONE_CONFIG_MAP
                    .get("geoip_field_mapping.yaml")
                    .unwrap()
                    .as_str()
            } else {
                &fs::read_to_string(geo_ip_file_path).unwrap()
            };
            let geo_ip_mapping = if let Ok(loaded_yaml) = YamlLoader::load_from_str(contents) {
                loaded_yaml
            } else {
                AlertMessage::alert("Parse error in geoip_field_mapping.yaml.").ok();
                YamlLoader::load_from_str("").unwrap()
            };
            let target_map = &geo_ip_mapping[0];
            let empty_yaml_vec: Vec<Yaml> = vec![];
            *GEOIP_FILTER.write().unwrap() = Some(
                target_map["Filter"]
                    .as_vec()
                    .unwrap_or(&empty_yaml_vec)
                    .to_owned(),
            );
            let mut static_geoip_conf = HashMap::new();
            let check_target_map = vec!["SrcIP", "TgtIP"];
            for check_key in check_target_map {
                if !target_map[check_key].is_badvalue()
                    && !target_map[check_key]
                        .as_vec()
                        .unwrap_or(&empty_yaml_vec)
                        .is_empty()
                {
                    static_geoip_conf.insert(
                        CompactString::from(check_key),
                        target_map[check_key].clone(),
                    );
                }
            }
            *GEOIP_DB_YAML.write().unwrap() = Some(static_geoip_conf);
        };
        let output_path = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output.as_ref(),
            Some(Action::JsonTimeline(opt)) => opt.output.as_ref(),
            Some(Action::EidMetrics(opt)) => opt.output.as_ref(),
            Some(Action::ExtractBase64(opt)) => opt.output.as_ref(),
            Some(Action::PivotKeywordsList(opt)) => opt.output.as_ref(),
            Some(Action::LogonSummary(opt)) => opt.output.as_ref(),
            Some(Action::Search(opt)) => opt.output.as_ref(),
            Some(Action::ComputerMetrics(opt)) => opt.output.as_ref(),
            Some(Action::LogMetrics(opt)) => opt.output.as_ref(),
            _ => None,
        };
        let disable_abbreviation = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.disable_abbreviations,
            Some(Action::JsonTimeline(opt)) => opt.disable_abbreviations,
            Some(Action::Search(opt)) => opt.disable_abbreviations,
            Some(Action::LogMetrics(opt)) => opt.disable_abbreviations,
            _ => false,
        };

        let general_ch_abbr = create_output_filter_config(
            check_setting_path(config_path, "generic_abbreviations.txt", false)
                .unwrap_or_else(|| {
                    check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/generic_abbreviations.txt",
                        true,
                    )
                    .unwrap()
                })
                .to_str()
                .unwrap(),
            false,
            disable_abbreviation,
        );
        let multiline_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.multiline,
            Some(Action::Search(opt)) => opt.multiline,
            Some(Action::LogMetrics(opt)) => opt.multiline,
            _ => false,
        };
        let proven_rule_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.proven_rules,
            Some(Action::JsonTimeline(opt)) => opt.output_options.proven_rules,
            _ => false,
        };
        let target_ruleids = if proven_rule_flag {
            load_target_ids(
                check_setting_path(config_path, "proven_rules.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/proven_rules.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            )
        } else {
            TargetIds::default()
        };
        let include_computer: HashSet<CompactString> = match &input_config.as_ref().unwrap().action
        {
            Some(Action::CsvTimeline(opt)) => opt
                .output_options
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::JsonTimeline(opt)) => opt
                .output_options
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::EidMetrics(opt)) => opt
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::ExtractBase64(opt)) => opt
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::PivotKeywordsList(opt)) => opt
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::LogonSummary(opt)) => opt
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::LogMetrics(opt)) => opt
                .detect_common_options
                .include_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            _ => HashSet::default(),
        };
        let exclude_computer: HashSet<CompactString> = match &input_config.as_ref().unwrap().action
        {
            Some(Action::CsvTimeline(opt)) => opt
                .output_options
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::JsonTimeline(opt)) => opt
                .output_options
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::EidMetrics(opt)) => opt
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::ExtractBase64(opt)) => opt
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::PivotKeywordsList(opt)) => opt
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::LogonSummary(opt)) => opt
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::LogMetrics(opt)) => opt
                .detect_common_options
                .exclude_computer
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            _ => HashSet::default(),
        };
        let include_eid: HashSet<CompactString> = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt
                .output_options
                .include_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::JsonTimeline(opt)) => opt
                .output_options
                .include_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::PivotKeywordsList(opt)) => opt
                .include_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            _ => HashSet::default(),
        };
        let exclude_eid: HashSet<CompactString> = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt
                .output_options
                .exclude_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::JsonTimeline(opt)) => opt
                .output_options
                .exclude_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            Some(Action::PivotKeywordsList(opt)) => opt
                .exclude_eid
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(CompactString::from)
                .collect(),
            _ => HashSet::default(),
        };
        let no_field_data_mapping_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.no_field,
            Some(Action::JsonTimeline(opt)) => opt.output_options.no_field,
            _ => false,
        };
        let field_data_map = if no_field_data_mapping_flag {
            None
        } else {
            create_field_data_map(Path::new(
                check_setting_path(config_path, "data_mapping", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/data_mapping",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ))
        };

        let no_pwsh_field_extraction_flag = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.no_pwsh_field_extraction,
            Some(Action::JsonTimeline(opt)) => opt.output_options.no_pwsh_field_extraction,
            _ => false,
        };

        let enable_recover_records = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.input_args.recover_records,
            Some(Action::JsonTimeline(opt)) => opt.output_options.input_args.recover_records,
            Some(Action::EidMetrics(opt)) => opt.input_args.recover_records,
            Some(Action::ExtractBase64(opt)) => opt.input_args.recover_records,
            Some(Action::LogonSummary(opt)) => opt.input_args.recover_records,
            Some(Action::PivotKeywordsList(opt)) => opt.input_args.recover_records,
            Some(Action::Search(opt)) => opt.input_args.recover_records,
            Some(Action::LogMetrics(opt)) => opt.input_args.recover_records,
            _ => false,
        };
        let time_offset = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.input_args.time_offset.clone(),
            Some(Action::JsonTimeline(opt)) => opt.output_options.input_args.time_offset.clone(),
            Some(Action::EidMetrics(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::ExtractBase64(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::LogonSummary(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::PivotKeywordsList(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::Search(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::ComputerMetrics(opt)) => opt.input_args.time_offset.clone(),
            Some(Action::LogMetrics(opt)) => opt.input_args.time_offset.clone(),
            _ => None,
        };
        let include_status: HashSet<CompactString> = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt
                .output_options
                .include_status
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| x.into())
                .collect(),
            Some(Action::JsonTimeline(opt)) => opt
                .output_options
                .include_status
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| x.into())
                .collect(),
            Some(Action::PivotKeywordsList(opt)) => opt
                .include_status
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| x.into())
                .collect(),
            _ => HashSet::default(),
        };
        let is_low_memory = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => !opt.output_options.sort_events,
            Some(Action::JsonTimeline(opt)) => !opt.output_options.sort_events,
            _ => false,
        };
        let enable_all_rules = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.enable_all_rules,
            Some(Action::JsonTimeline(opt)) => opt.output_options.enable_all_rules,
            _ => false,
        };
        let scan_all_evtx_files = match &input_config.as_ref().unwrap().action {
            Some(Action::CsvTimeline(opt)) => opt.output_options.scan_all_evtx_files,
            Some(Action::JsonTimeline(opt)) => opt.output_options.scan_all_evtx_files,
            _ => false,
        };
        let metrics_remove_duplication = match &input_config.as_ref().unwrap().action {
            Some(Action::EidMetrics(opt)) => opt.remove_duplicate_detections,
            Some(Action::LogonSummary(opt)) => opt.remove_duplicate_detections,
            _ => false,
        };
        let mut ret = StoredStatic {
            config: input_config.as_ref().unwrap().to_owned(),
            config_path: config_path.to_path_buf(),
            ch_config: create_output_filter_config(
                check_setting_path(config_path, "channel_abbreviations.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/channel_abbreviations.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
                true,
                disable_abbreviation,
            ),
            disp_abbr_generic: AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(general_ch_abbr.keys().map(|x| x.as_str()))
                .unwrap(),
            disp_abbr_general_values: general_ch_abbr.values().map(|x| x.to_owned()).collect_vec(),
            provider_abbr_config: create_output_filter_config(
                check_setting_path(config_path, "provider_abbreviations.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/provider_abbreviations.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
                false,
                disable_abbreviation,
            ),
            default_details: Self::get_default_details(
                check_setting_path(config_path, "default_details.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/default_details.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ),
            eventkey_alias: load_eventkey_alias(
                check_setting_path(config_path, "eventkey_alias.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/eventkey_alias.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ),
            logon_summary_flag: action_id == 2,
            metrics_flag: action_id == 3,
            search_flag: action_id == 10,
            computer_metrics_flag: action_id == 11,
            log_metrics_flag: action_id == 12,
            extract_base64_flag: action_id == 13,
            search_option: extract_search_options(input_config.as_ref().unwrap()),
            output_option: extract_output_options(input_config.as_ref().unwrap()),
            pivot_keyword_list_flag: action_id == 4,
            quiet_errors_flag,
            verbose_flag,
            html_report_flag: htmlreport::check_html_flag(input_config.as_ref().unwrap()),
            profiles: None,
            thread_number: check_thread_number(input_config.as_ref().unwrap()),
            event_timeline_config: load_eventcode_info(
                check_setting_path(config_path, "channel_eid_info.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/channel_eid_info.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ),
            target_eventids: load_target_ids(
                check_setting_path(config_path, "target_event_IDs.txt", false)
                    .unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/target_event_IDs.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ),
            target_ruleids,
            json_input_flag,
            output_path: output_path.cloned(),
            common_options,
            multiline_flag,
            include_computer,
            exclude_computer,
            include_eid,
            exclude_eid,
            field_data_map,
            no_pwsh_field_extraction: no_pwsh_field_extraction_flag,
            enable_recover_records,
            time_offset,
            include_status,
            is_low_memory,
            enable_all_rules,
            scan_all_evtx_files,
            metrics_remove_duplication,
        };
        ret.profiles = load_profile(
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
            Some(&ret),
        );
        ret
    }
    /// detailsのdefault値をファイルから読み取る関数
    pub fn get_default_details(filepath: &str) -> HashMap<CompactString, CompactString> {
        let read_result = utils::read_csv(filepath);
        match read_result {
            Err(_e) => {
                AlertMessage::alert(&_e).ok();
                HashMap::new()
            }
            Ok(lines) => {
                let mut ret: HashMap<CompactString, CompactString> = HashMap::new();
                lines
                    .iter()
                    .try_for_each(|line| -> Result<(), String> {
                        let provider = match line.first() {
                            Some(_provider) => _provider.trim(),
                            _ => {
                                return Err(
                                    "Failed to read provider in default_details.txt.".to_string()
                                )
                            }
                        };
                        let eid =
                            match line.get(1) {
                                Some(eid_str) => match eid_str.trim().parse::<i64>() {
                                    Ok(_eid) => _eid,
                                    _ => {
                                        return Err("EventID parsing error in default_details.txt."
                                            .to_string())
                                    }
                                },
                                _ => {
                                    return Err("Failed to read EventID in default_details.txt."
                                        .to_string())
                                }
                            };
                        let details = match line.get(2) {
                            Some(detail) => detail.trim(),
                            _ => {
                                return Err(
                                    "Failed to read details in default_details.txt.".to_string()
                                )
                            }
                        };
                        ret.insert(
                            CompactString::from(format!("{provider}_{eid}")),
                            CompactString::from(details),
                        );
                        Ok(())
                    })
                    .ok();
                ret
            }
        }
    }
}

/// config情報からthread_numberの情報を抽出する関数
fn check_thread_number(config: &Config) -> Option<usize> {
    match config.action.as_ref()? {
        Action::CsvTimeline(opt) => opt.output_options.detect_common_options.thread_number,
        Action::JsonTimeline(opt) => opt.output_options.detect_common_options.thread_number,
        Action::LogonSummary(opt) => opt.detect_common_options.thread_number,
        Action::EidMetrics(opt) => opt.detect_common_options.thread_number,
        Action::ExtractBase64(opt) => opt.detect_common_options.thread_number,
        Action::PivotKeywordsList(opt) => opt.detect_common_options.thread_number,
        Action::LogMetrics(opt) => opt.detect_common_options.thread_number,
        _ => None,
    }
}

// コマンド生成用のClapの定義
#[derive(Subcommand, Clone, Debug)]
pub enum Action {
    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe csv-timeline <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 292,
        disable_help_flag = true
    )]
    /// Create a DFIR timeline and save it in CSV format
    CsvTimeline(CsvOutputOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe json-timeline <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 360,
        disable_help_flag = true
    )]
    /// Create a DFIR timeline and save it in JSON/JSONL format
    JsonTimeline(JSONOutputOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe log-metrics <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 382,
        disable_help_flag = true
    )]
    /// Output evtx file metadata (filename, computer names, number of events, first and last timestamps, channels, providers)
    LogMetrics(LogMetricsOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe logon-summary <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 383,
        disable_help_flag = true
    )]
    /// Output a summary of successful and failed logons
    LogonSummary(LogonSummaryOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe eid-metrics <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 310,
        disable_help_flag = true
    )]
    /// Output event ID metrics (total number and percent of events, channel, ID, event name)
    EidMetrics(EidMetricsOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe expand-list <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 311,
        disable_help_flag = true
    )]
    /// Extract expand placeholders from the rules folder
    ExpandList(ExpandListOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe extract-base64 <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 311,
        disable_help_flag = true
    )]
    /// Extract and decode base64 strings from events
    ExtractBase64(ExtractBase64Option),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe pivot-keywords-list <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 420,
        disable_help_flag = true
    )]
    /// Create a list of pivot keywords
    PivotKeywordsList(PivotKeywordOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe search <INPUT> <--keywords \"<KEYWORDS>\" OR --regex \"<REGEX>\"> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 450,
        disable_help_flag = true
    )]
    /// Search all events by keyword(s) or regular expression
    Search(SearchOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  {usage}\n\n{all-args}",
        term_width = 400,
        display_order = 470,
        disable_help_flag = true
    )]
    /// Update to the latest rules in the hayabusa-rules github repository
    UpdateRules(UpdateOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  {usage}\n\n{all-args}",
        term_width = 400,
        display_order = 380,
        disable_help_flag = true
    )]
    /// Tune alert levels for the DFIR timeline (default: ./rules/config/level_tuning.txt)
    LevelTuning(LevelTuningOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  {usage}\n\n{all-args}",
        term_width = 400,
        display_order = 451,
        disable_help_flag = true
    )]
    /// Set default output profile for the DFIR timeline
    SetDefaultProfile(DefaultProfileOption),

    #[clap(display_order = 381)]
    /// Print the list of contributors
    ListContributors(CommonOptions),

    #[clap(display_order = 382)]
    /// List the output profiles for the DFIR timeline
    ListProfiles(CommonOptions),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe computer-metrics <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 290,
        disable_help_flag = true
    )]
    /// Output the total number of events according to computer names
    ComputerMetrics(ComputerMetricsOption),

    #[clap(
        author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
        help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe config-critical-systems <INPUT> [OPTIONS]\n\n{all-args}",
        term_width = 400,
        display_order = 291,
        disable_help_flag = true
    )]
    /// Find critical systems like domain controllers and file servers.
    ConfigCriticalSystems(ConfigCriticalSystemsOption),
}

impl Action {
    pub fn to_usize(action: Option<&Action>) -> usize {
        if let Some(a) = action {
            match a {
                Action::CsvTimeline(_) => 0,
                Action::JsonTimeline(_) => 1,
                Action::LogonSummary(_) => 2,
                Action::EidMetrics(_) => 3,
                Action::PivotKeywordsList(_) => 4,
                Action::UpdateRules(_) => 5,
                Action::LevelTuning(_) => 6,
                Action::SetDefaultProfile(_) => 7,
                Action::ListContributors(_) => 8,
                Action::ListProfiles(_) => 9,
                Action::Search(_) => 10,
                Action::ComputerMetrics(_) => 11,
                Action::LogMetrics(_) => 12,
                Action::ExtractBase64(_) => 13,
                Action::ExpandList(_) => 14,
                Action::ConfigCriticalSystems(_) => 15,
            }
        } else {
            100
        }
    }
    pub fn get_action_name(action: Option<&Action>) -> &str {
        if let Some(a) = action {
            match a {
                Action::CsvTimeline(_) => "csv-timeline",
                Action::JsonTimeline(_) => "json-timeline",
                Action::LogonSummary(_) => "logon-summary",
                Action::EidMetrics(_) => "eid-metrics",
                Action::PivotKeywordsList(_) => "pivot-keywords-list",
                Action::UpdateRules(_) => "update-rules",
                Action::LevelTuning(_) => "level-tuning",
                Action::SetDefaultProfile(_) => "set-default-profile",
                Action::ListContributors(_) => "list-contributors",
                Action::ListProfiles(_) => "list-profiles",
                Action::Search(_) => "search",
                Action::ComputerMetrics(_) => "computer-metrics",
                Action::LogMetrics(_) => "log-metrics",
                Action::ExtractBase64(_) => "extract-base64",
                Action::ExpandList(_) => "expand-list",
                Action::ConfigCriticalSystems(_) => "config-critical-systems",
            }
        } else {
            ""
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct DetectCommonOption {
    /// Scan JSON formatted logs instead of .evtx (.json or .jsonl)
    #[arg(help_heading = Some("General Options"), short = 'J', long = "JSON-input", conflicts_with = "live_analysis", display_order = 360)]
    pub json_input: bool,

    /// Specify additional evtx file extensions (ex: evtx_data)
    #[arg(help_heading = Some("General Options"), long = "target-file-ext", value_name = "FILE-EXT...", use_value_delimiter = true, value_delimiter = ',', display_order = 460)]
    pub evtx_file_ext: Option<Vec<String>>,

    /// Number of threads (default: optimal number for performance)
    #[arg(
        help_heading = Some("General Options"),
        short = 't',
        long = "threads",
        value_name = "NUMBER",
        display_order = 460
    )]
    pub thread_number: Option<usize>,

    /// Quiet errors mode: do not save error logs
    #[arg(help_heading = Some("General Options"), short = 'Q', long = "quiet-errors", display_order = 430)]
    pub quiet_errors: bool,

    /// Specify custom rule config directory (default: ./rules/config)
    #[arg(
        help_heading = Some("General Options"),
        short = 'c',
        long = "rules-config",
        default_value = "./rules/config",
        hide_default_value = true,
        value_name = "DIR",
        display_order = 442
    )]
    pub config: PathBuf,

    /// Output verbose information
    #[arg(help_heading = Some("Display Settings"), short = 'v', long, display_order = 480)]
    pub verbose: bool,

    /// Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
    #[arg(help_heading = Some("Filtering"), long = "include-computer", value_name = "COMPUTER...", conflicts_with = "exclude-computer", use_value_delimiter = true, value_delimiter = ',', display_order = 352)]
    pub include_computer: Option<Vec<String>>,

    /// Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
    #[arg(help_heading = Some("Filtering"), long = "exclude-computer", value_name = "COMPUTER...", conflicts_with = "include_computer",use_value_delimiter = true, value_delimiter = ',', display_order = 314)]
    pub exclude_computer: Option<Vec<String>>,
}

#[derive(Args, Clone, Debug)]
pub struct DefaultProfileOption {
    #[clap(flatten)]
    pub common_options: CommonOptions,
    /// Specify output profile
    #[arg(help_heading = Some("General Options"), short = 'p', long = "profile", display_order = 420)]
    pub profile: Option<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TimeFormatOptions {
    /// Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
    #[arg(help_heading = Some("Time Format"), long = "European-time", display_order = 50)]
    pub european_time: bool,

    /// Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
    #[arg(help_heading = Some("Time Format"), short = 'O', long = "ISO-8601", display_order = 90)]
    pub iso_8601: bool,

    /// Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
    #[arg(help_heading = Some("Time Format"), long = "RFC-2822", display_order = 180)]
    pub rfc_2822: bool,

    /// Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
    #[arg(help_heading = Some("Time Format"), long = "RFC-3339", display_order = 180)]
    pub rfc_3339: bool,

    /// Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
    #[arg(help_heading = Some("Time Format"), long = "US-military-time", display_order = 210)]
    pub us_military_time: bool,

    /// Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
    #[arg(help_heading = Some("Time Format"), long = "US-time", display_order = 210)]
    pub us_time: bool,

    /// Output time in UTC format (default: local time)
    #[arg(help_heading = Some("Time Format"), short = 'U', long = "UTC", display_order = 210)]
    pub utc: bool,
}

#[derive(Args, Clone, Debug)]
#[clap(group(ArgGroup::new("search_input_filtering").args(["keywords", "regex"]).required(true)))]
pub struct SearchOption {
    #[clap(flatten)]
    pub common_options: CommonOptions,

    #[clap(flatten)]
    pub input_args: InputOption,

    /// Search by keyword(s)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'k',
        long = "keyword",
        value_name = "KEYWORD...",
        display_order = 370,
        conflicts_with = "regex",
    )]
    pub keywords: Option<Vec<String>>,

    /// Search by regular expression
    #[arg(
        help_heading = Some("Filtering"),
        short = 'r',
        long,
        value_name = "REGEX",
        display_order = 440,
        conflicts_with = "keywords",
    )]
    pub regex: Option<String>,

    /// Case-insensitive keyword search
    #[arg(
        help_heading = Some("Filtering"),
        short,
        long = "ignore-case",
        display_order = 350,
        conflicts_with = "regex",
    )]
    pub ignore_case: bool,

    /// Search keywords with AND logic (default: OR)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'a',
        long = "and-logic",
        value_name = "KEYWORD...",
        display_order = 270,
        conflicts_with = "regex",
        requires="keywords"
    )]
    pub and_logic: bool,

    /// Filter by specific field(s)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'F',
        long = "filter",
        value_name = "FILTER...",
        display_order = 320
    )]
    pub filter: Vec<String>,

    /// End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE", display_order = 460)]
    pub end_timeline: Option<String>,

    /// Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE", display_order = 460)]
    pub start_timeline: Option<String>,

    /// Save the search results in CSV format (ex: search.csv)
    #[arg(
        help_heading = Some("Output"),
        short = 'o',
        long, value_name = "FILE",
        display_order = 410
    )]
    pub output: Option<PathBuf>,

    /// Specify additional evtx file extensions (ex: evtx_data)
    #[arg(help_heading = Some("General Options"), long = "target-file-ext", value_name = "FILE-EXT...", use_value_delimiter = true, value_delimiter = ',', display_order = 460)]
    pub evtx_file_ext: Option<Vec<String>>,

    /// Number of threads (default: optimal number for performance)
    #[arg(
            help_heading = Some("General Options"),
            short = 't',
            long = "threads",
            value_name = "NUMBER",
            display_order = 460
        )]
    pub thread_number: Option<usize>,

    /// Quiet errors mode: do not save error logs
    #[arg(help_heading = Some("General Options"), short = 'Q', long = "quiet-errors", display_order = 430)]
    pub quiet_errors: bool,

    /// Specify custom rule config directory (default: ./rules/config)
    #[arg(
            help_heading = Some("General Options"),
            short = 'c',
            long = "rules-config",
            default_value = "./rules/config",
            hide_default_value = true,
            value_name = "DIR",
            display_order = 442
        )]
    pub config: PathBuf,

    /// Output verbose information
    #[arg(help_heading = Some("Display Settings"), short = 'v', long, display_order = 480)]
    pub verbose: bool,

    /// Output event field information in multiple rows for CSV output
    #[arg(help_heading = Some("Output"), short = 'M', long="multiline", display_order = 390)]
    pub multiline: bool,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,

    /// Save the search results in JSON format (ex: -J -o results.json)
    #[arg(help_heading = Some("Output"), short = 'J', long = "JSON-output", conflicts_with_all = ["jsonl_output", "multiline"], requires = "output", display_order = 100)]
    pub json_output: bool,

    /// Save the search results in JSONL format (ex: -L -o results.jsonl)
    #[arg(help_heading = Some("Output"), short = 'L', long = "JSONL-output", conflicts_with_all = ["jsonl_output", "multiline"], requires = "output", display_order = 100)]
    pub jsonl_output: bool,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Disable abbreviations
    #[arg(help_heading = Some("Output"), short='b', long = "disable-abbreviations", display_order = 60)]
    pub disable_abbreviations: bool,

    /// Sort results before saving the file (warning: this uses much more memory!)
    #[arg(help_heading = Some("General Options"), short='s', long = "sort", display_order = 600)]
    pub sort_events: bool,
}

#[derive(Args, Clone, Debug)]
pub struct UpdateOption {
    #[clap(flatten)]
    pub common_options: CommonOptions,

    /// Specify a custom rule directory or file (default: ./rules)
    #[arg(
        help_heading = Some("General Options"),
        short = 'r',
        long,
        default_value = "./rules",
        hide_default_value = true,
        value_name = "DIR/FILE",
        requires = "no_wizard",
        display_order = 441
    )]
    pub rules: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub struct LevelTuningOption {
    #[clap(flatten)]
    pub common_options: CommonOptions,

    /// Tune alert levels (default: ./rules/config/level_tuning.txt)
    #[arg(
            help_heading = Some("General Options"),
            short = 'f',
            long = "file",
            default_value = "./rules/config/level_tuning.txt",
            hide_default_value = true,
            value_name = "FILE",
            display_order = 320
        )]
    pub level_tuning: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub struct EidMetricsOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save the Metrics in CSV format (ex: metrics.csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    /// Remove duplicate detections (default: disabled)
    #[arg(help_heading = Some("Output"), short = 'X', long = "remove-duplicate-detections", requires = "sort_events", display_order = 409)]
    pub remove_duplicate_detections: bool,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,
}

#[derive(Args, Clone, Debug)]
#[clap(group(ArgGroup::new("input_filtering").args(["directory", "filepath", "live_analysis"]).required(true)))]
#[clap(group(ArgGroup::new("level_rule_filtering").args(["min_level", "exact_level"]).multiple(false)))]
pub struct PivotKeywordOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save pivot words to separate files (ex: PivotKeywords)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILENAME-PREFIX", display_order = 410)]
    pub output: Option<PathBuf>,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    /// Enable rules with a status of deprecated
    #[arg(help_heading = Some("Filtering"), short = 'D', long = "enable-deprecated-rules", requires = "no_wizard", display_order = 310)]
    pub enable_deprecated_rules: bool,

    /// Enable rules with a status of unsupported
    #[arg(help_heading = Some("Filtering"), short = 'u', long = "enable-unsupported-rules", requires = "no_wizard", display_order = 312)]
    pub enable_unsupported_rules: bool,

    /// Do not load rules according to status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "exclude-status", value_name = "STATUS...", requires = "no_wizard", conflicts_with = "include_status",use_value_delimiter = true, value_delimiter = ',', display_order = 316)]
    pub exclude_status: Option<Vec<String>>,

    /// Only load rules with specific status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "include-status", value_name = "STATUS...", requires = "no_wizard", conflicts_with = "exclude_status", use_value_delimiter = true, value_delimiter = ',', display_order = 353)]
    pub include_status: Option<Vec<String>>,

    /// Only load rules with specific tags (ex: attack.execution,attack.discovery)
    #[arg(help_heading = Some("Filtering"), long = "include-tag", value_name = "TAG...", requires = "no_wizard", conflicts_with = "exclude_tag", use_value_delimiter = true, value_delimiter = ',', display_order = 354)]
    pub include_tag: Option<Vec<String>>,

    /// Do not load rules with specific tags (ex: sysmon)
    #[arg(help_heading = Some("Filtering"), long = "exclude-tag", value_name = "TAG...", requires = "no_wizard", conflicts_with = "include_tag", use_value_delimiter = true, value_delimiter = ',', display_order = 316)]
    pub exclude_tag: Option<Vec<String>>,

    /// Minimum level for rules to load (default: informational)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'm',
        long = "min-level",
        default_value = "informational",
        hide_default_value = true,
        value_name = "LEVEL",
        requires = "no_wizard",
        conflicts_with = "exact_level",
        display_order = 390
    )]
    pub min_level: String,

    /// Only load rules with a specific level (informational, low, medium, high, critical)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'e',
        long = "exact-level",
        value_name = "LEVEL",
        requires = "no_wizard",
        conflicts_with = "min_level",
        display_order = 313
    )]
    pub exact_level: Option<String>,

    /// Enable rules set to noisy (./rules/config/noisy_rules.txt)
    #[arg(help_heading = Some("Filtering"), short = 'n', long = "enable-noisy-rules", requires = "no_wizard", display_order = 311)]
    pub enable_noisy_rules: bool,

    /// End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE", display_order = 460)]
    pub end_timeline: Option<String>,

    /// Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE", display_order = 460)]
    pub start_timeline: Option<String>,

    /// Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
    #[arg(help_heading = Some("Filtering"), short = 'E', long = "EID-filter", display_order = 50)]
    pub eid_filter: bool,

    /// Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
    #[arg(help_heading = Some("Filtering"), long = "include-eid", value_name = "EID...", conflicts_with_all = ["eid_filter", "exclude_eid"], use_value_delimiter = true, value_delimiter = ',', display_order = 352)]
    pub include_eid: Option<Vec<String>>,

    /// Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
    #[arg(help_heading = Some("Filtering"), long = "exclude-eid", value_name = "EID...", conflicts_with_all = ["eid_filter", "include_eid"], use_value_delimiter = true, value_delimiter = ',', display_order = 315)]
    pub exclude_eid: Option<Vec<String>>,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,

    /// Do not ask questions. Scan for all events and alerts.
    #[arg(help_heading = Some("General Options"), short = 'w', long = "no-wizard", display_order = 400)]
    pub no_wizard: bool,
}

#[derive(Args, Clone, Debug)]
pub struct LogonSummaryOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save the logon summary to two CSV files (ex: -o logon-summary)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILENAME-PREFIX", display_order = 410)]
    pub output: Option<PathBuf>,

    /// Remove duplicate detections (default: disabled)
    #[arg(help_heading = Some("Output"), short = 'X', long = "remove-duplicate-detections", requires = "sort_events", display_order = 409)]
    pub remove_duplicate_detections: bool,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,

    /// End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE", display_order = 460)]
    pub end_timeline: Option<String>,

    /// Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE", display_order = 460)]
    pub start_timeline: Option<String>,
}

/// Options can be set when outputting
#[derive(Args, Clone, Debug)]
#[clap(group(ArgGroup::new("level_rule_filtering").args(["min_level", "exact_level"]).multiple(false)))]
pub struct OutputOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Specify output profile
    #[arg(help_heading = Some("Output"), short = 'p', long = "profile", display_order = 420)]
    pub profile: Option<String>,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    /// Enable rules with a status of deprecated
    #[arg(help_heading = Some("Filtering"), short = 'D', long = "enable-deprecated-rules", requires = "no_wizard", display_order = 310)]
    pub enable_deprecated_rules: bool,

    /// Enable rules with a status of unsupported
    #[arg(help_heading = Some("Filtering"), short = 'u', long = "enable-unsupported-rules", requires = "no_wizard", display_order = 312)]
    pub enable_unsupported_rules: bool,

    /// Do not load rules according to status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "exclude-status", value_name = "STATUS...", requires = "no_wizard", conflicts_with = "include_status", use_value_delimiter = true, value_delimiter = ',', display_order = 316)]
    pub exclude_status: Option<Vec<String>>,

    /// Only load rules with specific status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "include-status", value_name = "STATUS...", requires = "no_wizard", conflicts_with = "exclude_status", use_value_delimiter = true, value_delimiter = ',', display_order = 353)]
    pub include_status: Option<Vec<String>>,

    /// Only load rules with specific tags (ex: attack.execution,attack.discovery)
    #[arg(help_heading = Some("Filtering"), long = "include-tag", value_name = "TAG...", requires = "no_wizard", conflicts_with = "exclude_tag", use_value_delimiter = true, value_delimiter = ',', display_order = 354)]
    pub include_tag: Option<Vec<String>>,

    /// Only load rules with specified logsource categories (ex: process_creation,pipe_created)
    #[arg(help_heading = Some("Filtering"), long = "include-category", value_name = "CATEGORY...", conflicts_with = "exclude-category", requires = "no_wizard", use_value_delimiter = true, value_delimiter = ',', display_order = 351)]
    pub include_category: Option<Vec<String>>,

    /// Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
    #[arg(help_heading = Some("Filtering"), long = "exclude-category", value_name = "CATEGORY...", conflicts_with = "include_category", requires = "no_wizard", use_value_delimiter = true, value_delimiter = ',', display_order = 314)]
    pub exclude_category: Option<Vec<String>>,

    /// Minimum level for rules to load (default: informational)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'm',
        long = "min-level",
        default_value = "informational",
        requires = "no_wizard",
        hide_default_value = true,
        value_name = "LEVEL",
        display_order = 390,
    )]
    pub min_level: String,

    /// Only load rules with a specific level (informational, low, medium, high, critical)
    #[arg(
        help_heading = Some("Filtering"),
        short = 'e',
        long = "exact-level",
        value_name = "LEVEL",
        requires = "no_wizard",
        conflicts_with = "min-level",
        display_order = 313
    )]
    pub exact_level: Option<String>,

    /// Enable rules set to noisy (./rules/config/noisy_rules.txt)
    #[arg(help_heading = Some("Filtering"), short = 'n', long = "enable-noisy-rules", requires = "no_wizard", display_order = 311)]
    pub enable_noisy_rules: bool,

    /// End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE", display_order = 460)]
    pub end_timeline: Option<String>,

    /// Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE", display_order = 460)]
    pub start_timeline: Option<String>,

    /// Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
    #[arg(help_heading = Some("Filtering"), short = 'E', long = "EID-filter", conflicts_with_all=["include_eid","exclude_eid"], display_order = 50)]
    pub eid_filter: bool,

    /// Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
    #[arg(help_heading = Some("Filtering"), short = 'P', long = "proven-rules", display_order = 420)]
    pub proven_rules: bool,

    /// Do not load rules with specific tags (ex: sysmon)
    #[arg(help_heading = Some("Filtering"), long = "exclude-tag", value_name = "TAG...", requires = "no_wizard", conflicts_with = "include_tag", use_value_delimiter = true, value_delimiter = ',', display_order = 316)]
    pub exclude_tag: Option<Vec<String>>,

    /// Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
    #[arg(help_heading = Some("Filtering"), long = "include-eid", value_name = "EID...", conflicts_with_all = ["eid_filter", "exclude_eid"], use_value_delimiter = true, value_delimiter = ',', display_order = 352)]
    pub include_eid: Option<Vec<String>>,

    /// Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
    #[arg(help_heading = Some("Filtering"), long = "exclude-eid", value_name = "EID...", conflicts_with_all = ["eid_filter", "include_eid"], use_value_delimiter = true, value_delimiter = ',', display_order = 315)]
    pub exclude_eid: Option<Vec<String>>,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Output event frequency timeline (terminal needs to support unicode)
    #[arg(help_heading = Some("Display Settings"), short = 'T', long = "visualize-timeline", display_order = 490)]
    pub visualize_timeline: bool,

    /// Specify a custom rule directory or file (default: ./rules)
    #[arg(
        help_heading = Some("General Options"),
        short = 'r',
        long,
        default_value = "./rules",
        hide_default_value = true,
        value_name = "DIR/FILE",
        requires = "no_wizard",
        display_order = 441
    )]
    pub rules: PathBuf,

    /// Save Results Summary details to an HTML report (ex: results.html)
    #[arg(help_heading = Some("Output"), short = 'H', long="HTML-report", conflicts_with = "no_summary", value_name = "FILE", display_order = 80, requires = "output")]
    pub html_report: Option<PathBuf>,

    /// Do not display Results Summary for faster speed
    #[arg(help_heading = Some("Display Settings"), short = 'N', long = "no-summary", conflicts_with = "html_report", display_order = 401)]
    pub no_summary: bool,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,

    /// Disable field data mapping
    #[arg(help_heading = Some("Output"), short = 'F', long = "no-field-data-mapping", display_order = 400)]
    pub no_field: bool,

    /// Disable field extraction of PowerShell classic logs
    #[arg(help_heading = Some("Output"), long = "no-pwsh-field-extraction", display_order = 410)]
    pub no_pwsh_field_extraction: bool,

    /// Duplicate field data will be replaced with "DUP"
    #[arg(
            help_heading = Some("Output"),
            short = 'R',
            long = "remove-duplicate-data",
            requires = "sort_events",
            display_order = 440
        )]
    pub remove_duplicate_data: bool,

    /// Remove duplicate detections (default: disabled)
    #[arg(help_heading = Some("Output"), short = 'X', long = "remove-duplicate-detections", requires = "sort_events", display_order = 441)]
    pub remove_duplicate_detections: bool,

    /// Do not ask questions. Scan for all events and alerts.
    #[arg(help_heading = Some("General Options"), short = 'w', long = "no-wizard", display_order = 400)]
    pub no_wizard: bool,

    /// Sort results before saving the file (warning: this uses much more memory!)
    #[arg(help_heading = Some("General Options"), short='s', long = "sort", display_order = 451)]
    pub sort_events: bool,

    /// Enable all rules regardless of loaded evtx files (disable channel filter for rules)
    #[arg(help_heading = Some("Filtering"), short='A', long = "enable-all-rules", display_order = 300)]
    pub enable_all_rules: bool,

    /// Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
    #[arg(help_heading = Some("Filtering"), short='a', long = "scan-all-evtx-files", display_order = 450)]
    pub scan_all_evtx_files: bool,
}

#[derive(Copy, Args, Clone, Debug)]
pub struct CommonOptions {
    /// Disable color output
    #[arg(help_heading = Some("Display Settings"), short = 'K', long = "no-color", global = true, display_order = 400)]
    pub no_color: bool,

    /// Quiet mode: do not display the launch banner
    #[arg(help_heading = Some("Display Settings"), short, long, global = true, display_order = 430)]
    pub quiet: bool,

    /// Show the help menu
    #[clap(help_heading = Some("General Options"), short = 'h', long = "help", action = ArgAction::Help, display_order = 340, required = false)]
    pub help: Option<bool>,
}

#[derive(Args, Clone, Debug)]
#[clap(group(ArgGroup::new("input_filtering").args(["directory", "filepath", "live_analysis"]).required(true)))]
pub struct InputOption {
    /// Directory of multiple .evtx files
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", conflicts_with_all = ["filepath", "live_analysis"], display_order = 300)]
    pub directory: Option<Vec<PathBuf>>,

    /// File path to one .evtx file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", conflicts_with_all = ["directory", "live_analysis"], display_order = 320)]
    pub filepath: Option<PathBuf>,

    /// Analyze the local C:\Windows\System32\winevt\Logs folder
    #[arg(help_heading = Some("Input"), short = 'l', long = "live-analysis", conflicts_with_all = ["filepath", "directory", "json_input"], display_order = 380)]
    pub live_analysis: bool,

    /// Carve evtx records from slack space (default: disabled)
    #[arg(help_heading = Some("General Options"), short = 'x', long = "recover-records", conflicts_with = "json_input", display_order = 440)]
    pub recover_records: bool,

    /// Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
    #[arg(help_heading = Some("Filtering"), long = "time-offset", value_name = "OFFSET", conflicts_with = "start_timeline", display_order = 460)]
    pub time_offset: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct CsvOutputOption {
    #[clap(flatten)]
    pub output_options: OutputOption,

    /// Output event field information in multiple rows
    #[arg(help_heading = Some("Output"), short = 'M', long="multiline", display_order = 390)]
    pub multiline: bool,

    // display_order value is defined acronym of long option (A=10,B=20,...,Z=260,a=270, b=280...,z=520)
    /// Add GeoIP (ASN, city, country) info to IP addresses
    #[arg(
        help_heading = Some("Output"),
        short = 'G',
        long = "GeoIP",
        value_name = "MAXMIND-DB-DIR",
        display_order = 70
    )]
    pub geo_ip: Option<PathBuf>,

    /// Save the timeline in CSV format (ex: results.csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    /// Disable abbreviations
    #[arg(help_heading = Some("Output"), short='b', long = "disable-abbreviations", display_order = 60)]
    pub disable_abbreviations: bool,
}

#[derive(Args, Clone, Debug)]
pub struct JSONOutputOption {
    #[clap(flatten)]
    pub output_options: OutputOption,

    /// Save the timeline in JSON format (ex: results.json)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    /// Save the timeline in JSONL format (ex: -L -o results.jsonl)
    #[arg(help_heading = Some("Output"), short = 'L', long = "JSONL-output", requires = "output", display_order = 100)]
    pub jsonl_timeline: bool,

    /// Add GeoIP (ASN, city, country) info to IP addresses
    #[arg(
        help_heading = Some("Output"),
        short = 'G',
        long = "GeoIP",
        value_name = "MAXMIND-DB-DIR",
        display_order = 70
    )]
    pub geo_ip: Option<PathBuf>,

    /// Disable abbreviations
    #[arg(help_heading = Some("Output"), short='b', long = "disable-abbreviations", display_order = 60)]
    pub disable_abbreviations: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ComputerMetricsOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save the results in CSV format (ex: computer-metrics.csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    /// Scan JSON formatted logs instead of .evtx (.json or .jsonl)
    #[arg(help_heading = Some("General Options"), short = 'J', long = "JSON-input", conflicts_with = "live_analysis", display_order = 390)]
    pub json_input: bool,

    /// Specify additional evtx file extensions (ex: evtx_data)
    #[arg(help_heading = Some("General Options"), long = "target-file-ext", value_name = "FILE-EXT...", use_value_delimiter = true, value_delimiter = ',', display_order = 450)]
    pub evtx_file_ext: Option<Vec<String>>,

    /// Number of threads (default: optimal number for performance)
    #[arg(
        help_heading = Some("General Options"),
        short = 't',
        long = "threads",
        value_name = "NUMBER",
        display_order = 460
    )]
    pub thread_number: Option<usize>,

    /// Quiet errors mode: do not save error logs
    #[arg(help_heading = Some("General Options"), short = 'Q', long = "quiet-errors", display_order = 430)]
    pub quiet_errors: bool,

    /// Specify custom rule config directory (default: ./rules/config)
    #[arg(
        help_heading = Some("General Options"),
        short = 'c',
        long = "rules-config",
        default_value = "./rules/config",
        hide_default_value = true,
        value_name = "DIR",
        display_order = 442
    )]
    pub config: PathBuf,

    /// Output verbose information
    #[arg(help_heading = Some("Display Settings"), short = 'v', long, display_order = 480)]
    pub verbose: bool,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,
}

#[derive(Args, Clone, Debug)]
pub struct LogMetricsOption {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save the Metrics in CSV format (ex: metrics.csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Output event field information in multiple rows for CSV output
    #[arg(help_heading = Some("Output"), short = 'M', long="multiline", display_order = 390)]
    pub multiline: bool,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,

    /// Disable abbreviations
    #[arg(help_heading = Some("Output"), short='b', long = "disable-abbreviations", display_order = 60)]
    pub disable_abbreviations: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ExtractBase64Option {
    #[clap(flatten)]
    pub input_args: InputOption,

    /// Save results to a CSV file
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE", display_order = 410)]
    pub output: Option<PathBuf>,

    #[clap(flatten)]
    pub common_options: CommonOptions,

    #[clap(flatten)]
    pub detect_common_options: DetectCommonOption,

    #[clap(flatten)]
    pub time_format_options: TimeFormatOptions,

    /// Overwrite files when saving
    #[arg(help_heading = Some("General Options"), short='C', long = "clobber", display_order = 290, requires = "output")]
    pub clobber: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ExpandListOption {
    /// Specify rule directory (default: ./rules)
    #[arg(
        help_heading = Some("General Options"),
        short = 'r',
        long,
        default_value = "./rules",
        hide_default_value = true,
        value_name = "DIR/FILE",
        requires = "no_wizard",
        display_order = 441
    )]
    pub rules: PathBuf,

    #[clap(flatten)]
    pub common_options: CommonOptions,
}

#[derive(Args, Clone, Debug)]
#[clap(group(ArgGroup::new("input_filtering").args(["directory", "filepath"]).required(true)))]
pub struct ConfigCriticalSystemsOption {
    /// Directory of multiple .evtx files
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIR", conflicts_with_all = ["filepath"], display_order = 300)]
    pub directory: Option<Vec<PathBuf>>,

    /// File path to one .evtx file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE", conflicts_with_all = ["directory"], display_order = 320)]
    pub filepath: Option<PathBuf>,

    #[clap(flatten)]
    pub common_options: CommonOptions,
}

#[derive(Parser, Clone, Debug)]
#[clap(
    author = "Yamato Security (https://github.com/Yamato-Security/hayabusa - @SecurityYamato)",
    help_template = "\nHayabusa v3.1.0 - Dev Build\n{author-with-newline}\n{usage-heading}\n  hayabusa.exe <COMMAND> [OPTIONS]\n  hayabusa.exe help <COMMAND> or hayabusa.exe <COMMAND> -h\n\n{all-args}{options}",
    term_width = 400,
    disable_help_flag = true
)]
pub struct Config {
    #[command(subcommand)]
    pub action: Option<Action>,

    /// Print debug information (memory usage, etc...)
    #[clap(long = "debug", global = true, hide = true)]
    pub debug: bool,
}

impl ConfigReader {
    pub fn new() -> Self {
        let parse = Config::parse();
        let help_term_width = if let Some((Width(w), _)) = terminal_size() {
            w as usize
        } else {
            400
        };
        let build_cmd = Config::command()
            .disable_version_flag(true)
            .color(ColorChoice::Auto)
            .term_width(help_term_width);
        ConfigReader {
            app: build_cmd,
            config: Some(parse),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetIds {
    ids: HashSet<String>,
}

impl Default for TargetIds {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetIds {
    pub fn new() -> TargetIds {
        TargetIds {
            ids: HashSet::new(),
        }
    }

    pub fn is_target(&self, id: &str, flag_in_case_empty: bool) -> bool {
        // 中身が空の場合はEventIdの場合は全EventIdを対象とする。RuleIdの場合は全部のRuleIdはフィルタリングの対象にならないものとする
        if self.ids.is_empty() {
            return flag_in_case_empty;
        }
        self.ids.contains(id)
    }
}

fn load_target_ids(path: &str) -> TargetIds {
    let mut ret = TargetIds::default();
    let lines = match utils::read_txt(path) {
        Ok(lines) => lines,
        Err(e) => {
            // ファイルが存在しなければエラーとする
            AlertMessage::alert(&e).ok();
            return ret;
        }
    };

    for line in lines.iter() {
        if line.is_empty() {
            continue;
        }
        ret.ids.insert(line.to_string());
    }

    ret
}

#[derive(Debug, Clone)]
pub struct TargetEventTime {
    parse_success_flag: bool,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
}

impl TargetEventTime {
    pub fn new(stored_static: &StoredStatic) -> Self {
        let get_time =
            |input_time: Option<&String>, error_contents: &str, parse_success_flag: &mut bool| {
                if let Some(time) = input_time {
                    match DateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S %z") // 2014-11-28 21:00:09 +09:00
                    .or_else(|_| DateTime::parse_from_str(time, "%Y/%m/%d %H:%M:%S %z")) // 2014/11/28 21:00:09 +09:00
                {
                    Ok(dt) => Some(dt.with_timezone(&Utc)),
                    Err(_) => {
                        AlertMessage::alert(error_contents)
                        .ok();
                        *parse_success_flag = false;
                        None
                    }
                }
                } else {
                    None
                }
            };

        let get_time_offset = |time_offset: &Option<String>, parse_success_flag: &mut bool| {
            if let Some(timeline_offline) = time_offset {
                let timekey = ['y', 'M', 'd', 'h', 'm', 's'];
                let mut time_num = [0, 0, 0, 0, 0, 0];
                for (idx, key) in timekey.iter().enumerate() {
                    let mut timekey_splitter = timeline_offline.split(*key);
                    let mix_check = timekey_splitter.next();
                    let mixed_checker: Vec<&str> =
                        mix_check.unwrap_or_default().split(timekey).collect();
                    let target_num = if mixed_checker.is_empty() {
                        mix_check.unwrap()
                    } else {
                        mixed_checker[mixed_checker.len() - 1]
                    };
                    if target_num.is_empty() {
                        continue;
                    }
                    if let Ok(num) = target_num.parse::<u32>() {
                        time_num[idx] = num;
                    } else {
                        AlertMessage::alert(
                            "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        )
                        .ok();
                        *parse_success_flag = false;
                        return None;
                    }
                }
                if time_num.iter().all(|&x| x == 0) {
                    AlertMessage::alert(
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                    )
                    .ok();
                    *parse_success_flag = false;
                    return None;
                }
                let target_start_time = Local::now()
                    .checked_sub_months(Months::new(time_num[0] * 12))
                    .and_then(|dt| dt.checked_sub_months(Months::new(time_num[1])))
                    .and_then(|dt| dt.checked_sub_days(Days::new(time_num[2].into())))
                    .and_then(|dt| {
                        dt.checked_sub_signed(
                            Duration::try_hours(time_num[3].into()).unwrap_or_default(),
                        )
                    })
                    .and_then(|dt| {
                        dt.checked_sub_signed(
                            Duration::try_minutes(time_num[4].into()).unwrap_or_default(),
                        )
                    })
                    .and_then(|dt| {
                        dt.checked_sub_signed(
                            Duration::try_seconds(time_num[5].into()).unwrap_or_default(),
                        )
                    });
                if let Some(start_time) = target_start_time {
                    Some(start_time.format("%Y-%m-%d %H:%M:%S %z").to_string())
                } else {
                    AlertMessage::alert("timeline-offset field: the timestamp value is too large.")
                        .ok();
                    *parse_success_flag = false;
                    None
                }
            } else {
                None
            }
        };

        let mut parse_success_flag = true;
        let time_offset = get_time_offset(&stored_static.time_offset, &mut parse_success_flag);
        match &stored_static.config.action.as_ref().unwrap() {
            Action::CsvTimeline(option) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    get_time(
                        option.output_options.start_timeline.as_ref(),
                        "start-timeline field: the timestamp format is not correct.",
                        &mut parse_success_flag,
                    )
                };
                let end_time = get_time(
                    option.output_options.end_timeline.as_ref(),
                    "end-timeline field: the timestamp format is not correct.",
                    &mut parse_success_flag,
                );
                Self::set(parse_success_flag, start_time, end_time)
            }
            Action::JsonTimeline(option) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    get_time(
                        option.output_options.start_timeline.as_ref(),
                        "start-timeline field: the timestamp format is not correct.",
                        &mut parse_success_flag,
                    )
                };
                let end_time = get_time(
                    option.output_options.end_timeline.as_ref(),
                    "end-timeline field: the timestamp format is not correct.",
                    &mut parse_success_flag,
                );
                Self::set(parse_success_flag, start_time, end_time)
            }
            Action::PivotKeywordsList(option) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    get_time(
                        option.start_timeline.as_ref(),
                        "start-timeline field: the timestamp format is not correct.",
                        &mut parse_success_flag,
                    )
                };
                let end_time = get_time(
                    option.end_timeline.as_ref(),
                    "end-timeline field: the timestamp format is not correct.",
                    &mut parse_success_flag,
                );
                Self::set(parse_success_flag, start_time, end_time)
            }
            Action::LogonSummary(option) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    get_time(
                        option.start_timeline.as_ref(),
                        "start-timeline field: the timestamp format is not correct.",
                        &mut parse_success_flag,
                    )
                };
                let end_time = get_time(
                    option.end_timeline.as_ref(),
                    "end-timeline field: the timestamp format is not correct.",
                    &mut parse_success_flag,
                );
                Self::set(parse_success_flag, start_time, end_time)
            }
            Action::Search(option) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    get_time(
                        option.start_timeline.as_ref(),
                        "start-timeline field: the timestamp format is not correct.",
                        &mut parse_success_flag,
                    )
                };
                let end_time = get_time(
                    option.end_timeline.as_ref(),
                    "end-timeline field: the timestamp format is not correct.",
                    &mut parse_success_flag,
                );
                Self::set(parse_success_flag, start_time, end_time)
            }
            Action::LogMetrics(_)
            | Action::EidMetrics(_)
            | Action::ComputerMetrics(_)
            | Action::ExtractBase64(_) => {
                let start_time = if time_offset.is_some() {
                    get_time(
                        time_offset.as_ref(),
                        "Invalid timeline offset. Please use one of the following formats: 1y, 3M, 30d, 24h, 30m",
                        &mut parse_success_flag,
                    )
                } else {
                    None
                };
                Self::set(parse_success_flag, start_time, None)
            }
            _ => Self::set(parse_success_flag, None, None),
        }
    }

    pub fn set(
        input_parse_success_flag: bool,
        input_start_time: Option<DateTime<Utc>>,
        input_end_time: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            parse_success_flag: input_parse_success_flag,
            start_time: input_start_time,
            end_time: input_end_time,
        }
    }

    pub fn is_parse_success(&self) -> bool {
        self.parse_success_flag
    }

    pub fn is_target(&self, eventtime: &Option<DateTime<Utc>>) -> bool {
        if eventtime.is_none() {
            return true;
        }
        if let Some(starttime) = self.start_time {
            if eventtime.unwrap() < starttime {
                return false;
            }
        }
        if let Some(endtime) = self.end_time {
            if eventtime.unwrap() > endtime {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct EventKeyAliasConfig {
    key_to_eventkey: HashMap<String, String>,
    key_to_split_eventkey: HashMap<String, Vec<usize>>,
}

impl EventKeyAliasConfig {
    pub fn new() -> EventKeyAliasConfig {
        EventKeyAliasConfig {
            key_to_eventkey: HashMap::new(),
            key_to_split_eventkey: HashMap::new(),
        }
    }

    pub fn get_event_key(&self, alias: &str) -> Option<&String> {
        self.key_to_eventkey.get(alias)
    }

    pub fn get_event_key_split(&self, alias: &str) -> Option<&Vec<usize>> {
        self.key_to_split_eventkey.get(alias)
    }
}

impl Default for EventKeyAliasConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn load_eventkey_alias(path: &str) -> EventKeyAliasConfig {
    let mut config = EventKeyAliasConfig::new();

    // eventkey_aliasが読み込めなかったらエラーで終了とする。
    let read_result = utils::read_csv(path);
    if let Err(e) = read_result {
        AlertMessage::alert(&e).ok();
        return config;
    }

    read_result.unwrap().iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }

        let empty = &"".to_string();
        let alias = line.first().unwrap_or(empty);
        let event_key = line.get(1).unwrap_or(empty);
        if alias.is_empty() || event_key.is_empty() {
            return;
        }

        config
            .key_to_eventkey
            .insert(alias.to_owned(), event_key.to_owned());
        config.key_to_split_eventkey.insert(
            alias.to_owned(),
            event_key.split('.').map(|s| s.len()).collect(),
        );
    });
    config.key_to_eventkey.shrink_to_fit();
    config
}

///設定ファイルを読み込み、keyとfieldsのマップをPIVOT_KEYWORD大域変数にロードする。
pub fn load_pivot_keywords(path: &str) {
    let read_result = match utils::read_txt(path) {
        Ok(v) => v,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return;
        }
    };

    read_result.iter().for_each(|line| {
        let mut map = line.split('.').take(2);
        if let Some(size) = map.size_hint().1 {
            if size < 2 {
                return;
            }
        } else {
            return;
        }
        let key = map.next().unwrap();
        let value = map.next().unwrap();

        //存在しなければ、keyを作成
        PIVOT_KEYWORD
            .write()
            .unwrap()
            .entry(key.to_string())
            .or_default();

        PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut(key)
            .unwrap()
            .fields
            .insert(value.to_string());
    });
}

/// --target-file-extで追加された拡張子から、調査対象ファイルの拡張子セットを返す関数。--json-inputがtrueの場合はjsonのみを対象とする
pub fn get_target_extensions(arg: Option<&Vec<String>>, json_input_flag: bool) -> HashSet<String> {
    let mut target_file_extensions: HashSet<String> = convert_option_vecs_to_hs(arg);
    if json_input_flag {
        target_file_extensions.insert(String::from("json"));
        target_file_extensions.insert(String::from("jsonl"));
    } else {
        target_file_extensions.insert(String::from("evtx"));
    }
    target_file_extensions
}

/// Option<Vec<String>>の内容をHashSetに変換する関数
pub fn convert_option_vecs_to_hs(arg: Option<&Vec<String>>) -> HashSet<String> {
    let ret: HashSet<String> = arg.unwrap_or(&Vec::new()).iter().cloned().collect();
    ret
}

fn extract_search_options(config: &Config) -> Option<SearchOption> {
    match &config.action.as_ref()? {
        Action::Search(option) => Some(SearchOption {
            input_args: option.input_args.clone(),
            keywords: option.keywords.clone(),
            regex: option.regex.clone(),
            ignore_case: option.ignore_case,
            filter: option.filter.clone(),
            output: option.output.clone(),
            common_options: option.common_options,
            evtx_file_ext: option.evtx_file_ext.clone(),
            thread_number: option.thread_number,
            quiet_errors: option.quiet_errors,
            config: option.config.clone(),
            verbose: option.verbose,
            multiline: option.multiline,
            clobber: option.clobber,
            json_output: option.json_output,
            jsonl_output: option.jsonl_output,
            time_format_options: option.time_format_options.clone(),
            and_logic: option.and_logic,
            disable_abbreviations: option.disable_abbreviations,
            start_timeline: option.start_timeline.clone(),
            end_timeline: option.end_timeline.clone(),
            sort_events: option.sort_events,
        }),
        _ => None,
    }
}

/// configから出力に関連したオプションの値を格納した構造体を抽出する関数
fn extract_output_options(config: &Config) -> Option<OutputOption> {
    match &config.action.as_ref()? {
        Action::CsvTimeline(option) => Some(option.output_options.clone()),
        Action::JsonTimeline(option) => Some(option.output_options.clone()),
        Action::PivotKeywordsList(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            enable_deprecated_rules: option.enable_deprecated_rules,
            enable_noisy_rules: option.enable_noisy_rules,
            profile: None,
            exclude_status: option.exclude_status.clone(),
            min_level: option.min_level.clone(),
            exact_level: option.exact_level.clone(),
            end_timeline: option.end_timeline.clone(),
            start_timeline: option.start_timeline.clone(),
            eid_filter: option.eid_filter,
            time_format_options: TimeFormatOptions {
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
            },
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: option.detect_common_options.clone(),
            enable_unsupported_rules: option.enable_unsupported_rules,
            clobber: option.clobber,
            proven_rules: false,
            include_tag: option.include_tag.clone(),
            exclude_tag: option.exclude_tag.clone(),
            include_category: None,
            exclude_category: None,
            include_eid: option.include_eid.clone(),
            exclude_eid: option.exclude_eid.clone(),
            no_field: false,
            no_pwsh_field_extraction: false,
            remove_duplicate_data: false,
            remove_duplicate_detections: false,
            no_wizard: option.no_wizard,
            include_status: option.include_status.clone(),
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::EidMetrics(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: option.time_format_options.clone(),
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: option.detect_common_options.clone(),
            enable_unsupported_rules: false,
            clobber: option.clobber,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::ExtractBase64(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: option.time_format_options.clone(),
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: option.detect_common_options.clone(),
            enable_unsupported_rules: false,
            clobber: option.clobber,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::LogonSummary(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: option.time_format_options.clone(),
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: option.detect_common_options.clone(),
            enable_unsupported_rules: false,
            clobber: option.clobber,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::ComputerMetrics(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            profile: None,
            common_options: option.common_options,
            enable_deprecated_rules: false,
            enable_unsupported_rules: false,
            exclude_status: None,
            include_tag: None,
            include_category: None,
            exclude_category: None,
            min_level: String::default(),
            exact_level: None,
            enable_noisy_rules: false,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            proven_rules: false,
            exclude_tag: None,
            detect_common_options: DetectCommonOption {
                json_input: option.json_input,
                evtx_file_ext: option.evtx_file_ext.clone(),
                thread_number: option.thread_number,
                quiet_errors: option.quiet_errors,
                config: option.config.clone(),
                verbose: option.verbose,
                include_computer: None,
                exclude_computer: None,
            },
            time_format_options: TimeFormatOptions {
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
            },
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            clobber: option.clobber,
            include_eid: None,
            exclude_eid: None,
            no_field: false,
            no_pwsh_field_extraction: false,
            remove_duplicate_data: false,
            remove_duplicate_detections: false,
            no_wizard: true,
            include_status: None,
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::LogMetrics(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            profile: None,
            common_options: option.common_options,
            enable_deprecated_rules: false,
            enable_unsupported_rules: false,
            exclude_status: None,
            include_tag: None,
            include_category: None,
            exclude_category: None,
            min_level: String::default(),
            exact_level: None,
            enable_noisy_rules: false,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            proven_rules: false,
            exclude_tag: None,
            detect_common_options: option.detect_common_options.clone(),
            time_format_options: option.time_format_options.clone(),
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            clobber: option.clobber,
            include_eid: None,
            exclude_eid: None,
            no_field: false,
            no_pwsh_field_extraction: false,
            remove_duplicate_data: false,
            remove_duplicate_detections: false,
            no_wizard: true,
            include_status: None,
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::Search(option) => Some(OutputOption {
            input_args: option.input_args.clone(),
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: option.time_format_options.clone(),
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: DetectCommonOption {
                json_input: false,
                evtx_file_ext: option.evtx_file_ext.clone(),
                thread_number: option.thread_number,
                quiet_errors: option.quiet_errors,
                config: option.config.clone(),
                verbose: option.verbose,
                include_computer: None,
                exclude_computer: None,
            },
            exact_level: None,
            enable_unsupported_rules: false,
            clobber: option.clobber,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::SetDefaultProfile(option) => Some(OutputOption {
            input_args: InputOption {
                directory: None,
                filepath: None,
                live_analysis: false,
                recover_records: false,
                time_offset: None,
            },
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: TimeFormatOptions {
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
            },
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: false,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::UpdateRules(option) => Some(OutputOption {
            input_args: InputOption {
                directory: None,
                filepath: None,
                live_analysis: false,
                recover_records: false,
                time_offset: None,
            },
            enable_deprecated_rules: true,
            enable_noisy_rules: true,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: TimeFormatOptions {
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
            },
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: false,
                include_computer: None,
                exclude_computer: None,
            },
            enable_unsupported_rules: true,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        Action::ConfigCriticalSystems(option) => Some(OutputOption {
            input_args: InputOption {
                directory: option.directory.clone(),
                filepath: option.filepath.clone(),
                live_analysis: false,
                recover_records: false,
                time_offset: None,
            },
            enable_deprecated_rules: false,
            enable_noisy_rules: false,
            profile: None,
            exclude_status: None,
            min_level: String::default(),
            exact_level: None,
            end_timeline: None,
            start_timeline: None,
            eid_filter: false,
            time_format_options: TimeFormatOptions {
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
            },
            visualize_timeline: false,
            rules: Path::new("./rules").to_path_buf(),
            html_report: None,
            no_summary: false,
            common_options: option.common_options,
            detect_common_options: DetectCommonOption {
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                json_input: false,
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
            sort_events: false,
            enable_all_rules: false,
            scan_all_evtx_files: false,
        }),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct EventInfo {
    pub evttitle: String,
}

impl Default for EventInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl EventInfo {
    pub fn new() -> EventInfo {
        let evttitle = "Unknown".to_string();
        EventInfo { evttitle }
    }
}
#[derive(Debug, Clone)]
pub struct EventInfoConfig {
    eventinfo: HashMap<(String, String), EventInfo>,
}

impl Default for EventInfoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EventInfoConfig {
    pub fn new() -> EventInfoConfig {
        EventInfoConfig {
            eventinfo: HashMap::new(),
        }
    }
    pub fn get_event_id(&self, channel: &str, eventid: &str) -> Option<&EventInfo> {
        self.eventinfo
            .get(&(channel.to_string(), eventid.to_string()))
    }
}

fn load_eventcode_info(path: &str) -> EventInfoConfig {
    let mut infodata = EventInfo::new();
    let mut config = EventInfoConfig::new();
    let read_result = match utils::read_csv(path) {
        Ok(v) => v,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return config;
        }
    };

    // channel_eid_info.txtが読み込めなかったらエラーで終了とする。
    read_result.iter().for_each(|line| {
        if line.len() != 3 {
            return;
        }

        let empty = &"".to_string();
        let channel = line.first().unwrap_or(empty);
        let eventcode = line.get(1).unwrap_or(empty);
        let event_title = line.get(2).unwrap_or(empty);
        infodata = EventInfo {
            evttitle: event_title.to_string(),
        };
        config.eventinfo.insert(
            (channel.to_lowercase(), eventcode.to_owned()),
            infodata.to_owned(),
        );
    });
    config
}

fn create_control_chat_replace_map() -> HashMap<char, CompactString> {
    let mut ret = HashMap::new();
    let replace_char = '\0'..='\x1F';
    for c in replace_char.into_iter().filter(|x| x != &'\x0A') {
        ret.insert(
            c,
            CompactString::from(format!(
                "\\u00{}",
                format!("{:02x}", c as u8).to_uppercase()
            )),
        );
    }
    ret
}

pub fn load_windash_characters(file_path: &str) -> Vec<char> {
    if let Some(contents) = ONE_CONFIG_MAP.get("windash_characters.txt") {
        return contents
            .lines()
            .map(|line| line.chars().next().unwrap())
            .collect();
    }
    let mut characters = Vec::from(['-', '–', '—', '―']);
    let file = File::open(file_path);
    match file {
        Ok(f) => {
            characters = Vec::new();
            let reader = io::BufReader::new(f);
            for line in reader.lines() {
                let line = line.unwrap();
                if let Some(ch) = line.chars().next() {
                    characters.push(ch);
                }
            }
            characters
        }
        Err(_) => characters,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        create_control_chat_replace_map, Action, CommonOptions, Config, CsvOutputOption,
        DetectCommonOption, InputOption, JSONOutputOption, OutputOption, StoredStatic,
        TargetEventTime, TimeFormatOptions,
    };
    use crate::detections::configs::{
        self, EidMetricsOption, LogonSummaryOption, PivotKeywordOption, SearchOption,
    };
    use chrono::{DateTime, Utc};
    use compact_str::CompactString;
    use hashbrown::{HashMap, HashSet};

    //     #[test]
    //     #[ignore]
    //     fn singleton_read_and_write() {
    //         let message =
    //             "EventKeyAliasConfig { key_to_eventkey: {\"EventID\": \"Event.System.EventID\"} }";
    //         configs::EVENT_KEY_ALIAS_CONFIG =
    //             configs::load_eventkey_alias("test_files/config/eventkey_alias.txt");
    //         let display = format!(
    //             "{}",
    //             format_args!(
    //                 "{:?}",
    //                 configs::CONFIG.write().unwrap().event_key_alias_config
    //             )
    //         );
    //         assert_eq!(message, display);
    //     }
    // }

    #[test]
    fn target_event_time_filter() {
        let start_time = Some("2018-02-20T12:00:09Z".parse::<DateTime<Utc>>().unwrap());
        let end_time = Some("2020-03-30T12:00:09Z".parse::<DateTime<Utc>>().unwrap());
        let time_filter = TargetEventTime::set(true, start_time, end_time);

        let out_of_range1 = Some("1999-01-01T12:00:09Z".parse::<DateTime<Utc>>().unwrap());
        let within_range = Some("2019-02-27T01:05:01Z".parse::<DateTime<Utc>>().unwrap());
        let out_of_range2 = Some("2021-02-27T01:05:01Z".parse::<DateTime<Utc>>().unwrap());

        assert!(!time_filter.is_target(&out_of_range1));
        assert!(time_filter.is_target(&within_range));
        assert!(!time_filter.is_target(&out_of_range2));
    }

    #[test]
    fn target_event_time_filter_containes_on_time() {
        let start_time = Some("2018-02-20T12:00:09Z".parse::<DateTime<Utc>>().unwrap());
        let end_time = Some("2020-03-30T12:00:09Z".parse::<DateTime<Utc>>().unwrap());
        let time_filter = TargetEventTime::set(true, start_time, end_time);

        assert!(time_filter.is_target(&start_time));
        assert!(time_filter.is_target(&end_time));
    }

    #[test]
    fn test_get_target_extensions() {
        let data = vec!["evtx_data".to_string(), "evtx_stars".to_string()];
        let arg = Some(&data);
        let ret = configs::get_target_extensions(arg, false);
        let expect: HashSet<&str> = HashSet::from(["evtx", "evtx_data", "evtx_stars"]);
        assert_eq!(ret.len(), expect.len());
        for contents in expect.iter() {
            assert!(ret.contains(&contents.to_string()));
        }
    }

    #[test]
    fn no_target_extensions() {
        let ret = configs::get_target_extensions(None, false);
        let expect: HashSet<&str> = HashSet::from(["evtx"]);
        assert_eq!(ret.len(), expect.len());
        for contents in expect.iter() {
            assert!(ret.contains(&contents.to_string()));
        }
    }

    #[test]
    fn test_create_control_char_replace_map() {
        let mut expect: HashMap<char, CompactString> =
            HashMap::from_iter(('\0'..='\x1F').map(|c| {
                (
                    c as u8 as char,
                    CompactString::from(format!(
                        "\\u00{}",
                        format!("{:02x}", c as u8).to_uppercase()
                    )),
                )
            }));
        expect.remove(&'\x0A');
        let actual = create_control_chat_replace_map();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_time_offset_csv() {
        let csv_timeline = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        time_offset: Some("1d".to_string()),
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
                    time_format_options: TimeFormatOptions {
                        european_time: false,
                        iso_8601: false,
                        rfc_2822: false,
                        rfc_3339: false,
                        us_military_time: false,
                        us_time: false,
                        utc: false,
                    },
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
                    sort_events: false,
                    enable_all_rules: false,
                    scan_all_evtx_files: false,
                },
                geo_ip: None,
                output: None,
                multiline: false,
                disable_abbreviations: false,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&csv_timeline);
        let actual_diff = now - actual.start_time.unwrap();
        assert!(actual_diff.num_days() == 1);
    }

    #[test]
    fn test_time_offset_json() {
        let json_timeline = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::JsonTimeline(JSONOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        time_offset: Some("1y".to_string()),
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
                    time_format_options: TimeFormatOptions {
                        european_time: false,
                        iso_8601: false,
                        rfc_2822: false,
                        rfc_3339: false,
                        us_military_time: false,
                        us_time: false,
                        utc: false,
                    },
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
                    sort_events: false,
                    enable_all_rules: false,
                    scan_all_evtx_files: false,
                },
                geo_ip: None,
                output: None,
                jsonl_timeline: false,
                disable_abbreviations: false,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&json_timeline);
        let actual_diff = now - actual.start_time.unwrap();
        assert!(actual_diff.num_days() == 365 || actual_diff.num_days() == 366);
    }

    #[test]
    fn test_time_offset_search() {
        let json_timeline = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::Search(SearchOption {
                output: None,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: Some("1h".to_string()),
                },
                keywords: Some(vec!["mimikatz".to_string()]),
                regex: None,
                ignore_case: true,
                and_logic: false,
                filter: vec![],
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                multiline: false,
                clobber: true,
                json_output: false,
                jsonl_output: false,
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                },
                disable_abbreviations: false,
                start_timeline: None,
                end_timeline: None,
                sort_events: true,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&json_timeline);
        let actual_diff = now - actual.start_time.unwrap();
        assert!(actual_diff.num_hours() == 1);
    }

    #[test]
    fn test_time_offset_eid_metrics() {
        let eid_metrics = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::EidMetrics(EidMetricsOption {
                output: None,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: Some("1h1m".to_string()),
                },
                clobber: true,
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
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
                remove_duplicate_detections: false,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&eid_metrics);
        let actual_diff = now - actual.start_time.unwrap();
        assert!(actual_diff.num_hours() == 1 && actual_diff.num_minutes() == 61);
    }

    #[test]
    fn test_time_offset_logon_summary() {
        let logon_summary = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::LogonSummary(LogonSummaryOption {
                output: None,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: Some("1y1d1h".to_string()),
                },
                clobber: true,
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
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
                end_timeline: None,
                start_timeline: None,
                remove_duplicate_detections: false,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&logon_summary);
        let actual_diff = now - actual.start_time.unwrap();
        let days = actual_diff.num_days();
        assert!(
            (days == 366 && actual_diff.num_hours() == days * 24 + 1)
                || (days == 367 && actual_diff.num_hours() == days * 24 + 1)
        );
    }

    #[test]
    fn test_time_offset_pivot() {
        let pivot_keywords_list = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::PivotKeywordsList(PivotKeywordOption {
                output: None,
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: Some("1y1M1s".to_string()),
                },
                clobber: true,
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
                end_timeline: None,
                start_timeline: None,
                enable_deprecated_rules: false,
                enable_unsupported_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
                enable_noisy_rules: false,
                eid_filter: false,
                include_eid: None,
                exclude_eid: None,
                no_wizard: true,
                include_tag: None,
                exclude_tag: None,
                include_status: None,
            })),
            debug: false,
        }));
        let now = Utc::now();
        let actual = TargetEventTime::new(&pivot_keywords_list);
        let actual_diff = now - actual.start_time.unwrap();
        let actual_diff_day = actual_diff.num_days();
        assert!(
            (393..=397).contains(&actual_diff_day)
                && actual_diff.num_seconds() - (actual_diff_day * 24 * 60 * 60) == 1
        );
    }
}

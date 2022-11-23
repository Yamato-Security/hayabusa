use crate::detections::message::AlertMessage;
use crate::detections::pivot::{PivotKeyword, PIVOT_KEYWORD};
use crate::detections::utils;
use chrono::{DateTime, Utc};
use clap::{ColorChoice, Command, CommandFactory, Parser};
use hashbrown::{HashMap, HashSet};
use lazy_static::lazy_static;
use nested::Nested;
use regex::Regex;
use std::env::current_exe;
use std::path::PathBuf;
use std::sync::RwLock;
use terminal_size::{terminal_size, Width};

lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(Config::parse());
    pub static ref CURRENT_EXE_PATH: PathBuf =
        current_exe().unwrap().parent().unwrap().to_path_buf();
    pub static ref EVENTKEY_ALIAS: EventKeyAliasConfig = load_eventkey_alias(
        utils::check_setting_path(&CONFIG.read().unwrap().config, "eventkey_alias.txt", false)
            .unwrap_or_else(|| {
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
            })
            .to_str()
            .unwrap()
    );
    pub static ref IDS_REGEX: Regex =
        Regex::new(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$").unwrap();
}

pub struct ConfigReader {
    pub app: Command,
    pub headless_help: String,
    pub event_timeline_config: EventInfoConfig,
    pub target_eventids: TargetEventIds,
}

impl Default for ConfigReader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Parser, Clone)]
#[command(
    name = "Hayabusa",
    override_usage = "hayabusa.exe [OTHER-ACTIONS] <INPUT> [OUTPUT] [OPTIONS]",
    author = "Yamato Security (https://github.com/Yamato-Security/hayabusa) @SecurityYamato)",
    help_template = "\n{name} {version}\n{author}\n\n{usage-heading}\n  {usage}\n\n{all-args}",
    version,
    term_width = 400
)]
pub struct Config {
    /// Directory of multiple .evtx files
    #[arg(help_heading = Some("Input"), short = 'd', long, value_name = "DIRECTORY")]
    pub directory: Option<PathBuf>,

    /// File path to one .evtx file
    #[arg(help_heading = Some("Input"), short = 'f', long = "file", value_name = "FILE")]
    pub filepath: Option<PathBuf>,

    /// Analyze the local C:\Windows\System32\winevt\Logs folder
    #[arg(help_heading = Some("Input"), short = 'l', long = "live-analysis")]
    pub live_analysis: bool,

    /// Specify custom rule config directory (default: ./rules/config)
    #[arg(
        help_heading = Some("Advanced"),
        short = 'c',
        long = "rules-config",
        default_value = "./rules/config",
        hide_default_value = true,
        value_name = "DIRECTORY"
    )]
    pub config: PathBuf,

    /// Quiet errors mode: do not save error logs
    #[arg(help_heading = Some("Advanced"), short = 'Q', long = "quiet-errors")]
    pub quiet_errors: bool,

    /// Specify a custom rule directory or file (default: ./rules)
    #[arg(
        help_heading = Some("Advanced"), 
        short = 'r',
        long,
        default_value = "./rules",
        hide_default_value = true,
        value_name = "DIRECTORY/FILE"
    )]
    pub rules: PathBuf,

    /// Thread number (default: optimal number for performance)
    #[arg(help_heading = Some("Advanced"), short, long = "thread-number", value_name = "NUMBER")]
    pub thread_number: Option<usize>,

    /// Specify additional target file extensions (ex: evtx_data) (ex: evtx1,evtx2)
    #[arg(help_heading = Some("Advanced"), long = "target-file-ext", use_value_delimiter = true, value_delimiter = ',')]
    pub evtx_file_ext: Option<Vec<String>>,

    /// Save detail Results Summary in html (ex: results.html)
    #[arg(help_heading = Some("Output"), short = 'H', long="html-report", value_name = "FILE")]
    pub html_report: Option<PathBuf>,

    /// Save the timeline in JSON format (ex: -j -o results.json)
    #[arg(help_heading = Some("Output"), short = 'j', long = "json", requires = "output")]
    pub json_timeline: bool,

    /// Save the timeline in JSONL format (ex: -J -o results.jsonl)
    #[arg(help_heading = Some("Output"), short = 'J', long = "jsonl", requires = "output")]
    pub jsonl_timeline: bool,

    /// Save the timeline in CSV format (ex: results.csv)
    #[arg(help_heading = Some("Output"), short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Specify output profile
    #[arg(help_heading = Some("Output"), short = 'P', long = "profile")]
    pub profile: Option<String>,

    /// Disable color output
    #[arg(help_heading = Some("Display Settings"), long = "no-color")]
    pub no_color: bool,

    /// Do not display result summary
    #[arg(help_heading = Some("Display Settings"), long = "no-summary")]
    pub no_summary: bool,

    /// Quiet mode: do not display the launch banner
    #[arg(help_heading = Some("Display Settings"), short, long)]
    pub quiet: bool,

    /// Output verbose information
    #[arg(help_heading = Some("Display Settings"), short = 'v', long)]
    pub verbose: bool,

    /// Output event frequency timeline
    #[arg(help_heading = Some("Display Settings"), short = 'T', long = "visualize-timeline")]
    pub visualize_timeline: bool,

    /// Print debug information (memory usage, etc...)
    #[clap(help_heading = Some("Display Settings"), long = "debug")]
    pub debug: bool,

    /// Filter by Event IDs (config file: ./rules/config/target_event_IDs.txt)
    #[arg(help_heading = Some("Filtering"), short = 'e', long = "eid-filter")]
    pub eid_filter: bool,

    /// Enable rules marked as deprecated
    #[arg(help_heading = Some("Filtering"), long = "enable-deprecated-rules")]
    pub enable_deprecated_rules: bool,

    /// Ignore rules according to status (ex: experimental) (ex: stable,test)
    #[arg(help_heading = Some("Filtering"), long = "exclude-status", value_name = "STATUS", use_value_delimiter = true, value_delimiter = ',')]
    pub exclude_status: Option<Vec<String>>,

    /// Minimum level for rules (default: informational)
    #[arg(
        help_heading = Some("Filtering"), 
        short = 'm',
        long = "min-level",
        default_value = "informational",
        hide_default_value = true,
        value_name = "LEVEL"
    )]
    pub min_level: String,

    /// Enable rules marked as noisy
    #[arg(help_heading = Some("Filtering"), short = 'n', long = "enable-noisy-rules")]
    pub enable_noisy_rules: bool,

    /// End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-end", value_name = "DATE")]
    pub end_timeline: Option<String>,

    /// Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")
    #[arg(help_heading = Some("Filtering"), long = "timeline-start", value_name = "DATE")]
    pub start_timeline: Option<String>,

    /// Print the list of contributors
    #[arg(help_heading = Some("Other Actions"), long)]
    pub contributors: bool,

    /// Print a summary of successful and failed logons
    #[arg(help_heading = Some("Other Actions"), short = 'L', long = "logon-summary")]
    pub logon_summary: bool,

    /// Tune alert levels (default: ./rules/config/level_tuning.txt)
    #[arg(
        help_heading = Some("Other Actions"), 
        long = "level-tuning",
        hide_default_value = true,
        value_name = "FILE"
    )]
    pub level_tuning: Option<Option<String>>,

    /// List the output profiles
    #[arg(help_heading = Some("Other Actions"), long = "list-profiles")]
    pub list_profile: bool,

    /// Print event ID metrics
    #[arg(help_heading = Some("Other Actions"), short='M', long)]
    pub metrics: bool,

    /// Create a list of pivot keywords
    #[arg(help_heading = Some("Other Actions"), short = 'p', long = "pivot-keywords-list")]
    pub pivot_keywords_list: bool,

    /// Set default output profile
    #[arg(help_heading = Some("Other Actions"), long = "set-default-profile", value_name = "PROFILE")]
    pub set_default_profile: Option<String>,

    /// Update to the latest rules in the hayabusa-rules github repository
    #[arg(help_heading = Some("Other Actions"), short = 'u', long = "update-rules")]
    pub update_rules: bool,

    /// Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
    #[arg(help_heading = Some("Time Format"), long = "European-time")]
    pub european_time: bool,

    /// Output timestamp in ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
    #[arg(help_heading = Some("Time Format"), long = "ISO-8601")]
    pub iso_8601: bool,

    /// Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
    #[arg(help_heading = Some("Time Format"), long = "RFC-2822")]
    pub rfc_2822: bool,

    /// Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
    #[arg(help_heading = Some("Time Format"), long = "RFC-3339")]
    pub rfc_3339: bool,

    /// Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
    #[arg(help_heading = Some("Time Format"), long = "US-military-time")]
    pub us_military_time: bool,

    /// Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
    #[arg(help_heading = Some("Time Format"), long = "US-time")]
    pub us_time: bool,

    /// Output time in UTC format (default: local time)
    #[arg(help_heading = Some("Time Format"), short = 'U', long = "UTC")]
    pub utc: bool,

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
            .color(ColorChoice::Auto)
            .term_width(help_term_width);
        ConfigReader {
            app: build_cmd,
            headless_help: String::default(),
            event_timeline_config: load_eventcode_info(
                utils::check_setting_path(&parse.config, "channel_eid_info.txt", false)
                    .unwrap_or_else(|| {
                        utils::check_setting_path(
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
                utils::check_setting_path(&parse.config, "target_event_IDs.txt", false)
                    .unwrap_or_else(|| {
                        utils::check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/target_event_IDs.txt",
                            true,
                        )
                        .unwrap()
                    })
                    .to_str()
                    .unwrap(),
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetEventIds {
    ids: HashSet<String>,
}

impl Default for TargetEventIds {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetEventIds {
    pub fn new() -> TargetEventIds {
        TargetEventIds {
            ids: HashSet::new(),
        }
    }

    pub fn is_target(&self, id: &str) -> bool {
        // 中身が空の場合は全EventIdを対象とする。
        if self.ids.is_empty() {
            return true;
        }
        self.ids.contains(id)
    }
}

fn load_target_ids(path: &str) -> TargetEventIds {
    let mut ret = TargetEventIds::new();
    let lines = utils::read_txt(path); // ファイルが存在しなければエラーとする
    if lines.is_err() {
        AlertMessage::alert(lines.as_ref().unwrap_err()).ok();
        return ret;
    }

    for line in lines.unwrap_or_else(|_| Nested::<String>::new()).iter() {
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

impl Default for TargetEventTime {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetEventTime {
    pub fn new() -> Self {
        let mut parse_success_flag = true;
        let start_time = if let Some(s_time) = &CONFIG.read().unwrap().start_timeline {
            match DateTime::parse_from_str(s_time, "%Y-%m-%d %H:%M:%S %z") // 2014-11-28 21:00:09 +09:00
                .or_else(|_| DateTime::parse_from_str(s_time, "%Y/%m/%d %H:%M:%S %z")) // 2014/11/28 21:00:09 +09:00
            {
                Ok(dt) => Some(dt.with_timezone(&Utc)),
                Err(_) => {
                    AlertMessage::alert(
                        "start-timeline field: the timestamp format is not correct.",
                    )
                    .ok();
                    parse_success_flag = false;
                    None
                }
            }
        } else {
            None
        };
        let end_time = if let Some(e_time) = &CONFIG.read().unwrap().end_timeline {
            match DateTime::parse_from_str(e_time, "%Y-%m-%d %H:%M:%S %z") // 2014-11-28 21:00:09 +09:00
            .or_else(|_| DateTime::parse_from_str(e_time, "%Y/%m/%d %H:%M:%S %z")) // 2014/11/28 21:00:09 +09:00
        {
            Ok(dt) => Some(dt.with_timezone(&Utc)),
            Err(_) => {
                    AlertMessage::alert(
                        "end-timeline field: the timestamp format is not correct.",
                    )
                    .ok();
                    parse_success_flag = false;
                    None
                }
            }
        } else {
            None
        };
        Self::set(parse_success_flag, start_time, end_time)
    }

    pub fn set(
        input_parse_success_flag: bool,
        input_start_time: Option<chrono::DateTime<chrono::Utc>>,
        input_end_time: Option<chrono::DateTime<chrono::Utc>>,
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

fn load_eventkey_alias(path: &str) -> EventKeyAliasConfig {
    let mut config = EventKeyAliasConfig::new();

    // eventkey_aliasが読み込めなかったらエラーで終了とする。
    let read_result = utils::read_csv(path);
    if read_result.is_err() {
        AlertMessage::alert(read_result.as_ref().unwrap_err()).ok();
        return config;
    }

    read_result.unwrap().iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }

        let empty = &"".to_string();
        let alias = line.get(0).unwrap_or(empty);
        let event_key = line.get(1).unwrap_or(empty);
        if alias.is_empty() || event_key.is_empty() {
            return;
        }

        config
            .key_to_eventkey
            .insert(alias.to_owned(), event_key.to_owned());
        let splits = event_key.split('.').map(|s| s.len()).collect();
        config
            .key_to_split_eventkey
            .insert(alias.to_owned(), splits);
    });
    config.key_to_eventkey.shrink_to_fit();
    config
}

///設定ファイルを読み込み、keyとfieldsのマップをPIVOT_KEYWORD大域変数にロードする。
pub fn load_pivot_keywords(path: &str) {
    let read_result = utils::read_txt(path);
    if read_result.is_err() {
        AlertMessage::alert(read_result.as_ref().unwrap_err()).ok();
    }

    read_result.unwrap().iter().for_each(|line| {
        let map: Vec<&str> = line.split('.').collect();
        if map.len() != 2 {
            return;
        }

        //存在しなければ、keyを作成
        PIVOT_KEYWORD
            .write()
            .unwrap()
            .entry(map[0].to_string())
            .or_insert_with(PivotKeyword::new);

        PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut(&map[0].to_string())
            .unwrap()
            .fields
            .insert(map[1].to_string());
    });
}

/// --target-file-extで追加された拡張子から、調査対象ファイルの拡張子セットを返す関数
pub fn get_target_extensions(arg: Option<&Vec<String>>) -> HashSet<String> {
    let mut target_file_extensions: HashSet<String> = convert_option_vecs_to_hs(arg);
    target_file_extensions.insert(String::from("evtx"));
    target_file_extensions
}

/// Option<Vec<String>>の内容をHashSetに変換する関数
pub fn convert_option_vecs_to_hs(arg: Option<&Vec<String>>) -> HashSet<String> {
    let ret: HashSet<String> = arg.unwrap_or(&Vec::new()).iter().cloned().collect();
    ret
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
    let read_result = utils::read_csv(path);
    if read_result.is_err() {
        AlertMessage::alert(read_result.as_ref().unwrap_err()).ok();
        return config;
    }

    // event_id_info.txtが読み込めなかったらエラーで終了とする。
    read_result.unwrap().iter().for_each(|line| {
        if line.len() != 3 {
            return;
        }

        let empty = &"".to_string();
        let channel = line.get(0).unwrap_or(empty);
        let eventcode = line.get(1).unwrap_or(empty);
        let event_title = line.get(2).unwrap_or(empty);
        infodata = EventInfo {
            evttitle: event_title.to_string(),
        };
        config.eventinfo.insert(
            (channel.to_owned(), eventcode.to_owned()),
            infodata.to_owned(),
        );
    });
    config
}

#[cfg(test)]
mod tests {
    use crate::detections::configs;
    use chrono::{DateTime, Utc};
    use hashbrown::HashSet;

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
        let time_filter = configs::TargetEventTime::set(true, start_time, end_time);

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
        let time_filter = configs::TargetEventTime::set(true, start_time, end_time);

        assert!(time_filter.is_target(&start_time));
        assert!(time_filter.is_target(&end_time));
    }

    #[test]
    fn test_get_target_extensions() {
        let data = vec!["evtx_data".to_string(), "evtx_stars".to_string()];
        let arg = Some(&data);
        let ret = configs::get_target_extensions(arg);
        let expect: HashSet<&str> = HashSet::from(["evtx", "evtx_data", "evtx_stars"]);
        assert_eq!(ret.len(), expect.len());
        for contents in expect.iter() {
            assert!(ret.contains(&contents.to_string()));
        }
    }

    #[test]
    fn no_target_extensions() {
        let ret = configs::get_target_extensions(None);
        let expect: HashSet<&str> = HashSet::from(["evtx"]);
        assert_eq!(ret.len(), expect.len());
        for contents in expect.iter() {
            assert!(ret.contains(&contents.to_string()));
        }
    }
}

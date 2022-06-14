use crate::detections::pivot::PivotKeyword;
use crate::detections::pivot::PIVOT_KEYWORD;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, Utc};
use clap::{ArgMatches, Command, CommandFactory, Parser};
use hashbrown::HashMap;
use hashbrown::HashSet;
use lazy_static::lazy_static;
use regex::Regex;
use std::path::PathBuf;
use std::sync::RwLock;
lazy_static! {
    pub static ref CONFIG: RwLock<ConfigReader<'static>> = RwLock::new(ConfigReader::new());
    pub static ref LEVELMAP: HashMap<String, u128> = {
        let mut levelmap = HashMap::new();
        levelmap.insert("INFORMATIONAL".to_owned(), 1);
        levelmap.insert("LOW".to_owned(), 2);
        levelmap.insert("MEDIUM".to_owned(), 3);
        levelmap.insert("HIGH".to_owned(), 4);
        levelmap.insert("CRITICAL".to_owned(), 5);
        levelmap
    };
    pub static ref EVENTKEY_ALIAS: EventKeyAliasConfig = load_eventkey_alias(&format!(
        "{}/eventkey_alias.txt",
        CONFIG.read().unwrap().folder_path
    ));
    pub static ref IDS_REGEX: Regex =
        Regex::new(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$").unwrap();
}

#[derive(Clone)]
pub struct ConfigReader<'a> {
    pub args: ArgMatches,
    pub headless_help: String,
    pub folder_path: String,
    pub event_timeline_config: EventInfoConfig,
    pub target_eventids: TargetEventIds,
}

impl Default for ConfigReader<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Hayabusa: Aiming to be the world's greatest Windows event log analysis tool!
#[derive(Parser)]
#[clap(
    author = "Yamato Security (https://github.com/Yamato-Security/hayabusa) @SecurityYamato)",
    version
)]
struct Config {
    /// Directory of multiple .evtx files.
    #[clap(short = 'd', long, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    /// File path to one .evtx file.
    #[clap(short = 'f', long, value_name = "FILE_PATH")]
    filepath: Option<PathBuf>,

    /// Print all field information.
    #[clap(short = 'F', long = "full-data")]
    full_data: bool,

    /// Rule directory or file.
    #[clap(
        short = 'r',
        long,
        default_value = "./rules",
        value_name = "RULE_DIRECTORY/RULE_FILE"
    )]
    rules: PathBuf,

    /// Rule config folder.
    #[clap(
        short = 'C',
        long,
        default_value = "./rules/config",
        value_name = "RULE_CONFIG_DIRECTORY"
    )]
    config: PathBuf,

    /// Save the timeline in CSV format. (Ex: results.csv)
    #[clap(short = 'o', long, value_name = "CSV_TIMELINE")]
    output: Option<PathBuf>,

    /// Output all tags when saving to a CSV file.
    #[clap(long = "all-tags")]
    all_tags: bool,

    /// Do not display EventRecordID number.
    #[clap(short = 'R', long = "hide-record-id")]
    hide_record_id: bool,

    /// Output verbose information.
    #[clap(short = 'v', long)]
    verbose: bool,

    /// Output event frequency timeline.
    #[clap(short = 'V', long = "visualize-timeline")]
    visualize_timeline: bool,

    /// Enable rules marked as deprecated.
    #[clap(short = 'D', long = "enable-deprecated-rules")]
    enable_deprecated_rules: bool,

    /// Enable rules marked as noisy.
    #[clap(short = 'n', long = "enable-noisy-rules")]
    enable_noisy_rules: bool,

    /// Update to the latest rules in the hayabusa-rules github repository.
    #[clap(short = 'u', long = "update-rules")]
    update_rules: bool,

    /// Minimum level for rules.
    #[clap(
        short = 'm',
        long = "min-level",
        default_value = "informational",
        value_name = "LEVEL"
    )]
    min_level: String,

    /// Analyze the local C:\\Windows\\System32\\winevt\\Logs folder (Windows Only. Administrator privileges required.)
    #[clap(short = 'l', long = "live-analysis")]
    live_analysis: bool,

    /// Start time of the event logs to load. (Ex: "2020-02-22 00:00:00 +09:00")
    #[clap(long = "start-timeline", value_name = "START_TIMELINE")]
    start_timeline: Option<String>,

    /// End time of the event logs to load. (Ex: "2022-02-22 23:59:59 +09:00")
    #[clap(long = "end-timeline", value_name = "END_TIMELINE")]
    end_timeline: Option<String>,

    /// Output timestamp in RFC 2822 format. (Ex: Fri, 22 Feb 2022 22:00:00 -0600)
    #[clap(long = "rfc-2822")]
    rfc_2822: bool,

    /// Output timestamp in RFC 3339 format. (Ex: 2022-02-22 22:00:00.123456-06:00)
    #[clap(long = "rfc-3339")]
    rfc_3339: bool,

    /// Output timestamp in US time format. (Ex: 02-22-2022 10:00:00.123 PM -06:00)
    #[clap(long = "US-time")]
    us_time: bool,

    /// Output timestamp in US military time format. (Ex: 02-22-2022 22:00:00.123 -06:00)
    #[clap(long = "US-military-time")]
    us_military_time: bool,

    /// Output timestamp in European time format. (Ex: 22-02-2022 22:00:00.123 +02:00)
    #[clap(long = "European-time")]
    european_time: bool,

    /// Output time in UTC format. [default: local time]
    #[clap(short = 'U', long = "utc")]
    utc: bool,

    /// Disable color output.
    #[clap(long = "no_color")]
    no_color: bool,

    /// Thread number. [default: Optimal number for performance.]
    #[clap(short, long = "thread-number", value_name = "NUMBER")]
    thread_number: Option<usize>,

    /// Prints statistics of event IDs.
    #[clap(short, long)]
    statistics: bool,

    /// Successful and failed logons summary.
    #[clap(short = 'L', long = "logon-summary")]
    logon_summary: bool,

    /// Tune alert levels.
    #[clap(
        long = "level-tuning",
        default_value = "./rules/config/level_tuning.txt",
        value_name = "LEVEL_TUNING_FILE"
    )]
    level_tuning: PathBuf,

    /// Quiet mode. Do not display the launch banner.
    #[clap(short, long)]
    quiet: bool,

    /// Quiet errors mode. Do not save error logs.
    #[clap(short = 'Q', long = "quiet-errors")]
    quiet_errors: bool,

    /// Create a list of pivot keywords.
    #[clap(short = 'p', long = "pivot-keywords-list")]
    pivot_keywords_list: bool,

    /// Prints the list of contributors.
    #[clap(long)]
    contributors: bool,
}

impl ConfigReader<'_> {
    pub fn new() -> Self {
        let app_str = "hayabusa 1.3.1";
        let custom_usage_and_opt = r#"
USAGE:
    hayabusa.exe -f file.evtx [OPTIONS]
    hayabusa.exe -d evtx-directory [OPTIONS]

OPTIONS:
        --European-time                     Output timestamp in European time format. (Ex: 22-02-2022 22:00:00.123 +02:00)
        --US-military-time                  Output timestamp in US military time format. (Ex: 02-22-2022 22:00:00.123 -06:00)
        --US-time                           Output timestamp in US time format. (Ex: 02-22-2022 10:00:00.123 PM -06:00)
        --all-tags                          Output all tags when saving to a CSV file        
    -C, --config <RULE_CONFIG_DIRECTORY>    Rule config folder [default: .\rules\config]
        --contributors                      Prints the list of contributors
    -d, --directory <DIRECTORY>             Directory of multiple .evtx files
    -D, --enable-deprecated-rules           Enable rules marked as deprecated
        --end-timeline <END_TIMELINE>       End time of the event logs to load. (Ex: "2022-02-22 23:59:59 +09:00")
    -f, --filepath <FILE_PATH>              File path to one .evtx file
    -F, --full-data                         Print all field information
    -h, --help                              Print help information
    -l, --live-analysis                     Analyze the local C:\Windows\System32\winevt\Logs folder (Windows Only. Administrator privileges required.)        
    -L, --logon-summary                     Successful and failed logons summary
        --level-tuning <LEVEL_TUNING_FILE>  Tune alert levels [default: .\rules\config\level_tuning.txt]
    -m, --min-level <LEVEL>                 Minimum level for rules [default: informational]
    -n, --enable-noisy-rules                Enable rules marked as noisy
        --no_color                          Disable color output
    -o, --output <CSV_TIMELINE>             Save the timeline in CSV format. (Ex: results.csv)
    -p, --pivot-keywords-list               Create a list of pivot keywords
    -q, --quiet                             Quiet mode. Do not display the launch banner
    -Q, --quiet-errors                      Quiet errors mode. Do not save error logs
    -r, --rules <RULE_DIRECTORY/RULE_FILE>  Rule directory or file [default: .\rules]
    -R, --hide-record-id                    Do not display EventRecordID number
        --rfc-2822                          Output timestamp in RFC 2822 format. (Ex: Fri, 22 Feb 2022 22:00:00 -0600)
        --rfc-3339                          Output timestamp in RFC 3339 format. (Ex: 2022-02-22 22:00:00.123456-06:00)
    -s, --statistics                        Prints statistics of event IDs
        --start-timeline <START_TIMELINE>   Start time of the event logs to load. (Ex: "2020-02-22 00:00:00 +09:00")
    -t, --thread-number <NUMBER>            Thread number. [default: Optimal number for performance.]
    -u, --update-rules                      Update to the latest rules in the hayabusa-rules github repository
    -U, --utc                               Output time in UTC format. [default: local time]
    -v, --verbose                           Output verbose information
    -V, --visualize-timeline                Output event frequency timeline
        --version                           Print version information"#;
        let build_cmd = Config::command().override_help(r#"hayabusa 1.3.1
Yamato Security (https://github.com/Yamato-Security/hayabusa) @SecurityYamato)
Hayabusa: Aiming to be the world's greatest Windows event log analysis tool!
USAGE:
    hayabusa.exe -f file.evtx [OPTIONS]
    hayabusa.exe -d evtx-directory [OPTIONS]
OPTIONS:
        --European-time                     Output timestamp in European time format. (Ex: 22-02-2022 22:00:00.123 +02:00)
        --US-military-time                  Output timestamp in US military time format. (Ex: 02-22-2022 22:00:00.123 -06:00)
        --US-time                           Output timestamp in US time format. (Ex: 02-22-2022 10:00:00.123 PM -06:00)
        --all-tags                          Output all tags when saving to a CSV file        
    -C, --config <RULE_CONFIG_DIRECTORY>    Rule config folder [default: .\rules\config]
        --contributors                      Prints the list of contributors
    -d, --directory <DIRECTORY>             Directory of multiple .evtx files
    -D, --enable-deprecated-rules           Enable rules marked as deprecated
        --end-timeline <END_TIMELINE>       End time of the event logs to load. (Ex: "2022-02-22 23:59:59 +09:00")
    -f, --filepath <FILE_PATH>              File path to one .evtx file
    -F, --full-data                         Print all field information
    -h, --help                              Print help information
    -l, --live-analysis                     Analyze the local C:\Windows\System32\winevt\Logs folder (Windows Only. Administrator privileges required.)        
    -L, --logon-summary                     Successful and failed logons summary
        --level-tuning <LEVEL_TUNING_FILE>  Tune alert levels [default: .\rules\config\level_tuning.txt]
    -m, --min-level <LEVEL>                 Minimum level for rules [default: informational]
    -n, --enable-noisy-rules                Enable rules marked as noisy
        --no_color                          Disable color output
    -o, --output <CSV_TIMELINE>             Save the timeline in CSV format. (Ex: results.csv)
    -p, --pivot-keywords-list               Create a list of pivot keywords
    -q, --quiet                             Quiet mode. Do not display the launch banner
    -Q, --quiet-errors                      Quiet errors mode. Do not save error logs
    -r, --rules <RULE_DIRECTORY/RULE_FILE>  Rule directory or file [default: .\rules]
    -R, --hide-record-id                    Do not display EventRecordID number
    --rfc-2822                          Output timestamp in RFC 2822 format. (Ex: Fri, 22 Feb 2022 22:00:00 -0600)
    --rfc-3339                          Output timestamp in RFC 3339 format. (Ex: 2022-02-22 22:00:00.123456-06:00)
    -s, --statistics                        Prints statistics of event IDs
    --start-timeline <START_TIMELINE>   Start time of the event logs to load. (Ex: "2020-02-22 00:00:00 +09:00")
    -t, --thread-number <NUMBER>            Thread number. [default: Optimal number for performance.]
    -u, --update-rules                      Update to the latest rules in the hayabusa-rules github repository
    -U, --utc                               Output time in UTC format. [default: local time]
    -v, --verbose                           Output verbose information
    -V, --visualize-timeline                Output event frequency timeline
        --version                           Print version information
    "#);
        let arg = build_cmd.clone().get_matches();
        let headless_help = format!("{}{}", app_str, custom_usage_and_opt);
        let folder_path = arg.value_of("config").unwrap().to_string();
        ConfigReader {
            args: arg,
            headless_help,
            folder_path,
            event_timeline_config: load_eventcode_info("config/statistics_event_info.txt"),
            target_eventids: load_target_ids("config/target_eventids.txt"),
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

    for line in lines.unwrap() {
        if line.is_empty() {
            continue;
        }
        ret.ids.insert(line);
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
        let start_time =
            if let Some(s_time) = CONFIG.read().unwrap().args.value_of("start-timeline") {
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
        let end_time = if let Some(e_time) = CONFIG.read().unwrap().args.value_of("end-timeline") {
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

    read_result.unwrap().into_iter().for_each(|line| {
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

    read_result.unwrap().into_iter().for_each(|line| {
        let map: Vec<&str> = line.split('.').collect();
        if map.len() != 2 {
            return;
        }

        //存在しなければ、keyを作成
        PIVOT_KEYWORD
            .write()
            .unwrap()
            .entry(map[0].to_string())
            .or_insert(PivotKeyword::new());

        PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut(&map[0].to_string())
            .unwrap()
            .fields
            .insert(map[1].to_string());
    });
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
    eventinfo: HashMap<String, EventInfo>,
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
    pub fn get_event_id(&self, eventid: &str) -> Option<&EventInfo> {
        self.eventinfo.get(eventid)
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

    // statistics_event_infoが読み込めなかったらエラーで終了とする。
    read_result.unwrap().into_iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }

        let empty = &"".to_string();
        let eventcode = line.get(0).unwrap_or(empty);
        let event_title = line.get(1).unwrap_or(empty);
        infodata = EventInfo {
            evttitle: event_title.to_string(),
        };
        config
            .eventinfo
            .insert(eventcode.to_owned(), infodata.to_owned());
    });
    config
}

#[cfg(test)]
mod tests {
    use crate::detections::configs;
    use chrono::{DateTime, Utc};

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
}

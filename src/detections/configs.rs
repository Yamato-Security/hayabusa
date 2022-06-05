use crate::detections::pivot::PivotKeyword;
use crate::detections::pivot::PIVOT_KEYWORD;
use crate::detections::print::AlertMessage;
use crate::detections::utils;
use chrono::{DateTime, Utc};
use clap::{App, AppSettings, Arg, ArgMatches};
use hashbrown::HashMap;
use hashbrown::HashSet;
use lazy_static::lazy_static;
use regex::Regex;
use std::sync::RwLock;
lazy_static! {
    pub static ref CONFIG: RwLock<ConfigReader> = RwLock::new(ConfigReader::new());
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
pub struct ConfigReader {
    pub args: ArgMatches<'static>,
    pub folder_path: String,
    pub event_timeline_config: EventInfoConfig,
    pub target_eventids: TargetEventIds,
}

impl Default for ConfigReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigReader {
    pub fn new() -> Self {
        let arg = build_app();
        let folder_path_str = arg.value_of("config").unwrap_or("rules/config").to_string();
        ConfigReader {
            args: arg,
            folder_path: folder_path_str,
            event_timeline_config: load_eventcode_info("config/statistics_event_info.txt"),
            target_eventids: load_target_ids("config/target_eventids.txt"),
        }
    }
}

fn build_app<'a>() -> ArgMatches<'a> {
    let program = std::env::args()
        .next()
        .and_then(|s| {
            std::path::PathBuf::from(s)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap();

    if is_test_mode() {
        return ArgMatches::default();
    }

    let usages = "-d, --directory [DIRECTORY] 'Directory of multiple .evtx files.'
    -f, --filepath [FILE_PATH] 'File path to one .evtx file.'
    -F, --full-data 'Print all field information.'
    -r, --rules [RULE_DIRECTORY/RULE_FILE] 'Rule directory or file (default: ./rules)'
    -C, --config [RULE_CONFIG_DIRECTORY] 'Rule config folder. (Default: ./rules/config)'
    -o, --output [CSV_TIMELINE] 'Save the timeline in CSV format. (Example: results.csv)'
    --all-tags 'Output all tags when saving to a CSV file.'
    -R, --display-record-id 'Display EventRecordID.'
    -v, --verbose 'Output verbose information.'
    -V, --visualize-timeline 'Output event frequency timeline.'
    -D, --enable-deprecated-rules 'Enable rules marked as deprecated.'
    -n, --enable-noisy-rules 'Enable rules marked as noisy.'
    -u, --update-rules 'Update to the latest rules in the hayabusa-rules github repository.'
    -m, --min-level [LEVEL] 'Minimum level for rules. (Default: informational)'
    -l, --live-analysis 'Analyze the local C:\\Windows\\System32\\winevt\\Logs folder (Windows Only. Administrator privileges required.)'
    --start-timeline [START_TIMELINE] 'Start time of the event logs to load. (Example: \"2018-11-28 12:00:00 +09:00\")'
    --end-timeline [END_TIMELINE] 'End time of the event logs to load. (Example: \"2021-11-28 12:00:00 +09:00\")'
    --rfc-2822 'Output date and time in RFC 2822 format. (Example: Mon, 07 Aug 2006 12:34:56 -0600)'
    --rfc-3339 'Output date and time in RFC 3339 format. (Example: 2006-08-07T12:34:56.485214 -06:00)'
    -U, --utc 'Output time in UTC format. (Default: local time)'
    --no-color 'Disable color output.'
    -t, --thread-number [NUMBER] 'Thread number. (Default: Optimal number for performance.)'
    -s, --statistics 'Prints statistics of event IDs.'
    -L, --logon-summary 'Successful and failed logons summary.'
    -q, --quiet 'Quiet mode. Do not display the launch banner.'
    -Q, --quiet-errors 'Quiet errors mode. Do not save error logs.'
    -p, --pivot-keywords-list 'Create a list of pivot keywords.'
    --contributors 'Prints the list of contributors.'";
    App::new(&program)
        .about("Hayabusa: Aiming to be the world's greatest Windows event log analysis tool!")
        .version("1.3.0")
        .author("Yamato Security (https://github.com/Yamato-Security/hayabusa) @SecurityYamato")
        .setting(AppSettings::VersionlessSubcommands)
        .arg(
            // TODO: When update claps to 3.x, these can write in usage texts...
            Arg::from_usage("--level-tuning=[LEVEL_TUNING_FILE] 'Adjust rule level.'")
                .default_value("./rules/config/level_tuning.txt"),
        )
        .usage(usages)
        .args_from_usage(usages)
        .get_matches()
}

fn is_test_mode() -> bool {
    for i in std::env::args() {
        if i == "--test" {
            return true;
        }
    }

    false
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

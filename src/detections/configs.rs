use crate::detections::utils;
use clap::{App, AppSettings, ArgMatches};
use lazy_static::lazy_static;
use std::collections::HashMap;
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
        return levelmap;
    };
}

#[derive(Clone)]
pub struct ConfigReader {
    pub args: ArgMatches<'static>,
    pub event_key_alias_config: EventKeyAliasConfig,
    pub event_timeline_config: EventInfoConfig,
}

impl ConfigReader {
    pub fn new() -> Self {
        ConfigReader {
            args: build_app(),
            event_key_alias_config: load_eventkey_alias("config/eventkey_alias.txt"),
            event_timeline_config: load_eventcode_info("config/timeline_event_info.txt"),
        }
    }
}

fn build_app<'a>() -> ArgMatches<'a> {
    let program = std::env::args()
        .nth(0)
        .and_then(|s| {
            std::path::PathBuf::from(s)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap();

    if is_test_mode() {
        return ArgMatches::default();
    }

    let usages = "-f --filepath=[FILEPATH] 'Event file path'
    --csv-timeline=[CSV_TIMELINE] 'Csv output timeline'
    --rfc-2822 'Output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600'
    --rfc-3339 'Output date and time in RFC 3339 format. Example: 2006-08-07T12:34:56.485214 -06:00'
    --verbose 'Output check information to target event file path and rule file.'
    -q 'Quiet Output Logo'
    -r --rules=[RULEDIRECTORY] 'using target of rule file directory'
    -L --level=[LEVEL] 'Specified execute rule level(default: INFORMATIONAL)'
    -u --utc 'Output time in UTC format(default: local time)'
    -d --directory=[DIRECTORY] 'Event log files directory'
    -s --statistics 'Prints statistics for event logs'
    -t --threadnum=[NUM] 'Thread number'
    --contributors 'Prints the list of contributors'";
    App::new(&program)
        .about("hayabusa. Aiming to be the world's greatest Windows event log analysis tool!")
        .version("1.0.0")
        .author("Author name Yamato-Security(https://github.com/Yamato-Security/hayabusa)")
        .setting(AppSettings::VersionlessSubcommands)
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

    return false;
}

#[derive(Debug, Clone)]
pub struct EventKeyAliasConfig {
    key_to_eventkey: HashMap<String, String>,
}

impl EventKeyAliasConfig {
    pub fn new() -> EventKeyAliasConfig {
        return EventKeyAliasConfig {
            key_to_eventkey: HashMap::new(),
        };
    }

    pub fn get_event_key(&self, alias: String) -> Option<&String> {
        return self.key_to_eventkey.get(&alias);
    }

    pub fn get_event_key_values(&self) -> Vec<(&String, &String)> {
        return self.key_to_eventkey.iter().map(|e| e).collect();
    }
}

fn load_eventkey_alias(path: &str) -> EventKeyAliasConfig {
    let mut config = EventKeyAliasConfig::new();

    let read_result = utils::read_csv(path);
    // eventkey_aliasが読み込めなかったらエラーで終了とする。
    read_result.unwrap().into_iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }

        let empty = &"".to_string();
        let alias = line.get(0).unwrap_or(empty);
        let event_key = line.get(1).unwrap_or(empty);
        if alias.len() == 0 || event_key.len() == 0 {
            return;
        }

        config
            .key_to_eventkey
            .insert(alias.to_owned(), event_key.to_owned());
    });
    return config;
}

#[derive(Debug, Clone)]
pub struct EventInfo {
    pub evttitle: String,
    pub detectflg: String,
    pub comment: String,
}

impl EventInfo {
    pub fn new() -> EventInfo {
        let evttitle = "Unknown".to_string();
        let detectflg = "".to_string();
        let comment = "".to_string();
        return EventInfo {
            evttitle,
            detectflg,
            comment,
        };
    }
}
#[derive(Debug, Clone)]
pub struct EventInfoConfig {
    eventinfo: HashMap<String, EventInfo>,
}

impl EventInfoConfig {
    pub fn new() -> EventInfoConfig {
        return EventInfoConfig {
            eventinfo: HashMap::new(),
        };
    }
    pub fn get_event_id(&self, eventid: &String) -> Option<&EventInfo> {
        return self.eventinfo.get(eventid);
    }

    pub fn get_event_info(&self) -> Vec<(&String, &EventInfo)> {
        return self.eventinfo.iter().map(|e| e).collect();
    }

    //    pub fn get_event_key_values(&self) -> Vec<(&String, &String)> {
    //        return self.timeline_eventcode_info.iter().map(|e| e).collect();
    //    }
}

fn load_eventcode_info(path: &str) -> EventInfoConfig {
    let mut infodata = EventInfo::new();
    let mut config = EventInfoConfig::new();
    let read_result = utils::read_csv(path);
    // timeline_event_infoが読み込めなかったらエラーで終了とする。
    read_result.unwrap().into_iter().for_each(|line| {
        if line.len() != 4 {
            return;
        }

        let empty = &"".to_string();
        let eventcode = line.get(0).unwrap_or(empty);
        let event_title = line.get(1).unwrap_or(empty);
        let detect_flg = line.get(2).unwrap_or(empty);
        let comment = line.get(3).unwrap_or(empty);
        infodata = EventInfo {
            evttitle: event_title.to_string(),
            detectflg: detect_flg.to_string(),
            comment: comment.to_string(),
        };
        config
            .eventinfo
            .insert(eventcode.to_owned(), infodata.to_owned());
    });
    return config;
}

#[cfg(test)]
mod tests {

    use crate::detections::configs;

    #[test]
    #[ignore]
    fn singleton_read_and_write() {
        let message =
            "EventKeyAliasConfig { key_to_eventkey: {\"EventID\": \"Event.System.EventID\"} }";
        configs::CONFIG.write().unwrap().event_key_alias_config =
            configs::load_eventkey_alias("test_files/config/eventkey_alias.txt");

        let display = format!(
            "{}",
            format_args!(
                "{:?}",
                configs::CONFIG.write().unwrap().event_key_alias_config
            )
        );
        assert_eq!(message, display);
    }
}

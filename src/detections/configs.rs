use crate::detections::utils;
use clap::{App, AppSettings, Arg, ArgMatches};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;
lazy_static! {
    pub static ref CONFIG: RwLock<ConfigReader> = RwLock::new(ConfigReader::new());
}

#[derive(Clone)]
pub struct ConfigReader {
    pub args: ArgMatches<'static>,
    pub event_key_alias_config: EventKeyAliasConfig,
}

impl ConfigReader {
    pub fn new() -> Self {
        ConfigReader {
            args: build_app(),
            event_key_alias_config: load_eventkey_alias("config/eventkey_alias.txt"),
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

    App::new(&program)
        .about("Yea! (Yamato Event Analyzer). Aiming to be the world's greatest Windows event log analysis tool!")
        .version("0.0.1")
        .author("Author name <author@example.com>")
        .setting(AppSettings::VersionlessSubcommands)
        .arg(Arg::from_usage("-f --filepath=[FILEPATH] 'event file path'"))
        .arg(Arg::from_usage("--attackhunt=[ATTACK_HUNT] 'Attack Hunt'"))
        .arg(Arg::from_usage("--csv-timeline=[CSV_TIMELINE] 'csv output timeline'"))
        .arg(Arg::from_usage("--human-readable-timeline=[HUMAN_READABLE_TIMELINE] 'human readable timeline'"))
        .arg(Arg::from_usage("--rfc-2822 'output date and time in RFC 2822 format. Example: Mon, 07 Aug 2006 12:34:56 -0600'"))
        .arg(Arg::from_usage("-l --lang=[LANG] 'output language'"))
        .arg(Arg::from_usage("-u --utc 'output time in UTC format(default: local time)'"))
        .arg(Arg::from_usage("-d --directory=[DIRECTORY] 'event log files directory'"))
        .arg(Arg::from_usage("-s --statistics 'event statistics'"))
        .arg(Arg::from_usage("-t --threadnum=[NUM] 'thread number'"))
        .arg(Arg::from_usage("-tl --timeline 'show event log timeline'"))
        .arg(Arg::from_usage("--credits 'Zachary Mathis, Akira Nishikawa'"))
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

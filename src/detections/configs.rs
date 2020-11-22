use crate::detections::utils;
use clap::{App, AppSettings, Arg, ArgMatches};
use std::collections::HashMap;
use std::sync::Once;
#[derive(Clone)]
pub struct SingletonReader {
    pub args: ArgMatches<'static>,
    pub event_key_alias_config: EventKeyAliasConfig,
}

pub fn singleton() -> Box<SingletonReader> {
    static mut SINGLETON: Option<Box<SingletonReader>> = Option::None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonReader {
                args: build_app().get_matches(),
                event_key_alias_config: load_eventkey_alias(),
            };

            SINGLETON = Some(Box::new(singleton));
        });

        return SINGLETON.clone().unwrap();
    }
}

fn build_app() -> clap::App<'static, 'static> {
    let program = std::env::args()
        .nth(0)
        .and_then(|s| {
            std::path::PathBuf::from(s)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap();

    App::new(program)
        .about("Yea! (Yamato Event Analyzer). Aiming to be the world's greatest Windows event log analysis tool!")
        .version("0.0.1")
        .author("Author name <author@example.com>")
        .setting(AppSettings::VersionlessSubcommands)
        .arg(Arg::from_usage("-f --filepath=[FILEPATH] 'event file path'"))
        .arg(Arg::from_usage("--attackhunt=[ATTACK_HUNT] 'Attack Hunt'"))
        .arg(Arg::from_usage("--csv-timeline=[CSV_TIMELINE] 'csv output timeline'"))
        .arg(Arg::from_usage("--human-readable-timeline=[HUMAN_READABLE_TIMELINE] 'human readable timeline'"))
        .arg(Arg::from_usage("-l --lang=[LANG] 'output language'"))
        .arg(Arg::from_usage("-t --timezone=[TIMEZONE] 'timezone setting'"))
        .arg(Arg::from_usage("-d --directory 'event log files directory'"))
        .arg(Arg::from_usage("-s --statistics 'event statistics'"))
        .arg(Arg::from_usage("-u --update 'signature update'"))
        .arg(Arg::from_usage("--credits 'Zachary Mathis, Akira Nishikawa'"))
}

#[derive(Clone)]
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
}

fn load_eventkey_alias() -> EventKeyAliasConfig {
    let mut config = EventKeyAliasConfig::new();

    let read_result = utils::read_csv("config/eventkey_alias.txt");
    // eventkey_alisasが読み込めなかったらエラーで終了とする。
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

extern crate clap;
extern crate serde;

use clap::{App, AppSettings, Arg};
use evtx::EvtxParser;
use quick_xml::de::DeError;
use std::{fs, path::PathBuf, process};
use yamato_event_analyzer::detections::detection;
use yamato_event_analyzer::toml;
use yamato_event_analyzer::omikuji::Omikuji;

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
        .arg(Arg::from_usage("-o --omikuji 'output with omikuji'"))
        .arg(Arg::from_usage("--credits 'Zachary Mathis, Akira Nishikawa'"))
}

fn main() -> Result<(), DeError> {
    let args = build_app().get_matches();
    let filepath: Option<&str> = args.value_of("filepath");

    if let Some(filepath) = filepath {
        parse_file(filepath);
    }
    output_with_omikuji(Omikuji::DAIKICHI);
    Ok(())
}

fn parse_file(filepath: &str) {
    let fp = PathBuf::from(filepath);
    let parser = match EvtxParser::from_path(fp) {
        Ok(pointer) => pointer,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    let mut detection = detection::Detection::new();
    &detection.start(parser);
}

fn output_with_omikuji(omikuji: Omikuji) {
    let fp = &format!("art/omikuji/{}", omikuji.get_file_name());
    let content = fs::read_to_string(fp).unwrap();
    println!("{}", content);
}

use std::fs::File;
use std::io::prelude::*;
use std::sync::Once;
use clap::ArgMatches;

#[derive(Clone)]
pub struct SingletonReader {
    pub regex: Vec<Vec<String>>,
    pub whitelist: Vec<Vec<String>>,
    pub args: Config<'static>,
}

#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub filepath: Option<&'a str>,
    pub attackhunt: Option<&'a str>,
    pub csv_timeline: Option<&'a str>,
    pub human_readable_timeline: Option<&'a str>,
    pub lang: Option<&'a str>,
    pub timezone: Option<&'a str>,
}

impl<'a> Config<'a> {
    fn new(args: ArgMatches<'a>) -> Self {
        Config {
            filepath: args.value_of("filepath"),
            attackhunt: args.value_of("attackhunt"),
            csv_timeline: args.value_of("csv-timeline"),
            human_readable_timeline: args.value_of("human-readable-timeline"),
            lang: args.value_of("lang"),
            timezone: args.value_of("timezone"),
        }
    }
}

pub fn init_singleton(args: ArgMatches<'static>) -> Box<SingletonReader> {
    static mut SINGLETON: Option<Box<SingletonReader>> = Option::None;
    static ONCE: Once = Once::new();
    static CONFIG: Config = Config::new(args);

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonReader {
                regex: read_csv("regexes.txt"),
                whitelist: read_csv("whitelist.txt"),
                args: CONFIG,
            };

            SINGLETON = Some(Box::new(singleton));
        });

        return SINGLETON.clone().unwrap();
    }
}

pub fn singleton() -> Box<SingletonReader> {
    static mut SINGLETON: Option<Box<SingletonReader>> = Option::None;
    unsafe {
        return SINGLETON.clone().unwrap();
    }
}

fn read_csv(filename: &str) -> Vec<Vec<String>> {
    let mut f = File::open(filename).expect("file not found!!!");
    let mut contents: String = String::new();
    let mut ret = vec![];
    if f.read_to_string(&mut contents).is_err() {
        return ret;
    }

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    return ret;
}

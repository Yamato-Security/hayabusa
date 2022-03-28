use crate::detections::configs;
use crate::detections::print::AlertMessage;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::QUIET_ERRORS_FLAG;
use crate::detections::utils;
use hashbrown::HashMap;
use hashbrown::HashSet;
use lazy_static::lazy_static;
use regex::Regex;
use std::fs::File;
use std::io::BufWriter;
use std::io::{BufRead, BufReader};

lazy_static! {
    static ref IDS_REGEX: Regex =
        Regex::new(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$").unwrap();
    pub static ref FILTER_REGEX: HashMap<String, DataFilterRule> = load_record_filters();
}

#[derive(Debug)]
pub struct DataFilterRule {
    pub regex_rule: Regex,
    pub replace_str: String,
}

#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub no_use_rule: HashSet<String>,
}

pub fn exclude_ids() -> RuleExclude {
    let mut exclude_ids = RuleExclude {
        no_use_rule: HashSet::new(),
    };

    if !configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("enable-noisy-rules")
    {
        exclude_ids.insert_ids("./rules/config/noisy_rules.txt");
    };

    exclude_ids.insert_ids("./rules/config/exclude_rules.txt");

    exclude_ids
}

impl RuleExclude {
    fn insert_ids(&mut self, filename: &str) {
        let f = File::open(filename);
        if f.is_err() {
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::warn(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &format!("{} does not exist", filename),
                )
                .ok();
            }
            if !*QUIET_ERRORS_FLAG {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("{} does not exist", filename));
            }
            return;
        }
        let reader = BufReader::new(f.unwrap());
        for v in reader.lines() {
            let v = v.unwrap().split('#').collect::<Vec<&str>>()[0]
                .trim()
                .to_string();
            if v.is_empty() || !IDS_REGEX.is_match(&v) {
                // 空行は無視する。IDの検証
                continue;
            }
            self.no_use_rule.insert(v);
        }
    }
}

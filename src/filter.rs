use crate::detections::configs;
use crate::detections::print::AlertMessage;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::QUIET_ERRORS_FLAG;
use hashbrown::HashSet;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub struct DataFilterRule {
    pub regex_rule: Regex,
    pub replace_str: String,
}

#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub no_use_rule: HashSet<String>,
}

impl RuleExclude {
    pub fn default() -> RuleExclude {
        RuleExclude {
            no_use_rule: HashSet::new(),
        }
    }
}

pub fn exclude_ids() -> RuleExclude {
    let mut exclude_ids = RuleExclude::default();

    if !configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("enable-noisy-rules")
    {
        exclude_ids.insert_ids(&format!(
            "{}/noisy_rules.txt",
            configs::CONFIG.read().unwrap().folder_path
        ));
    };

    exclude_ids.insert_ids(&format!(
        "{}/exclude_rules.txt",
        configs::CONFIG.read().unwrap().folder_path
    ));

    exclude_ids
}

impl RuleExclude {
    fn insert_ids(&mut self, filename: &str) {
        let f = File::open(filename);
        if f.is_err() {
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::warn(&format!("{} does not exist", filename)).ok();
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
            if v.is_empty() || !configs::IDS_REGEX.is_match(&v) {
                // 空行は無視する。IDの検証
                continue;
            }
            self.no_use_rule.insert(v);
        }
    }
}

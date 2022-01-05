use crate::detections::configs;
use crate::detections::print::AlertMessage;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::QUIET_ERRORS_FLAG;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufWriter;
use std::io::{BufRead, BufReader};

lazy_static! {
    static ref IDS_REGEX: Regex =
        Regex::new(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$").unwrap();
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
        exclude_ids.insert_ids("config/noisy-rules.txt");
    };

    exclude_ids.insert_ids("config/exclude-rules.txt");

    return exclude_ids;
}

impl RuleExclude {
    fn insert_ids(&mut self, filename: &str) {
        let f = File::open(filename);
        if f.is_err() {
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::alert(
                    &mut BufWriter::new(std::io::stderr().lock()),
                    &format!("[ERROR] {}", f.as_ref().unwrap_err()),
                )
                .ok();
            }
            if !*QUIET_ERRORS_FLAG {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {}", f.as_ref().unwrap_err()));
            }
            return ();
        }
        let reader = BufReader::new(f.unwrap());
        for v in reader.lines() {
            let v = v.unwrap().split("#").collect::<Vec<&str>>()[0]
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

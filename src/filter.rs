use crate::detections::configs::{self, StoredStatic};
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use hashbrown::HashMap;
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
    pub no_use_rule: HashMap<String, String>,
}

impl RuleExclude {
    pub fn new() -> RuleExclude {
        RuleExclude {
            no_use_rule: HashMap::new(),
        }
    }
}

impl Default for RuleExclude {
    fn default() -> Self {
        Self::new()
    }
}

pub fn exclude_ids(stored_static: &StoredStatic) -> RuleExclude {
    let mut exclude_ids = RuleExclude::default();
    exclude_ids.insert_ids(
        &format!(
            "{}/noisy_rules.txt",
            stored_static.config_path.as_path().display(),
        ),
        stored_static,
    );

    exclude_ids.insert_ids(
        &format!(
            "{}/exclude_rules.txt",
            stored_static.config_path.as_path().display(),
        ),
        stored_static,
    );

    exclude_ids
}

impl RuleExclude {
    fn insert_ids(&mut self, filename: &str, stored_static: &StoredStatic) {
        let f = File::open(filename);
        if f.is_err() {
            if stored_static.verbose_flag {
                AlertMessage::warn(&format!("{filename} does not exist")).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("{filename} does not exist"));
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
            self.no_use_rule.insert(v, filename.to_owned());
        }
    }
}

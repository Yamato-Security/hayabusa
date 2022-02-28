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

fn load_record_filters() -> HashMap<String, DataFilterRule> {
    let file_path = "./rules/config/regex/record_data_filter.txt";
    let read_result = utils::read_csv(file_path);
    let mut ret = HashMap::new();
    if read_result.is_err() {
        if configs::CONFIG.read().unwrap().args.is_present("verbose") {
            AlertMessage::warn(
                &mut BufWriter::new(std::io::stderr().lock()),
                &format!("{} does not exist", file_path),
            )
            .ok();
        }
        if !*QUIET_ERRORS_FLAG {
            ERROR_LOG_STACK
                .lock()
                .unwrap()
                .push(format!("{} does not exist", file_path));
        }
        return HashMap::default();
    }
    read_result.unwrap().into_iter().for_each(|line| {
        if line.len() != 3 {
            return;
        }

        let empty = &"".to_string();
        let key = line.get(0).unwrap_or(empty).trim();
        let regex_str = line.get(1).unwrap_or(empty).trim();
        let replaced_str = line.get(2).unwrap_or(empty).trim();
        if key.len() == 0 || regex_str.len() == 0 {
            return;
        }

        let regex_rule: Option<Regex> = match Regex::new(regex_str) {
            Ok(regex) => Some(regex),
            Err(_err) => {
                let errmsg = format!("failed to read regex filter in record_data_filter.txt");
                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    AlertMessage::alert(&mut BufWriter::new(std::io::stderr().lock()), &errmsg)
                        .ok();
                }
                if !*QUIET_ERRORS_FLAG {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[ERROR] {}", errmsg));
                }
                None
            }
        };

        if regex_rule.is_none() {
            return;
        }
        ret.insert(
            key.to_string(),
            DataFilterRule {
                regex_rule: regex_rule.unwrap(),
                replace_str: replaced_str.to_string(),
            },
        );
    });
    return ret;
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

    return exclude_ids;
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
            return ();
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

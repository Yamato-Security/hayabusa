use crate::detections::configs;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub no_use_rule: HashSet<String>,
}

pub fn exclude_ids() -> RuleExclude {
    let mut exclude_ids = RuleExclude {
        no_use_rule: HashSet::new(),
    };

    let f = match File::open("config/exclude-rules.txt") {
        Ok(file) => file,
        Err(_) => panic!("config/exclude-rules.txt does not exist"),
    };
    let reader = BufReader::new(f);
    for v in reader.lines() {
        let v = v.unwrap().split("#").collect::<Vec<&str>>()[0].trim().to_string();
        if v.is_empty() {
            // 空行は無視する。
            continue;
        }
        exclude_ids.no_use_rule.insert(v);
    }

    if !configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("enable-noisy-rules")
    {
        let f = match File::open("config/noisy-rules.txt") {
            Ok(file) => file,
            Err(_) => panic!("config/noisy-rules.txt does not exist"),
        };
        let reader = BufReader::new(f);
        for v in reader.lines() {
            let v = v.unwrap().split("#").collect::<Vec<&str>>()[0].trim().to_string();
            if v.is_empty() {
                // 空行は無視する。
                continue;
            }
            exclude_ids.no_use_rule.insert(v);
        }
    };

    return exclude_ids;
}

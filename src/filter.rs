use crate::detections::configs;
use std::collections::HashSet;
use std::fs;

#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub no_use_rule: HashSet<String>,
}

pub fn exclude_ids() -> RuleExclude {
    let mut ids;
    match fs::read("config/exclude-rules.txt") {
        Ok(file) => ids = String::from_utf8(file).unwrap(),
        Err(_) => panic!("config/exclude-rules.txt does not exist"),
    };

    if !configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("show-noisyalerts")
    {
        ids += "\n"; // 改行を入れないとexclude-rulesの一番最後の行とnoisy-rules.txtの一番最初の行が一行にまとめられてしまう。
        match fs::read("config/noisy-rules.txt") {
            Ok(file) => ids += &String::from_utf8(file).unwrap(),
            Err(_) => panic!("config/noisy-rules.txt does not exist"),
        };
    }

    let mut exclude_ids = RuleExclude {
        no_use_rule: HashSet::new(),
    };

    for v in ids.split_whitespace() {
        let v = v.to_string();
        if v.is_empty() {
            // 空行は無視する。
            continue;
        }
        exclude_ids.no_use_rule.insert(v);
    }

    return exclude_ids;
}

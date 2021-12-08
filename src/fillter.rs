use crate::detections::configs;
use std::collections::HashSet;
use std::fs;

#[derive(Clone, Debug)]
pub struct RuleFill {
    pub no_use_rule: HashSet<String>,
}

pub fn exclude_ids() -> RuleFill {
    let mut ids = String::from_utf8(fs::read("config/exclude-rules.txt").unwrap()).unwrap();
    if !configs::CONFIG
        .read()
        .unwrap()
        .args
        .is_present("show-noisyalerts")
    {
        ids += "\n"; // 改行を入れないとexclude-rulesの一番最後の行とnoisy-rules.txtの一番最後の行が一行にまとめられてしまう。
        ids += &String::from_utf8(fs::read("config/noisy-rules.txt").unwrap()).unwrap();
    }

    let mut fill_ids = RuleFill {
        no_use_rule: HashSet::new(),
    };

    for v in ids.split_whitespace() {
        let v = v.to_string();
        if v.is_empty() {
            // 空行は無視する。
            continue;
        }
        fill_ids.no_use_rule.insert(v);
    }

    return fill_ids;
}

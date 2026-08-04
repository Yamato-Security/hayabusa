use nested::Nested;
use regex::Regex;
use yaml_rust2::Yaml;

use super::LeafMatcher;
use crate::detections::{detection::EvtxRecordInfo, utils};

/// Class that checks whether the value has at least the specified number of characters.
pub struct MinlengthMatcher {
    pub(super) min_len: i64,
}

impl MinlengthMatcher {
    pub fn new() -> MinlengthMatcher {
        MinlengthMatcher { min_len: 0 }
    }
}

impl LeafMatcher for MinlengthMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        key_list.get(1).unwrap() == "min_length"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let min_length = select_value.as_i64();
        if min_length.is_none() {
            let errmsg = format!(
                "min_length value should be an integer. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        self.min_len = min_length.unwrap();
        Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => s.len() as i64 >= self.min_len,
            None => false,
        }
    }
}

/// Class representing the logic of reading a file containing a list of regular expressions and comparing.
/// Similar processing was implemented in part of the check_cmd method of DeepBlueCLI.
pub struct RegexesFileMatcher {
    pub(super) regexes: Vec<Regex>,
}

impl RegexesFileMatcher {
    pub fn new() -> RegexesFileMatcher {
        RegexesFileMatcher { regexes: vec![] }
    }
}

impl LeafMatcher for RegexesFileMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        key_list.get(1).unwrap() == "regexes"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(_) | Yaml::Integer(_) | Yaml::Real(_) => select_value.as_str(),
            _ => None,
        };
        if value.is_none() {
            let errmsg = format!(
                "regexes value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        let regexes_strs = match utils::read_txt(value.unwrap()) {
            Ok(v) => v,
            Err(e) => return Err(vec![e]),
        };
        self.regexes = regexes_strs
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => utils::check_regex(s, &self.regexes),
            None => false,
        }
    }
}

/// Represents the logic to detect when the value matches a string enumerated in a file.
/// Similar processing was implemented in part of the check_cmd method of DeepBlueCLI.
pub struct AllowlistFileMatcher {
    pub(super) regexes: Vec<Regex>,
}

impl AllowlistFileMatcher {
    pub fn new() -> AllowlistFileMatcher {
        AllowlistFileMatcher { regexes: vec![] }
    }
}

impl LeafMatcher for AllowlistFileMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        key_list.get(1).unwrap() == "allowlist"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Some(s.to_owned()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(r) => Some(r.to_owned()),
            _ => None,
        };
        if value.is_none() {
            let errmsg = format!(
                "allowlist value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        let regexes_strs = match utils::read_txt(&value.unwrap()) {
            Ok(v) => v,
            Err(e) => return Err(vec![e]),
        };
        self.regexes = regexes_strs
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => !utils::check_allowlist(s, &self.regexes),
            None => true,
        }
    }
}

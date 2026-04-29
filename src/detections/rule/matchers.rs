use cidr_utils::cidr::IpCidr;
use cidr_utils::cidr::errors::NetworkParseError;
use nested::Nested;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use std::{cmp::Ordering, collections::HashMap};
use yaml_rust2::Yaml;

use crate::detections::configs::WINDASH_CHARACTERS;
use crate::detections::rule::base64_match::{
    convert_to_base64_str, to_base64_utf8, to_base64_utf16be, to_base64_utf16le_with_bom,
};
use crate::detections::rule::fast_match::{
    FastMatch, check_fast_match, convert_to_fast_match, create_fast_match,
};
use crate::detections::{detection::EvtxRecordInfo, utils};
use downcast_rs::Downcast;

// Represents the logic for comparing EventLog values at leaf nodes.
// A class implementing this trait exists for each comparison logic, such as regex matching and character count limits.
//
// When creating a new class that implements LeafMatcher,
// add an instance of the newly created class to the return value array of the get_matchers method of LeafSelectionNode.
pub trait LeafMatcher: Downcast + Send + Sync {
    /// Determines whether this is a LeafMatcher matching the specified key_list.
    fn is_target_key(&self, key_list: &Nested<String>) -> bool;

    /// Determines whether the JSON-format data specified as an argument matches.
    /// Windows Event Log is converted to JSON format in main.rs, and that JSON-format Windows event log data comes here.
    /// For example, for logic that matches using regex, write the regex matching process here.
    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool;

    /// Describe the initialization logic here.
    /// If parsing from the rule file fails due to an incorrect rule file format, etc., return an error in the Result return type.
    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>>;
}
downcast_rs::impl_downcast!(LeafMatcher);

/// Class that checks whether the value has at least the specified number of characters.
pub struct MinlengthMatcher {
    min_len: i64,
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
    regexes: Vec<Regex>,
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
    regexes: Vec<Regex>,
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

/// Default match class.
/// Handling wildcards and pipes.
pub struct DefaultMatcher {
    re: Option<Vec<Regex>>,
    fast_match: Option<Vec<FastMatch>>,
    pipes: Vec<PipeElement>,
    key_list: Nested<String>,
}

impl DefaultMatcher {
    pub fn new() -> DefaultMatcher {
        DefaultMatcher {
            re: None,
            fast_match: None,
            pipes: Vec::new(),
            key_list: Nested::<String>::new(),
        }
    }

    pub fn get_eqfield_key(&self) -> Option<&String> {
        let pipe = self.pipes.first()?;
        pipe.get_eqfield()
    }

    /// Determines whether this matcher matches the given regex.
    fn is_regex_fullmatch(&self, value: &str) -> bool {
        self.re.as_ref().unwrap().iter().any(|x| x.is_match(value))
    }

    /// Converts the field name in Hayabusa rule files and the pipe specified after it to a regex-format string.
    /// Processing to convert wildcard strings to regex is also implemented in this method. Specify the wildcard string in pattern and PipeElement::Wildcard in pipes.
    fn from_pattern_to_regex_str(pattern: String, pipes: &[PipeElement]) -> String {
        // Process the pattern with Pipe.
        pipes
            .iter()
            .fold(pattern, |acc, pipe| pipe.pipe_pattern(acc))
    }
}

impl LeafMatcher for DefaultMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() <= 1 {
            return true;
        }

        key_list.get(1).unwrap() == "value"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let mut tmp_key_list = Nested::<String>::new();
        tmp_key_list.extend(key_list.iter());
        self.key_list = tmp_key_list;
        if select_value.is_null() {
            return Ok(());
        }

        // patternをパースする
        let yaml_value = match select_value {
            Yaml::Boolean(b) => Some(b.to_string()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(r) => Some(r.to_string()),
            Yaml::String(s) => Some(s.to_owned()),
            _ => None,
        };
        if yaml_value.is_none() {
            let errmsg = format!(
                "An unknown error occured. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }
        let mut pattern = Vec::new();
        pattern.push(yaml_value.unwrap());
        // Pipeが指定されていればパースする
        let emp = String::default();
        // 一つ目はただのキーで、2つめ以降がpipe

        let mut keys_all: Vec<&str> = key_list.get(0).unwrap_or(&emp).split('|').collect(); // key_list cannot be empty.

        // Correspondence between all and allOnly.
        let mut change_map: HashMap<&str, &str> = HashMap::new();
        change_map.insert("all", "allOnly");
        change_map.insert("i", "reignorecase");
        change_map.insert("m", "remultiline");
        change_map.insert("s", "resingleline");

        // Detect the case where | is at the beginning, and change all -> allOnly.
        if keys_all[0].is_empty() && keys_all.len() == 2 && keys_all[1] == "all" {
            keys_all[1] = change_map["all"];
        }
        if keys_all.len() >= 3 {
            if keys_all[1] == "re" {
                if keys_all[2] == "i" {
                    keys_all[2] = change_map["i"];
                } else if keys_all[2] == "m" {
                    keys_all[2] = change_map["m"];
                } else if keys_all[2] == "s" {
                    keys_all[2] = change_map["s"];
                }
                keys_all.remove(1);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "endswith" {
                keys_all[1] = "fieldrefendswith";
                keys_all.remove(2);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "startswith" {
                keys_all[1] = "fieldrefstartswith";
                keys_all.remove(2);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "contains" {
                keys_all[1] = "fieldrefcontains";
                keys_all.remove(2);
            }
        }

        let keys_without_head = &keys_all[1..];

        let mut err_msges = vec![];
        for key in keys_without_head.iter() {
            let pipe_element = PipeElement::new(key, &pattern[0], key_list);
            match pipe_element {
                Ok(element) => {
                    self.pipes.push(element);
                }
                Err(e) => {
                    err_msges.push(e);
                }
            }
        }
        if !err_msges.is_empty() {
            return Err(err_msges);
        }
        let n = self.pipes.len();
        if n == 0 {
            // Case without pipe.
            self.fast_match = convert_to_fast_match(&pattern[0], true);
        } else if n == 1 {
            // Case with pipe.
            self.fast_match = create_fast_match(&self.pipes, &pattern);
        } else if n == 2 {
            if self.pipes[0] == PipeElement::Base64 && self.pipes[1] == PipeElement::Contains {
                self.fast_match = convert_to_fast_match(
                    &format!("*{}*", &to_base64_utf8(pattern[0].as_str())),
                    true,
                );
            } else if self.pipes[0] == PipeElement::Base64offset
                && self.pipes[1] == PipeElement::Contains
            {
                self.fast_match = convert_to_base64_str(None, pattern[0].as_str(), &mut err_msges);
            } else if self.pipes[0] == PipeElement::Contains && self.pipes[1] == PipeElement::All
            // For |contains|all, it has been designated as AndSelectionNode in a prior branch, so treat it as contains only here.
            {
                self.fast_match = convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true);
            } else if self.pipes[0] == PipeElement::Contains
                && self.pipes[1] == PipeElement::Windash
            {
                // For |contains|windash
                let mut fastmatches =
                    convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true)
                        .unwrap_or_default();
                let windash_chars = WINDASH_CHARACTERS.as_slice();
                fastmatches.extend(
                    convert_to_fast_match(
                        format!("*{}*", pattern[0].replacen(windash_chars, "/", 1)).as_str(),
                        true,
                    )
                    .unwrap_or_default(),
                );
                if !fastmatches.is_empty() {
                    self.fast_match = Some(fastmatches);
                }
            } else if self.pipes[1] == PipeElement::Cased {
                if self.pipes[0] == PipeElement::Startswith {
                    self.fast_match = convert_to_fast_match(&format!("{}*", pattern[0]), false);
                } else if self.pipes[0] == PipeElement::Endswith {
                    self.fast_match = convert_to_fast_match(&format!("*{}", pattern[0]), false);
                } else if self.pipes[0] == PipeElement::Contains {
                    self.fast_match = convert_to_fast_match(&format!("*{}*", pattern[0]), false);
                }
            }
        } else if n == 3 {
            if self.pipes.contains(&PipeElement::Contains)
                && self.pipes.contains(&PipeElement::All)
                && self.pipes.contains(&PipeElement::Windash)
            // For |contains|all|windash, it has been designated as AndSelectionNode in a prior branch, so treat it as contains and windash only here.
            {
                let mut fastmatches =
                    convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true)
                        .unwrap_or_default();
                let windash_chars = WINDASH_CHARACTERS.as_slice();
                pattern.push(pattern[0].replacen(windash_chars, "/", 1));
                fastmatches.extend(
                    convert_to_fast_match(
                        format!("*{}*", pattern[0].replacen(windash_chars, "/", 1)).as_str(),
                        true,
                    )
                    .unwrap_or_default(),
                );
                if !fastmatches.is_empty() {
                    self.fast_match = Some(fastmatches);
                }
            } else if (self.pipes[0] == PipeElement::Utf16
                || self.pipes[0] == PipeElement::Utf16Le
                || self.pipes[0] == PipeElement::Utf16Be
                || self.pipes[0] == PipeElement::Wide)
                && (self.pipes[1] == PipeElement::Base64offset
                    || self.pipes[1] == PipeElement::Base64)
                && self.pipes[2] == PipeElement::Contains
            {
                if self.pipes[1] == PipeElement::Base64offset {
                    let encode = &self.pipes[0];
                    let org_str = pattern[0].as_str();
                    if encode == &PipeElement::Utf16 {
                        let utf16_le_match = convert_to_base64_str(
                            Some(&PipeElement::Utf16Le),
                            org_str,
                            &mut err_msges,
                        );
                        let utf16_be_match = convert_to_base64_str(
                            Some(&PipeElement::Utf16Be),
                            org_str,
                            &mut err_msges,
                        );
                        if let Some(utf16_le_match) = utf16_le_match
                            && let Some(utf16_be_match) = utf16_be_match
                        {
                            let mut matches = utf16_le_match;
                            matches.extend(utf16_be_match);
                            self.fast_match = Some(matches);
                        }
                    } else {
                        self.fast_match =
                            convert_to_base64_str(Some(encode), org_str, &mut err_msges);
                    }
                } else if self.pipes[1] == PipeElement::Base64 {
                    let encode = &self.pipes[0];
                    let org_str = pattern[0].as_str();
                    match encode {
                        PipeElement::Utf16 => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16le_with_bom(org_str, true)),
                                true,
                            );
                        }
                        PipeElement::Utf16Le | PipeElement::Wide => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16le_with_bom(org_str, false)),
                                true,
                            );
                        }
                        PipeElement::Utf16Be => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16be(org_str)),
                                true,
                            );
                        }
                        _ => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf8(org_str)),
                                true,
                            );
                        }
                    }
                }
            }
        } else {
            let errmsg = format!(
                "Multiple pipe elements cannot be used. key:{}",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }
        if self.fast_match.is_some()
            && matches!(
                &self.fast_match.as_ref().unwrap()[0],
                FastMatch::Exact(_) | FastMatch::Contains(_)
            )
            && !self.key_list.is_empty()
        {
            // Regex is not needed when replaced with FastMatch::Exact/Contains search.
            return Ok(());
        }
        let is_eqfield = self.pipes.iter().any(|pipe_element| {
            matches!(
                pipe_element,
                PipeElement::EqualsField(_)
                    | PipeElement::Endswithfield(_)
                    | PipeElement::FieldRef(_)
                    | PipeElement::FieldRefEndswith(_)
                    | PipeElement::FieldRefStartswith(_)
                    | PipeElement::FieldRefContains(_)
            )
        });
        if !is_eqfield {
            // If it is not a regex, it represents a wildcard.
            // Wildcards are matched using regex, so internally add a Pipe that converts wildcards to regex.
            let is_re = self.pipes.iter().any(|pipe_element| {
                matches!(
                    pipe_element,
                    PipeElement::Re
                        | PipeElement::ReIgnoreCase
                        | PipeElement::ReMultiLine
                        | PipeElement::ReSingleLine
                )
            });
            if !is_re {
                self.pipes.push(PipeElement::Wildcard);
            }

            let mut re_result_vec = vec![];
            for p in pattern {
                let pattern = DefaultMatcher::from_pattern_to_regex_str(p, &self.pipes);
                // Convert the pattern processed by Pipe to regex.
                if let Ok(re_result) = Regex::new(&pattern) {
                    re_result_vec.push(re_result);
                } else {
                    let errmsg = format!(
                        "Cannot parse regex. [regex:{pattern}, key:{}]",
                        utils::concat_selection_key(key_list)
                    );
                    return Err(vec![errmsg]);
                }
            }
            self.re = Some(re_result_vec);
        }
        Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        let pipe: &PipeElement = self.pipes.first().unwrap_or(&PipeElement::Wildcard);
        let match_result = match pipe {
            PipeElement::Cidr(ip_result) => match ip_result {
                Ok(matcher_ip) => {
                    let val = String::default();
                    let event_value_str = event_value.unwrap_or(&val);
                    let event_ip = IpAddr::from_str(event_value_str);
                    match event_ip {
                        Ok(target_ip) => Some(matcher_ip.contains(&target_ip)),
                        Err(_) => Some(false), // For formats other than IP addresses.
                    }
                }
                Err(_) => Some(false), // For formats other than IP addresses.
            },
            PipeElement::Exists(..)
            | PipeElement::EqualsField(_)
            | PipeElement::FieldRef(_)
            | PipeElement::FieldRefStartswith(_)
            | PipeElement::FieldRefContains(_)
            | PipeElement::FieldRefEndswith(_)
            | PipeElement::Endswithfield(_) => Some(pipe.is_eqfield_match(event_value, recinfo)),
            PipeElement::Gt(_) | PipeElement::Lt(_) | PipeElement::Gte(_) | PipeElement::Lte(_) => {
                let val = String::default();
                let event_val_str = event_value.unwrap_or(&val);
                let event_val_int = event_val_str.parse::<usize>();
                match event_val_int {
                    Ok(event_val) => {
                        let cmp_result = match pipe {
                            PipeElement::Gt(n) => event_val > *n,
                            PipeElement::Lt(n) => event_val < *n,
                            PipeElement::Gte(n) => event_val >= *n,
                            PipeElement::Lte(n) => event_val <= *n,
                            _ => false,
                        };
                        Some(cmp_result)
                    }
                    Err(_) => Some(false), // For non-numeric values.
                }
            }
            _ => None,
        };
        if let Some(result) = match_result {
            return result;
        }

        // If null is set in yaml.
        // If keylist is empty (== JSON grep search), ignore.
        if self.key_list.is_empty() && self.re.is_none() && self.fast_match.is_none() {
            return false;
        }

        // If null is set in yaml.
        if self.re.is_none() && self.fast_match.is_none() {
            // If the target field does not exist in the record, treat it as detected.
            for v in self.key_list.iter() {
                if recinfo.get_value(v).is_none() {
                    return true;
                }
            }
            return false;
        }

        if event_value.is_none() {
            return false;
        }

        let event_value_str = event_value.unwrap();
        if self.key_list.is_empty() {
            // In this case it is just a grep search, so simply check whether it matches the regex.
            return self
                .re
                .as_ref()
                .unwrap()
                .iter()
                .any(|x| x.is_match(event_value_str));
        } else if let Some(fast_matcher) = &self.fast_match {
            let fast_match_result = check_fast_match(&self.pipes, event_value_str, fast_matcher);
            if let Some(is_match) = fast_match_result {
                return is_match;
            }
        }
        // If it could not be converted to character count/starts_with/ends_with search, compare using regex match.
        self.is_regex_fullmatch(event_value_str)
    }
}

/// Class representing elements specified by pipes (|).
/// Needs refactoring.
#[derive(PartialEq)]
pub enum PipeElement {
    Startswith,
    Endswith,
    Contains,
    Re,
    ReIgnoreCase,
    ReMultiLine,
    ReSingleLine,
    Wildcard,
    Expand,
    Exists(String, String),
    EqualsField(String),
    Endswithfield(String),
    FieldRef(String),
    FieldRefStartswith(String),
    FieldRefEndswith(String),
    FieldRefContains(String),
    Base64,
    Base64offset,
    Windash,
    Cidr(Result<IpCidr, NetworkParseError>),
    All,
    AllOnly,
    Cased,
    Gt(usize),
    Lt(usize),
    Gte(usize),
    Lte(usize),
    Utf16,
    Utf16Le,
    Utf16Be,
    Wide,
}

impl PipeElement {
    fn new(key: &str, pattern: &str, key_list: &Nested<String>) -> Result<PipeElement, String> {
        let pipe_element = match key {
            "startswith" => Some(PipeElement::Startswith),
            "endswith" => Some(PipeElement::Endswith),
            "contains" => Some(PipeElement::Contains),
            "re" => Some(PipeElement::Re),
            "exists" => Some(PipeElement::Exists(
                key_list[0].split('|').collect::<Vec<&str>>()[0].to_string(),
                pattern.to_string(),
            )),
            "reignorecase" => Some(PipeElement::ReIgnoreCase),
            "resingleline" => Some(PipeElement::ReSingleLine),
            "remultiline" => Some(PipeElement::ReMultiLine),
            "equalsfield" => Some(PipeElement::EqualsField(pattern.to_string())),
            "endswithfield" => Some(PipeElement::Endswithfield(pattern.to_string())),
            "expand" => Some(PipeElement::Expand),
            "fieldref" => Some(PipeElement::FieldRef(pattern.to_string())),
            "fieldrefstartswith" => Some(PipeElement::FieldRefStartswith(pattern.to_string())),
            "fieldrefendswith" => Some(PipeElement::FieldRefEndswith(pattern.to_string())),
            "fieldrefcontains" => Some(PipeElement::FieldRefContains(pattern.to_string())),
            "base64" => Some(PipeElement::Base64),
            "base64offset" => Some(PipeElement::Base64offset),
            "windash" => Some(PipeElement::Windash),
            "cidr" => Some(PipeElement::Cidr(IpCidr::from_str(pattern))),
            "all" => Some(PipeElement::All),
            "allOnly" => Some(PipeElement::AllOnly),
            "cased" => Some(PipeElement::Cased),
            "gt" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Gt(n)),
                Err(_) => {
                    return Err(format!(
                        "gt value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "lt" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Lt(n)),
                Err(_) => {
                    return Err(format!(
                        "lt value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "gte" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Gte(n)),
                Err(_) => {
                    return Err(format!(
                        "gte value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "lte" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Lte(n)),
                Err(_) => {
                    return Err(format!(
                        "lte value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "utf16" => Some(PipeElement::Utf16),
            "utf16le" => Some(PipeElement::Utf16Le),
            "utf16be" => Some(PipeElement::Utf16Be),
            "wide" => Some(PipeElement::Wide),
            _ => None,
        };

        if let Some(elment) = pipe_element {
            Ok(elment)
        } else {
            Err(format!(
                "An unknown pipe element was specified. key:{}",
                utils::concat_selection_key(key_list)
            ))
        }
    }

    fn get_eqfield(&self) -> Option<&String> {
        match self {
            PipeElement::EqualsField(s)
            | PipeElement::Endswithfield(s)
            | PipeElement::FieldRef(s)
            | PipeElement::FieldRefStartswith(s)
            | PipeElement::FieldRefEndswith(s)
            | PipeElement::FieldRefContains(s) => Some(s),
            _ => None,
        }
    }

    fn is_eqfield_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        match self {
            PipeElement::Exists(eq_key, val) => {
                val.to_lowercase() == recinfo.get_value(eq_key).is_some().to_string()
            }
            PipeElement::EqualsField(eq_key) | PipeElement::FieldRef(eq_key) => {
                let eq_value = recinfo.get_value(eq_key);
                // If an eventkey specified does not exist in the Evtx record, set to false.
                if event_value.is_none() || eq_value.is_none() {
                    return false;
                }
                eq_value.unwrap().cmp(event_value.unwrap()) == Ordering::Equal
            }
            PipeElement::FieldRefStartswith(eq_key) => {
                let starts_value = recinfo.get_value(eq_key);
                if event_value.is_none() || starts_value.is_none() {
                    return false;
                }
                let event_value = &event_value.unwrap().to_lowercase();
                let starts_value = &starts_value.unwrap().to_lowercase();
                event_value.starts_with(starts_value)
            }
            PipeElement::Endswithfield(eq_key) | PipeElement::FieldRefEndswith(eq_key) => {
                let ends_value = recinfo.get_value(eq_key);
                // If an eventkey specified does not exist in the Evtx record, set to false.
                if event_value.is_none() || ends_value.is_none() {
                    return false;
                }

                let event_value = &event_value.unwrap().to_lowercase();
                let ends_value = &ends_value.unwrap().to_lowercase();
                event_value.ends_with(ends_value)
            }
            PipeElement::FieldRefContains(eq_key) => {
                let contains_value = recinfo.get_value(eq_key);
                if event_value.is_none() || contains_value.is_none() {
                    return false;
                }
                let event_value = &event_value.unwrap().to_lowercase();
                let contains_value = &contains_value.unwrap().to_lowercase();
                event_value.contains(contains_value)
            }
            _ => false,
        }
    }

    /// Processes the pattern with pipe.
    fn pipe_pattern(&self, pattern: String) -> String {
        // When implementing polymorphism with an enum, all type implementations go into one method. For Java developers, this might feel odd.
        let fn_add_asterisk_end = |patt: String| {
            if patt.ends_with("//*") {
                patt
            } else if patt.ends_with("/*") {
                patt + "*"
            } else if patt.ends_with('*') {
                patt
            } else if patt.ends_with('\\') {
                // If the end is \ (one backslash), convert the end to \\* (two backslashes and an asterisk).
                // A trailing \\* means one backslash followed by a wildcard pattern.
                patt + "\\*"
            } else {
                patt + "*"
            }
        };
        let fn_add_asterisk_begin = |patt: String| {
            if patt.starts_with("//*") {
                patt
            } else if patt.starts_with("/*") {
                "*".to_string() + &patt
            } else if patt.starts_with('*') {
                patt
            } else {
                "*".to_string() + &patt
            }
        };

        match self {
            // For startswith, handle by appending a wildcard to the end of pattern.
            PipeElement::Startswith => fn_add_asterisk_end(pattern),
            // For endswith, handle by prepending a wildcard to the beginning of pattern.
            PipeElement::Endswith => fn_add_asterisk_begin(pattern),
            // For contains, handle by prepending and appending wildcards to pattern.
            PipeElement::Contains => fn_add_asterisk_end(fn_add_asterisk_begin(pattern)),
            // Convert WildCard to regex.
            PipeElement::Wildcard => PipeElement::pipe_pattern_wildcard(pattern),
            PipeElement::ReIgnoreCase => "(?i)".to_string() + pattern.as_str(),
            PipeElement::ReMultiLine => "(?m)".to_string() + pattern.as_str(),
            PipeElement::ReSingleLine => "(?s)".to_string() + pattern.as_str(),
            _ => pattern,
        }
    }

    /// Pipe processing for PipeElement::Wildcard.
    /// This processing could be included in pipe_pattern(), but became complex so it was separated into a separate function.
    fn pipe_pattern_wildcard(pattern: String) -> String {
        let wildcards = vec!["*", "?"];

        // Put the result of splitting pattern by wildcard into pattern_splits.
        // With the following algorithm, elements at even indices of pattern_splits are non-wildcard strings, and elements at odd indices contain wildcards.
        let mut idx = 0;
        let mut pattern_splits = vec![];
        let mut cur_str = String::default();
        while idx < pattern.len() {
            let prev_idx = idx;
            for wildcard in &wildcards {
                let cur_pattern: String = pattern.chars().skip(idx).collect::<String>();
                if cur_pattern.starts_with(&format!(r"\\{wildcard}")) {
                    // When there are two escape characters before the wildcard.
                    cur_str = format!("{}{}", cur_str, r"\");
                    pattern_splits.push(cur_str);
                    pattern_splits.push(wildcard.to_string());

                    cur_str = String::default();
                    idx += 3;
                    break;
                } else if cur_pattern.starts_with(&format!(r"\{wildcard}")) {
                    // When there is one escape character before the wildcard.
                    cur_str = format!("{cur_str}{wildcard}");
                    idx += 2;
                    break;
                } else if cur_pattern.starts_with(wildcard) {
                    // When it is a wildcard.
                    pattern_splits.push(cur_str);
                    pattern_splits.push(wildcard.to_string());

                    cur_str = String::default();
                    idx += 1;
                    break;
                }
            }
            // If hit in the above For loop, continue.
            if prev_idx != idx {
                continue;
            }

            cur_str = format!(
                "{}{}",
                cur_str,
                pattern.chars().skip(idx).take(1).collect::<String>()
            );
            idx += 1;
        }
        // If the last character is not a wildcard, cur_str contains characters, so put them into pattern_splits.
        if !cur_str.is_empty() {
            pattern_splits.push(cur_str);
        }

        // Convert from SIGMA rule wildcard notation to regex notation.
        let ret = pattern_splits.iter().enumerate().fold(
            String::default(),
            |acc: String, (idx, pattern)| {
                let regex_value = if idx % 2 == 0 {
                    // If not a wildcard, return the escaped string.
                    regex::escape(pattern)
                } else {
                    // When it is a wildcard.、"*"は".*"という正規表現に変換し、"?"は"."に変換する。
                    let wildcard_regex_value = if *pattern == "*" {
                        "(.|\\a|\\f|\\t|\\n|\\r|\\v)*"
                    } else {
                        "."
                    };
                    wildcard_regex_value.to_string()
                };

                format!("{acc}{regex_value}")
            },
        );

        // sigma wildcards are case insensitive.
        // Therefore, prepend a symbol indicating case insensitivity to the regex.
        "(?i)".to_string() + &ret
    }
}

#[cfg(test)]
mod tests {
    use super::super::matchers::{
        AllowlistFileMatcher, DefaultMatcher, MinlengthMatcher, PipeElement, RegexesFileMatcher,
    };

    use super::super::selectionnodes::{
        AndSelectionNode, LeafSelectionNode, OrSelectionNode, SelectionNode,
    };
    use crate::detections::configs::{
        Action, Config, CsvOutputOption, OutputOption, STORED_EKEY_ALIAS, StoredStatic,
    };
    use crate::detections::rule::matchers::FastMatch;
    use crate::detections::rule::tests::parse_rule_from_str;
    use crate::detections::{self, utils};

    fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
        let mut rule_node = parse_rule_from_str(rule_str);
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    min_level: "informational".to_string(),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            ..Default::default()
        }));

        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());

        match serde_json::from_str(record_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo =
                    utils::create_rec_info(record, "testpath".to_owned(), &keys, &false, &false);
                assert_eq!(
                    rule_node.select(
                        &recinfo,
                        dummy_stored_static.verbose_flag,
                        dummy_stored_static.quiet_errors_flag,
                        dummy_stored_static.json_input_flag,
                        &dummy_stored_static.eventkey_alias,
                    ),
                    expect_select
                );
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_rule_parse() {
        // ルールファイルをYAML形式で読み込み
        let rule_str = r#"
        title: PowerShell Execution Pipeline
        description: hogehoge
        enabled: true
        author: Yea
        logsource:
            product: windows
        detection:
            selection:
                Channel: Microsoft-Windows-PowerShell/Operational
                EventID: 4103
                ContextInfo:
                    - Host Application
                    - ホスト アプリケーション
                ImagePath:
                    min_length: 1234321
                    regexes: test_files/config/regex/detectlist_suspicous_services.txt
                    allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        falsepositives:
            - unknown
        level: medium
        details: 'command=%CommandLine%'
        creation_date: 2020/11/8
        updated_date: 2020/11/8
        "#;
        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = &rule_node.detection.name_to_selection["selection"];

        // Root
        let detection_childs = selection_node.get_childs();
        assert_eq!(detection_childs.len(), 4);

        // Channel
        {
            // Verify that LeafSelectionNode is correctly loaded.
            let child_node = detection_childs[0];
            assert!(child_node.is::<LeafSelectionNode>());
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "Channel");
            assert_eq!(child_node.get_childs().len(), 0);

            // Verify that the comparison regex is correct.
            let matcher = &child_node.matcher;
            assert!(matcher.is_some());
            let matcher = child_node.matcher.as_ref().unwrap();
            assert!(matcher.is::<DefaultMatcher>());
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

            assert!(matcher.fast_match.is_some());
            let fast_match = matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact(
                    "Microsoft-Windows-PowerShell/Operational".to_string()
                )]
            );
        }

        // EventID
        {
            // Verify that LeafSelectionNode is correctly loaded.
            let child_node = detection_childs[1] as &dyn SelectionNode;
            assert!(child_node.is::<LeafSelectionNode>());
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "EventID");
            assert_eq!(child_node.get_childs().len(), 0);

            // Verify that the comparison regex is correct.
            let matcher = &child_node.matcher;
            assert!(matcher.is_some());
            let matcher = child_node.matcher.as_ref().unwrap();
            assert!(matcher.is::<DefaultMatcher>());
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(matcher.fast_match.is_some());
        }

        // ContextInfo
        {
            // Verify that OrSelectionNode is correctly loaded.
            let child_node = detection_childs[2] as &dyn SelectionNode;
            assert!(child_node.is::<OrSelectionNode>());
            let child_node = child_node.downcast_ref::<OrSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 2);

            // Test patterns where LeafSelectionNode is under OrSelectionNode.
            // Verify that the Host Application node, which is a LeafSelectionNode, is correct.
            let hostapp_en_node = ancestors[0] as &dyn SelectionNode;
            assert!(hostapp_en_node.is::<LeafSelectionNode>());
            let hostapp_en_node = hostapp_en_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_en_matcher = &hostapp_en_node.matcher;
            assert!(hostapp_en_matcher.is_some());
            let hostapp_en_matcher = hostapp_en_matcher.as_ref().unwrap();
            assert!(hostapp_en_matcher.is::<DefaultMatcher>());
            let hostapp_en_matcher = hostapp_en_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(hostapp_en_matcher.fast_match.is_some());
            let fast_match = hostapp_en_matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact("Host Application".to_string())]
            );

            // Verify that the host application node, which is a LeafSelectionNode, is correct.
            let hostapp_jp_node = ancestors[1] as &dyn SelectionNode;
            assert!(hostapp_jp_node.is::<LeafSelectionNode>());
            let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_jp_matcher = &hostapp_jp_node.matcher;
            assert!(hostapp_jp_matcher.is_some());
            let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
            assert!(hostapp_jp_matcher.is::<DefaultMatcher>());
            let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(hostapp_jp_matcher.fast_match.is_some());
            let fast_match = hostapp_jp_matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact("ホスト アプリケーション".to_string())]
            );
        }

        // ImagePath
        {
            // Verify that AndSelectionNode is correctly loaded.
            let child_node = detection_childs[3] as &dyn SelectionNode;
            assert!(child_node.is::<AndSelectionNode>());
            let child_node = child_node.downcast_ref::<AndSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 3);

            // Verify that min-len is correctly loaded.
            {
                let ancestor_node = ancestors[0] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<MinlengthMatcher>());
                let ancestor_matcher = ancestor_matcher.downcast_ref::<MinlengthMatcher>().unwrap();
                assert_eq!(ancestor_matcher.min_len, 1234321);
            }

            // Verify that regexes are correctly loaded.
            {
                let ancestor_node = ancestors[1] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<RegexesFileMatcher>());
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<RegexesFileMatcher>()
                    .unwrap();

                // Verify that the content matches regexes.txt.
                let csvcontent = &ancestor_matcher.regexes;

                assert_eq!(csvcontent.len(), 16);
                assert_eq!(
                    csvcontent[0].as_str().to_string(),
                    r"^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$"
                );
                assert_eq!(
                    csvcontent[13].as_str().to_string(),
                    r"\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp"
                );
            }

            // Verify that allowlist.txt can be loaded.
            {
                let ancestor_node = ancestors[2] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<AllowlistFileMatcher>());
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<AllowlistFileMatcher>()
                    .unwrap();

                let csvcontent = &ancestor_matcher.regexes;
                assert_eq!(csvcontent.len(), 2);

                assert_eq!(
                    csvcontent[0].as_str().to_string(),
                    r#"^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe""#.to_string()
                );
                assert_eq!(
                    csvcontent[1].as_str().to_string(),
                    r#"^"C:\\Program Files\\Google\\Update\\GoogleUpdate\.exe""#.to_string()
                );
            }
        }
    }

    #[test]
    fn test_notdetect_regex_eventid() {
        // Since it is an exact match, verify that prefix matching does not detect.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 410}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_notdetect_regex_eventid2() {
        // Since it is an exact match, verify that suffix matching does not detect.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_regex_eventid() {
        // This should be detected for EventID=4103.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_regex_str() {
        // Also verify with string-like data.
        // Since it is an exact match, verify that it does not match as a prefix.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Securit"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_notdetect_regex_str2() {
        // Also verify with string-like data.
        // Since it is an exact match, verify that it does not match as a suffix.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ecurity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_regex_str() {
        // Verify that exact matching also works with string-like data.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_regex_emptystr() {
        // Verify that exact matching also works with string-like data.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"Channel": ""}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_notdetect_minlen() {
        // Verify that minlen is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security9", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_minlen() {
        // Verify that minlen is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_minlen2() {
        // Verify that minlen is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security.11", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_minlen_and() {
        // Verify that minlen is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_minlen_and() {
        // Verify that minlen is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 11
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_regex() {
        // Verify that regex can be used.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel|re: ^Program$
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_regex_partial_match() {
        // Partial regex match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re: DESKTOP
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_regexes() {
        // Verify that regexes.txt is correctly detected.
        // In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        // Note that when using double quotes as values in JSON, \ escape is required.
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_allowlist() {
        // Verify that the allowlist is correctly handled.
        // In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        // Note that when using double quotes as values in JSON, \ escape is required.
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_allowlist2() {
        // Verify that the allowlist is correctly handled.
        // In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_startswith1() {
        // Verify that startswith is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith2() {
        // Verify that startswith is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_startswith_case_insensitive() {
        // Verify that startswith is case-insensitive.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "ADMINISTRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_startswith_cased() {
        // Verify that startswith|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_cased2() {
        // Verify that startswith|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith1() {
        // Verify that endswith is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_endswith2() {
        // Verify that endswith is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_case_insensitive() {
        // Test to verify that endswith detects without distinguishing case.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "ADministRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased1() {
        // Verify that endswith|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased2() {
        // Verify that endswith|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "test"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased3() {
        // Verify that endswith|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "sTest"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains1() {
        // Verify that contains is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains2() {
        // Verify that contains is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_contains_case_insensitive() {
        // Test to verify that contains detects without distinguishing case.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "ADminIstraTOrS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_contains_cased1() {
        // Verify that contains|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains_cased2() {
        // Verify that contains|cased is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "MinistratorS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_wildcard_multibyte() {
        // Verification with multi-byte characters.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホストアプリケーション
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_wildcard_multibyte_notdetect() {
        // Verification with multi-byte characters.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホスとアプリケーション
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        // Wildcards match regardless of case.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk() {
        let value = PipeElement::pipe_pattern_wildcard(r"*ho*ge*".to_string());
        assert_eq!(
            "(?i)(.|\\a|\\f|\\t|\\n|\\r|\\v)*ho(.|\\a|\\f|\\t|\\n|\\r|\\v)*ge(.|\\a|\\f|\\t|\\n|\\r|\\v)*",
            value
        );
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\*ho\*\*ge\*".to_string());
        // The wildcard "\*" represents the literal "*".
        // In regex, "*" must be escaped, so \* is correct.
        assert_eq!(r"(?i)\*ho\*\*ge\*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk3() {
        // The wildcard "\\\\*" represents the literal "\\" and the regex ".*".
        // The literal "\\" is escaped, so "\\\\.*" is correct.
        let value = PipeElement::pipe_pattern_wildcard(r"\\*ho\\*ge\\*".to_string());
        assert_eq!(
            r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*ho\\(.|\a|\f|\t|\n|\r|\v)*ge\\(.|\a|\f|\t|\n|\r|\v)*",
            value
        );
    }

    #[test]
    fn test_pipe_pattern_wildcard_question() {
        let value = PipeElement::pipe_pattern_wildcard(r"?ho?ge?".to_string());
        assert_eq!(r"(?i).ho.ge.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\?ho\?ge\?".to_string());
        assert_eq!(r"(?i)\?ho\?ge\?", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question3() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\?ho\\?ge\\?".to_string());
        assert_eq!(r"(?i)\\.ho\\.ge\\.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_backshash() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\ho\\ge\\".to_string());
        assert_eq!(r"(?i)\\\\ho\\\\ge\\\\", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_mixed() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\*\****\*\\*".to_string());
        assert_eq!(
            r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*\*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*\*\\(.|\a|\f|\t|\n|\r|\v)*",
            value
        );
    }

    #[test]
    fn test_pipe_pattern_wildcard_many_backshashs() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\\*ho\\\*ge\\\".to_string());
        assert_eq!(
            r"(?i)\\\\(.|\a|\f|\t|\n|\r|\v)*ho\\\\(.|\a|\f|\t|\n|\r|\v)*ge\\\\\\",
            value
        );
    }

    #[test]
    fn test_grep_match() {
        // Wildcards match regardless of case.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_grep_not_match() {
        // Wildcards match regardless of case.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4104
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_value_keyword() {
        // Also verify with string-like data.
        // Since it is an exact match, verify that it does not match as a prefix.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_value_keyword() {
        // Also verify with string-like data.
        // Since it is an exact match, verify that it does not match as a prefix.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Securiteen
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_endswith_field() {
        // Verify that endswithfield is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field2() {
        // Verify that endswithfield is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_caseinsensitive() {
        // Verify that endswithfield detects case-insensitively.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "iTy" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_caseinsensitive2() {
        // Verify that endswithfield detects case-insensitively.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "SecuriTy", "Computer": "ity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_notdetect() {
        // Patterns correctly not detected by endswithfield.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "rity", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_endswith_field_notdetect2() {
        // Patterns correctly not detected by endswithfield.
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref() {
        // Verify that fieldref is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect() {
        // Patterns that fieldref cannot detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_endswith() {
        // Verify that fieldref is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|endswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_endswith() {
        // Patterns that fieldref cannot detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_startswith() {
        // Verify that fieldref is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_startswith() {
        // Patterns that fieldref cannot detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_contains() {
        // Verify that fieldref is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_contains() {
        // Patterns that fieldref cannot detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field() {
        // Verify that equalsfields is correctly detected.
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_notdetect() {
        // Patterns that equalsfields cannot detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_emptyfield() {
        // If a non-existent field is specified, do not detect.
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: NoField
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Securiti" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: Channel
        details: 'command=%CommandLine%'
        "#;
        check_select(rule_str, record_json_str, false);

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: NoField1
        details: 'command=%CommandLine%'
        "#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_field_null() {
        // Verify that the target field does not exist when the value is null.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
                Takoyaki:
                    value: null
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_field_null_not_detect() {
        // Verify that the target field does not exist when the value is null.するテスト
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: null
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with() {
        // When a single wildcard is at the end, it is equivalent to starts_with matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_starts_with_notdetect() {
        // When a single wildcard is at the end, it is equivalent to starts_with matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: AA-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with_exact_val() {
        // When a single wildcard is at the end and the characters to compare (excluding *) exactly match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_starts_with_shorter_val_notdetect() {
        // When a single wildcard is at the end but the characters to compare have fewer characters, it does not match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with_multibytes() {
        // Patterns containing wildcards and non-ASCII characters use regex matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: 社員端末*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "社員端末A"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with() {
        // When a single wildcard is at the beginning, it is equivalent to ends_with matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with_starts_with_exact_val() {
        // When a single wildcard is at the beginning and the characters to compare (excluding *) exactly match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*A-HOST'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with_shorter_val_notdetect() {
        // When a single wildcard is at the beginning but the characters to compare have fewer characters, it does not match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOSTA'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_only_wildcard() {
        // When there is only a wildcard, it is equivalent to ends_with matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_two_wildcards() {
        // When two or more wildcards are included, use regex matching.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST-*'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST-1"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64_contains() {
        // Match for base64|contains.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64offset_contains() {
        // Match for base64offset|contains.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64offset_contains_not_match() {
        // Match for base64offset|contains.しないパターン
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "test"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ipv4_detect() {
        // IPs matching CIDR.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_cidr_ipv4_not_detect() {
        // IPs not matching CIDR.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2600:1f18:130c:d900::/56
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "8.8.8.8"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ipv6_detect() {
        // IPs matching CIDR.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1234:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_cidr_ipv6_not_detect() {
        // IPs not matching CIDR.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1111:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ip_field_not_exists_not_detect() {
        // IPs not matching CIDR.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_backslash_exact_match() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory: 'C:\Windows\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_backslash1() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_backslash2() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false); //★ expect false
    }

    #[test]
    fn test_detect_contains_backslash1() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains_backslash2() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_backslash_endswith() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|endswith: 'C:\Windows\system32\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_backslash_regex() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|re: '.*system32\\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_all_only_detect_case() {
        let rule_str = r"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_all_only_no_detect_case() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_all_only_detected_and_selection_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 'dummy'
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_all_only_not_detect_and_selection_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 3
                - 2
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_contains_windash() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '-addstore'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

        let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -addstore"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
        check_select(rule_str, record_json_str2, true);
    }

    #[test]
    fn test_contains_all_windash() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '-addstore'
                    - '-test-test'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -test-test /addstore"
            }
          }
        }"#;

        let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test -addstore"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
        check_select(rule_str, record_json_str2, false);
    }

    #[test]
    fn test_contains_windash_multitype_dash() {
        let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '–addstore'
            condition: selection1
        "#;
        let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '—addstore'
            condition: selection1
        "#;
        let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '―addstore'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

        let record_json_str_en = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –addstore"
            }
          }
        }"#;

        let record_json_str_em = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —addstore"
            }
          }
        }"#;

        let record_json_str_horizontal = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―addstore"
            }
          }
        }"#;

        check_select(rule_str_en_dash, record_json_str, true);
        check_select(rule_str_en_dash, record_json_str_en, true);
        check_select(rule_str_en_dash, record_json_str_em, true);
        check_select(rule_str_en_dash, record_json_str_horizontal, true);
        check_select(rule_str_em_dash, record_json_str, true);
        check_select(rule_str_em_dash, record_json_str_en, true);
        check_select(rule_str_em_dash, record_json_str_em, true);
        check_select(rule_str_em_dash, record_json_str_horizontal, true);
        check_select(rule_str_horizontal_bar, record_json_str, true);
        check_select(rule_str_horizontal_bar, record_json_str_en, true);
        check_select(rule_str_horizontal_bar, record_json_str_em, true);
        check_select(rule_str_horizontal_bar, record_json_str_horizontal, true);
    }

    #[test]
    fn test_contains_all_windash_multitype_dash() {
        let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '–addstore'
                    - '–test–test'
            condition: selection1
        "#;

        let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '—addstore'
                    - '—test—test'
            condition: selection1
        "#;

        let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '―addstore'
                    - '―test―test'
            condition: selection1
        "#;

        let record_json_str_en_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –test–test /addstore"
            }
          }
        }"#;

        let record_json_str_en_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test –addstore"
            }
          }
        }"#;

        let record_json_str_em_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —test—test /addstore"
            }
          }
        }"#;

        let record_json_str_em_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test —addstore"
            }
          }
        }"#;

        let record_json_str_horizontal_bar = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―test―test /addstore"
            }
          }
        }"#;

        let record_json_str_horizontal_bar2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test ―addstore"
            }
          }
        }"#;

        check_select(rule_str_en_dash, record_json_str_en_dash, true);
        check_select(rule_str_en_dash, record_json_str_en_dash2, false);
        check_select(rule_str_em_dash, record_json_str_em_dash, true);
        check_select(rule_str_em_dash, record_json_str_em_dash2, false);
        check_select(
            rule_str_horizontal_bar,
            record_json_str_horizontal_bar,
            true,
        );
        check_select(
            rule_str_horizontal_bar,
            record_json_str_horizontal_bar2,
            false,
        );
    }

    #[test]
    fn test_exists_true() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_caseinsensitive_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|i: ABC
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "abc"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_exists_null_true() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_multiline_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|m: ^ABC$
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_exists_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Dummy|exists: false
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_singleline_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|s: A.*F
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_ge() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_ge_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_lt() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_lt_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_gte() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_gte_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_lte() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_lte_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }
}

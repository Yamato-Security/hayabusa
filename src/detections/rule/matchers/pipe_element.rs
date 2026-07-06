use cidr_utils::cidr::IpCidr;
use cidr_utils::cidr::errors::NetworkParseError;
use nested::Nested;
use std::cmp::Ordering;
use std::str::FromStr;

use crate::detections::{detection::EvtxRecordInfo, utils};

/// Represents the modifiers specified after pipes (|) in a rule field key.
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
    pub(super) fn new(
        key: &str,
        pattern: &str,
        key_list: &Nested<String>,
    ) -> Result<PipeElement, String> {
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

        if let Some(element) = pipe_element {
            Ok(element)
        } else {
            Err(format!(
                "An unknown pipe element was specified. key:{}",
                utils::concat_selection_key(key_list)
            ))
        }
    }

    pub(super) fn get_eqfield(&self) -> Option<&String> {
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

    pub(super) fn is_eqfield_match(
        &self,
        event_value: Option<&String>,
        recinfo: &EvtxRecordInfo,
    ) -> bool {
        match self {
            PipeElement::Exists(eq_key, val) => {
                val.to_lowercase() == recinfo.get_value(eq_key).is_some().to_string()
            }
            PipeElement::EqualsField(eq_key) | PipeElement::FieldRef(eq_key) => {
                let eq_value = recinfo.get_value(eq_key);
                // If the specified event key does not exist in the evtx record, return false.
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
                // If the specified event key does not exist in the evtx record, return false.
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

    /// Applies this pipe's transformation to the pattern.
    pub(super) fn pipe_pattern(&self, pattern: String) -> String {
        // When implementing polymorphism with an enum, every variant's implementation ends up in a
        // single method. This may feel odd to developers used to Java-style class hierarchies.
        let add_asterisk_end = |pattern: String| {
            if pattern.ends_with("//*") {
                pattern
            } else if pattern.ends_with("/*") {
                pattern + "*"
            } else if pattern.ends_with('*') {
                pattern
            } else if pattern.ends_with('\\') {
                // If the pattern ends with \ (a single backslash), turn the ending into \\*
                // (two backslashes and an asterisk): in wildcard notation a trailing \\* means a
                // literal backslash followed by the * wildcard.
                pattern + "\\*"
            } else {
                pattern + "*"
            }
        };
        let add_asterisk_begin = |pattern: String| {
            if pattern.starts_with("//*") {
                pattern
            } else if pattern.starts_with("/*") {
                "*".to_string() + &pattern
            } else if pattern.starts_with('*') {
                pattern
            } else {
                "*".to_string() + &pattern
            }
        };

        match self {
            // For startswith, handle by appending a wildcard to the end of pattern.
            PipeElement::Startswith => add_asterisk_end(pattern),
            // For endswith, handle by prepending a wildcard to the beginning of pattern.
            PipeElement::Endswith => add_asterisk_begin(pattern),
            // For contains, handle by prepending and appending wildcards to pattern.
            PipeElement::Contains => add_asterisk_end(add_asterisk_begin(pattern)),
            // Convert WildCard to regex.
            PipeElement::Wildcard => PipeElement::pipe_pattern_wildcard(pattern),
            PipeElement::ReIgnoreCase => "(?i)".to_string() + pattern.as_str(),
            PipeElement::ReMultiLine => "(?m)".to_string() + pattern.as_str(),
            PipeElement::ReSingleLine => "(?s)".to_string() + pattern.as_str(),
            _ => pattern,
        }
    }

    /// Pipe processing for PipeElement::Wildcard.
    /// This processing could have been included in pipe_pattern(), but it became complex, so it
    /// was split out into its own function.
    pub(super) fn pipe_pattern_wildcard(pattern: String) -> String {
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
            // If one of the wildcard branches above matched, idx has already been advanced, so
            // continue with the next chunk.
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
                    // When it is a wildcard, convert "*" into a ".*"-style regex (an alternation
                    // that additionally matches the newline, which "." alone does not) and convert
                    // "?" into ".".
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

        // Sigma wildcards are case-insensitive.
        // Therefore, prepend the case-insensitive flag to the regex.
        "(?i)".to_string() + &ret
    }
}

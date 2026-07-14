use cidr_utils::cidr::IpCidr;
use cidr_utils::cidr::errors::NetworkParseError;
use nested::Nested;
use std::str::FromStr;

use super::modifiers::{fieldref, regex, string};
use crate::detections::utils;

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

    /// Returns the field name referenced by an `equalsfield`/`endswithfield`/`fieldref*` modifier.
    /// Delegates to the `fieldref` category module.
    pub(super) fn get_eqfield(&self) -> Option<&String> {
        fieldref::get_key(self)
    }

    /// Applies this pipe's transformation to the pattern. String-wrapping/wildcard modifiers are
    /// handled by the `string` category module and regex-flag modifiers by the `regex` module;
    /// every other modifier leaves the pattern unchanged.
    pub(super) fn pipe_pattern(&self, pattern: String) -> String {
        match self {
            PipeElement::Startswith
            | PipeElement::Endswith
            | PipeElement::Contains
            | PipeElement::Wildcard => string::wrap_pattern(self, pattern),
            PipeElement::ReIgnoreCase | PipeElement::ReMultiLine | PipeElement::ReSingleLine => {
                regex::add_flag(self, pattern)
            }
            _ => pattern,
        }
    }

    /// Pipe processing for `PipeElement::Wildcard`. Thin wrapper over the `string` category
    /// module's `wildcard_to_regex`, kept under this name only so existing tests can call it
    /// directly (production code goes through `string::wrap_pattern`).
    #[cfg(test)]
    pub(super) fn pipe_pattern_wildcard(pattern: String) -> String {
        string::wildcard_to_regex(pattern)
    }
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use nested::Nested;
use regex::Regex;
use yaml_rust2::Yaml;

use super::LeafMatcher;
use super::pipe_element::PipeElement;
use crate::detections::configs::WINDASH_CHARACTERS;
use crate::detections::rule::base64_match::{
    convert_to_base64_str, to_base64_utf8, to_base64_utf16be, to_base64_utf16le_with_bom,
};
use crate::detections::rule::fast_match::{FastMatch, check_fast_match, convert_to_fast_match};
use crate::detections::{detection::EvtxRecordInfo, utils};

/// Default match class, used when no special matcher (min_length/regexes/allowlist) applies.
/// Handles wildcards and pipes.
pub struct DefaultMatcher {
    re: Option<Vec<Regex>>,
    pub(super) fast_match: Option<Vec<FastMatch>>,
    pipes: Vec<PipeElement>,
    key_list: Nested<String>,
    // Set to true when the `neq` modifier is used. `neq` negates the whole comparison
    // (equivalent to Sigma's SigmaNegateModifier), so the final match result is inverted.
    neg_match: bool,
}

impl DefaultMatcher {
    pub fn new() -> DefaultMatcher {
        DefaultMatcher {
            re: None,
            fast_match: None,
            pipes: Vec::new(),
            key_list: Nested::<String>::new(),
            neg_match: false,
        }
    }

    /// Returns the field name referenced by an equalsfield/endswithfield/fieldref-style pipe,
    /// if this matcher uses one.
    pub fn get_eqfield_key(&self) -> Option<&String> {
        let pipe = self.pipes.first()?;
        pipe.get_eqfield()
    }

    /// Returns true if the value matches any of this matcher's compiled regexes.
    /// Note that Regex::is_match() performs a substring search, so any anchoring must be
    /// expressed in the pattern itself.
    fn is_regex_fullmatch(&self, value: &str) -> bool {
        self.re.as_ref().unwrap().iter().any(|x| x.is_match(value))
    }

    /// Converts a rule value (pattern) into a regex string by applying, in order, the pipes
    /// specified after the field name in the rule file.
    /// Wildcard-to-regex conversion is also implemented through this method: pass the wildcard
    /// string as `pattern` and include PipeElement::Wildcard in `pipes`.
    fn from_pattern_to_regex_str(pattern: String, pipes: &[PipeElement]) -> String {
        // Process the pattern with each pipe.
        pipes
            .iter()
            .fold(pattern, |acc, pipe| pipe.pipe_pattern(acc))
    }
}

/// How the pattern is wrapped before matching (the surrounding wildcards).
#[derive(PartialEq)]
enum Wrap {
    /// The bare pattern with no surrounding wildcards (no `contains`/`startswith`/`endswith`).
    None,
    StartsWith,
    EndsWith,
    Contains,
    /// The keyless `|all` form, which uses the internal `allOnly*` sentinel prefix.
    AllOnly,
}

/// Whether the pattern is base64-encoded before matching.
#[derive(PartialEq)]
enum Encoding {
    Plain,
    Base64,
    Base64offset,
}

/// Whether the pattern is UTF-16-encoded before the base64 step (only meaningful with `Encoding`
/// other than `Plain`).
#[derive(PartialEq)]
enum Utf16Kind {
    None,
    /// `|utf16`: both byte orders (base64offset) / UTF-16LE with a BOM (base64).
    Utf16,
    Utf16Le,
    Utf16Be,
    Wide,
}

/// A field's fast-path pipe modifiers, normalized from the pipe list in a single pass.
///
/// `from_pipes` folds the modifiers into these canonical fields (O(n)) instead of matching a
/// hand-enumerated table of pipe tuples; `build_fast_match` then maps a recognized plan to a
/// `FastMatch` list. Because the plan is built by a single scan it is order- and count-independent:
/// for the canonical Sigma modifier order (every real rule) it produces exactly the same matcher the
/// former table did, but a non-canonical order the old index-based table missed — e.g.
/// `|cased|contains` or `|contains|base64` — is now normalized like its canonical form instead of
/// silently falling back to the regex path (which ignored the missed modifier). See the
/// `test_reordered_*` / `test_utf16_base64_contains_*` tests. `from_pipes` returns `None` when the
/// list contains a modifier the fast path does not build a `FastMatch` for (regex, field reference,
/// numeric comparison, cidr, exists, …), and `build_fast_match` returns `None` for a
/// recognized-but-unsupported combination; in both cases the caller uses the regex path.
struct MatchPlan {
    wrap: Wrap,
    encoding: Encoding,
    utf16: Utf16Kind,
    cased: bool,
    windash: bool,
    all: bool,
}

impl MatchPlan {
    fn from_pipes(pipes: &[PipeElement]) -> Option<MatchPlan> {
        let mut plan = MatchPlan {
            wrap: Wrap::None,
            encoding: Encoding::Plain,
            utf16: Utf16Kind::None,
            cased: false,
            windash: false,
            all: false,
        };
        for pipe in pipes {
            match pipe {
                PipeElement::Startswith => plan.wrap = Wrap::StartsWith,
                PipeElement::Endswith => plan.wrap = Wrap::EndsWith,
                PipeElement::Contains => plan.wrap = Wrap::Contains,
                PipeElement::AllOnly => plan.wrap = Wrap::AllOnly,
                PipeElement::Base64 => plan.encoding = Encoding::Base64,
                PipeElement::Base64offset => plan.encoding = Encoding::Base64offset,
                PipeElement::Utf16 => plan.utf16 = Utf16Kind::Utf16,
                PipeElement::Utf16Le => plan.utf16 = Utf16Kind::Utf16Le,
                PipeElement::Utf16Be => plan.utf16 = Utf16Kind::Utf16Be,
                PipeElement::Wide => plan.utf16 = Utf16Kind::Wide,
                PipeElement::Cased => plan.cased = true,
                PipeElement::Windash => plan.windash = true,
                PipeElement::All => plan.all = true,
                // Any other modifier is handled off the fast path (regex, field reference, numeric,
                // cidr, exists, …); leave the fast matcher unset so the caller builds a regex.
                _ => return None,
            }
        }
        Some(plan)
    }

    /// Builds the `FastMatch` list for a recognized plan, or `None` when the fast path does not
    /// handle the combination (the caller then falls back to the regex path). `pattern` may gain a
    /// dash-replaced variant for the `|contains|all|windash` form, matching the original behavior.
    fn build_fast_match(
        &self,
        pattern: &mut Vec<String>,
        err_msgs: &mut Vec<String>,
    ) -> Option<Vec<FastMatch>> {
        match self.encoding {
            Encoding::Plain => {
                // UTF-16 only applies together with a base64 encoding.
                if self.utf16 != Utf16Kind::None {
                    return None;
                }
                match self.wrap {
                    Wrap::None => {
                        if self.cased || self.windash || self.all {
                            return None;
                        }
                        convert_to_fast_match(&pattern[0], true)
                    }
                    Wrap::StartsWith | Wrap::EndsWith => {
                        if self.windash || self.all {
                            return None;
                        }
                        let wrapped = if self.wrap == Wrap::StartsWith {
                            format!("{}*", pattern[0])
                        } else {
                            format!("*{}", pattern[0])
                        };
                        // `|cased` makes the comparison case-sensitive (ignore_case = false).
                        convert_to_fast_match(&wrapped, !self.cased)
                    }
                    Wrap::AllOnly => {
                        if self.cased || self.windash || self.all {
                            return None;
                        }
                        convert_to_fast_match(&format!("allOnly*{}*", pattern[0]), true)
                    }
                    Wrap::Contains if self.windash => {
                        // For |contains|windash: also match a variant of the pattern whose first
                        // dash-like character (hyphen, en/em dash, etc.) is replaced with "/", to
                        // cover the interchangeable option prefixes accepted by Windows commands.
                        if self.cased {
                            return None;
                        }
                        let windash_chars = WINDASH_CHARACTERS.as_slice();
                        // |contains|all|windash was already turned into an AND-op NarySelectionNode
                        // during parsing; it additionally records the dash-replaced variant in
                        // `pattern` for the regex fallback, so preserve that here.
                        if self.all {
                            pattern.push(pattern[0].replacen(windash_chars, "/", 1));
                        }
                        let mut fastmatches =
                            convert_to_fast_match(&format!("*{}*", pattern[0]), true)
                                .unwrap_or_default();
                        fastmatches.extend(
                            convert_to_fast_match(
                                &format!("*{}*", pattern[0].replacen(windash_chars, "/", 1)),
                                true,
                            )
                            .unwrap_or_default(),
                        );
                        (!fastmatches.is_empty()).then_some(fastmatches)
                    }
                    Wrap::Contains => {
                        // |contains, |contains|all (parse-split, treated as plain contains), or
                        // |contains|cased (case-sensitive).
                        if self.all && self.cased {
                            return None;
                        }
                        convert_to_fast_match(&format!("*{}*", pattern[0]), !self.cased)
                    }
                }
            }
            Encoding::Base64 => {
                // |base64|contains, optionally UTF-16-encoded first (|utf16|base64|contains).
                if self.wrap != Wrap::Contains || self.cased || self.windash || self.all {
                    return None;
                }
                let original = pattern[0].as_str();
                let encoded = match self.utf16 {
                    Utf16Kind::None => to_base64_utf8(original),
                    // |utf16|base64 means UTF-16LE with a BOM.
                    Utf16Kind::Utf16 => to_base64_utf16le_with_bom(original, true),
                    Utf16Kind::Utf16Le | Utf16Kind::Wide => {
                        to_base64_utf16le_with_bom(original, false)
                    }
                    Utf16Kind::Utf16Be => to_base64_utf16be(original),
                };
                convert_to_fast_match(&format!("*{encoded}*"), true)
            }
            Encoding::Base64offset => {
                // |base64offset|contains (all three byte-alignment variants), optionally UTF-16
                // encoded first. Plain |utf16| tries both byte orders.
                if self.wrap != Wrap::Contains || self.cased || self.windash || self.all {
                    return None;
                }
                let original = pattern[0].as_str();
                match self.utf16 {
                    Utf16Kind::None => convert_to_base64_str(None, original, err_msgs),
                    Utf16Kind::Utf16 => {
                        let le =
                            convert_to_base64_str(Some(&PipeElement::Utf16Le), original, err_msgs);
                        let be =
                            convert_to_base64_str(Some(&PipeElement::Utf16Be), original, err_msgs);
                        match (le, be) {
                            (Some(mut le), Some(be)) => {
                                le.extend(be);
                                Some(le)
                            }
                            _ => None,
                        }
                    }
                    Utf16Kind::Utf16Le => {
                        convert_to_base64_str(Some(&PipeElement::Utf16Le), original, err_msgs)
                    }
                    Utf16Kind::Utf16Be => {
                        convert_to_base64_str(Some(&PipeElement::Utf16Be), original, err_msgs)
                    }
                    Utf16Kind::Wide => {
                        convert_to_base64_str(Some(&PipeElement::Wide), original, err_msgs)
                    }
                }
            }
        }
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

        // Parse the pattern.
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
        // If pipes are specified, parse them.
        let empty_str = String::default();
        // The first element is just the field key; the second and subsequent elements are pipes.

        let mut keys_all: Vec<&str> = key_list.get(0).unwrap_or(&empty_str).split('|').collect(); // key_list cannot be empty.

        // `neq` (Sigma's SigmaNegateModifier) negates the whole comparison. Detect it among the
        // pipe modifiers (never the field name at index 0), strip it from the modifier chain, and
        // flag the matcher so the final result is inverted in `is_match`. Because it is handled as
        // a plain negation, it composes with any other modifier (plain value, contains, startswith,
        // endswith, re, fieldref, fieldref|contains, ...).
        if keys_all.len() >= 2 && keys_all[1..].contains(&"neq") {
            self.neg_match = true;
            let field = keys_all[0];
            let mut rest: Vec<&str> = keys_all[1..]
                .iter()
                .copied()
                .filter(|k| *k != "neq")
                .collect();
            keys_all = Vec::with_capacity(rest.len() + 1);
            keys_all.push(field);
            keys_all.append(&mut rest);
        }

        // `neq` has no field to negate on a keyless selection. The keyless `|all` whole-record path
        // (in parse_selection_recursively) only fires when the key is exactly `|all`, so `|all|neq`
        // would fall through to an empty-field match and, being negated, match every record. Reject
        // the combination so such a rule fails to load with a clear message rather than misbehaving.
        if self.neg_match && keys_all[0].is_empty() {
            return Err(vec![
                "The `neq` modifier cannot be combined with the keyless `|all` modifier."
                    .to_string(),
            ]);
        }

        // Maps shorthand pipe names to the internal names accepted by PipeElement::new():
        // "all" -> "allOnly" (for a leading "|all" key) and the regex flags "i"/"m"/"s" ->
        // "reignorecase"/"remultiline"/"resingleline".
        let mut change_map: HashMap<&str, &str> = HashMap::new();
        change_map.insert("all", "allOnly");
        change_map.insert("i", "reignorecase");
        change_map.insert("m", "remultiline");
        change_map.insert("s", "resingleline");

        // Detect the case where "|" is at the beginning of the key (no field name, e.g. "|all"),
        // and rename all -> allOnly.
        if keys_all[0].is_empty() && keys_all.len() == 2 && keys_all[1] == "all" {
            keys_all[1] = change_map["all"];
        }
        // Collapse two-part modifiers into a single pipe name so that each remaining element maps
        // to exactly one PipeElement: "re|i"/"re|m"/"re|s" become the corresponding regex-flag
        // pipes, and "fieldref|startswith" etc. become the dedicated fieldref pipes.
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

        let mut err_msgs = vec![];
        for key in keys_without_head.iter() {
            let pipe_element = PipeElement::new(key, &pattern[0], key_list);
            match pipe_element {
                Ok(element) => {
                    self.pipes.push(element);
                }
                Err(e) => {
                    err_msgs.push(e);
                }
            }
        }
        if !err_msgs.is_empty() {
            return Err(err_msgs);
        }
        // Four or more pipe modifiers are not supported.
        if self.pipes.len() >= 4 {
            let errmsg = format!(
                "Multiple pipe elements cannot be used. key:{}",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }
        // Normalize the pipe modifiers into a canonical MatchPlan and build the fast matcher from
        // it in one pass, replacing the former hand-enumerated table of pipe-count/tuple cases. An
        // unrecognized combination yields no fast matcher and the regex path below handles it.
        self.fast_match = MatchPlan::from_pipes(&self.pipes)
            .and_then(|plan| plan.build_fast_match(&mut pattern, &mut err_msgs));

        if self.fast_match.is_some()
            && matches!(
                &self.fast_match.as_ref().unwrap()[0],
                FastMatch::Exact(_) | FastMatch::Contains(_)
            )
            && !self.key_list.is_empty()
        {
            // No regex needs to be compiled when the pattern was fully replaced with a
            // FastMatch::Exact/Contains search. (Grep searches with an empty key list still need
            // the regex, so they are excluded here.)
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
            // If the pattern is not a regex (no |re pipe), it is interpreted as a wildcard
            // expression. Wildcards are matched using regex internally, so append a pipe that
            // converts the wildcard string into a regex.
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

            // Two regex paths intentionally keep substring (not full-value) semantics, so their
            // wildcard regexes must stay unanchored: keyword (grep) searches, which have an empty
            // key list, and the keyless `|all` modifier, whose leaf is matched against the entire
            // record string rather than a single field (see selectionnodes.rs). Anchoring either
            // to the whole value would break their contains-style matching.
            let is_whole_record_search =
                self.key_list.is_empty() || self.key_list.get(0).is_some_and(|k| k == "|all");
            let mut re_result_vec = vec![];
            for p in pattern {
                let pattern = DefaultMatcher::from_pattern_to_regex_str(p, &self.pipes);
                // Wildcard-derived regexes must match the entire field value (Sigma full-value
                // semantics), but pipe_pattern_wildcard() produces an unanchored regex and
                // Regex::is_match() searches substrings, so anchor them here. The whole-record
                // searches above and |re-style user-supplied regexes are left untouched.
                let pattern = if !is_re && !is_whole_record_search {
                    format!("^(?:{pattern})$")
                } else {
                    pattern
                };
                // Compile the pipe-processed pattern into a regex.
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
        let result = self.is_match_inner(event_value, recinfo);
        // `neq` negates the whole comparison (Sigma's SigmaNegateModifier).
        result ^ self.neg_match
    }

    fn is_negated(&self) -> bool {
        self.neg_match
    }
}

impl DefaultMatcher {
    /// Performs the actual (non-negated) match. `is_match` inverts this result when the
    /// `neq` modifier is present.
    fn is_match_inner(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        let pipe: &PipeElement = self.pipes.first().unwrap_or(&PipeElement::Wildcard);
        // Pipes that implement their own matching (cidr, exists, field references and numeric
        // comparisons) are handled first; all other kinds fall through to fast match/regex.
        let match_result = match pipe {
            PipeElement::Cidr(ip_result) => match ip_result {
                Ok(matcher_ip) => {
                    let val = String::default();
                    let event_value_str = event_value.unwrap_or(&val);
                    let event_ip = IpAddr::from_str(event_value_str);
                    match event_ip {
                        Ok(target_ip) => Some(matcher_ip.contains(&target_ip)),
                        Err(_) => Some(false), // The event value is not an IP address.
                    }
                }
                Err(_) => Some(false), // The rule's cidr value is not a valid CIDR range.
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
                    Err(_) => Some(false), // The event value is not numeric.
                }
            }
            _ => None,
        };
        if let Some(result) = match_result {
            return result;
        }

        // If null is set in the yaml and the key list is empty (i.e. a grep-style search over the
        // whole record), there is nothing to match against, so never detect.
        if self.key_list.is_empty() && self.re.is_none() && self.fast_match.is_none() {
            return false;
        }

        // If null is set in the yaml.
        if self.re.is_none() && self.fast_match.is_none() {
            // A null value matches when the target field does not exist in the record.
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
        // Fall back to a regex match when the pattern could not be handled by the fast match path
        // (exact/starts_with/ends_with/contains).
        self.is_regex_fullmatch(event_value_str)
    }
}

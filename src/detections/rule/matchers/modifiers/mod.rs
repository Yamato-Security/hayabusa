//! Per-category pipe-modifier logic.
//!
//! `PipeElement` (in [`super::pipe_element`]) is still the parsed representation of a single
//! `|`-modifier, and `MatchPlan` (in [`super::default_matcher`]) still normalizes the fast-path
//! modifiers, but the *behavior* of each modifier now lives in a category module here —
//! [`string`], [`regex`], [`numeric`], [`cidr`], [`fieldref`] and [`encoding`]. The central
//! `match` statements in `pipe_element`/`default_matcher` now delegate to these modules, so adding a
//! Sigma modifier means editing one category module instead of touching several hand-enumerated
//! dispatch sites.

use crate::detections::detection::EvtxRecordInfo;

use super::pipe_element::PipeElement;

pub(super) mod cidr;
pub(super) mod encoding;
pub(super) mod fieldref;
pub(super) mod numeric;
pub(super) mod regex;
pub(super) mod string;

/// A modifier that matches an event value directly rather than through the fast-match/regex
/// pipeline: `cidr`, the numeric comparisons (`gt`/`lt`/`gte`/`lte`), the field references
/// (`fieldref`/`equalsfield`/`endswithfield`/…) and `exists`.
///
/// `value_match` returns `Some(result)` for those modifiers and `None` for every other modifier,
/// which tells `DefaultMatcher::is_match_inner` to fall through to the fast-match/regex path.
pub(super) trait ValueMatcher {
    fn value_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> Option<bool>;
}

impl ValueMatcher for PipeElement {
    fn value_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> Option<bool> {
        match self {
            PipeElement::Cidr(ip_result) => Some(cidr::is_match(ip_result, event_value)),
            PipeElement::Exists(..)
            | PipeElement::EqualsField(_)
            | PipeElement::FieldRef(_)
            | PipeElement::FieldRefStartswith(_)
            | PipeElement::FieldRefContains(_)
            | PipeElement::FieldRefEndswith(_)
            | PipeElement::Endswithfield(_) => Some(fieldref::is_match(self, event_value, recinfo)),
            PipeElement::Gt(_) | PipeElement::Lt(_) | PipeElement::Gte(_) | PipeElement::Lte(_) => {
                Some(numeric::is_match(self, event_value))
            }
            // Every other modifier is handled by the fast-match/regex path.
            _ => None,
        }
    }
}

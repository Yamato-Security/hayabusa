//! The field-reference modifiers (`equalsfield`, `endswithfield`, `fieldref`,
//! `fieldref|startswith`, `fieldref|endswith`, `fieldref|contains`) and `exists`, which compare a
//! field against another field of the same record rather than against a literal pattern.

use std::cmp::Ordering;

use crate::detections::detection::EvtxRecordInfo;

use super::PipeElement;

/// Returns the field name referenced by an `equalsfield`/`endswithfield`/`fieldref*` modifier,
/// used by `DefaultMatcher::get_eqfield_key` to know which other field this leaf depends on.
pub(in crate::detections::rule::matchers) fn get_key(pipe: &PipeElement) -> Option<&String> {
    match pipe {
        PipeElement::EqualsField(s)
        | PipeElement::Endswithfield(s)
        | PipeElement::FieldRef(s)
        | PipeElement::FieldRefStartswith(s)
        | PipeElement::FieldRefEndswith(s)
        | PipeElement::FieldRefContains(s) => Some(s),
        _ => None,
    }
}

/// Matches the field-reference / `exists` modifiers against the record. `event_value` is the value
/// of this leaf's own field; the referenced field is looked up from `recinfo`.
pub(super) fn is_match(
    pipe: &PipeElement,
    event_value: Option<&String>,
    recinfo: &EvtxRecordInfo,
) -> bool {
    match pipe {
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

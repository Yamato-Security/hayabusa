//! The encoding modifiers `base64` / `base64offset` and their optional UTF-16 pre-encoding
//! (`utf16` / `utf16le` / `utf16be` / `wide`).
//!
//! `MatchPlan` (in [`super::super::default_matcher`]) folds the pipe list into an [`Encoding`] plus
//! a [`Utf16Kind`]; this module turns that pair into the base64-encoded needle(s) the fast matcher
//! searches for.

use super::PipeElement;
use crate::detections::rule::base64_match::{
    convert_to_base64_str, to_base64_utf16be, to_base64_utf16le_with_bom, to_base64_utf8,
};
use crate::detections::rule::fast_match::FastMatch;

/// Whether the pattern is base64-encoded before matching.
#[derive(PartialEq)]
pub(in crate::detections::rule::matchers) enum Encoding {
    Plain,
    Base64,
    Base64offset,
}

/// Whether the pattern is UTF-16-encoded before the base64 step (only meaningful with `Encoding`
/// other than `Plain`).
#[derive(PartialEq)]
pub(in crate::detections::rule::matchers) enum Utf16Kind {
    None,
    /// `|utf16`: both byte orders (base64offset) / UTF-16LE with a BOM (base64).
    Utf16,
    Utf16Le,
    Utf16Be,
    Wide,
}

/// `|base64|contains`: returns the base64 encoding of `original`, optionally UTF-16-encoded first
/// (`|utf16|base64|contains`). The caller wraps the result in `*…*` and builds a `Contains`
/// fast match.
pub(in crate::detections::rule::matchers) fn base64_encoded(
    utf16: &Utf16Kind,
    original: &str,
) -> String {
    match utf16 {
        Utf16Kind::None => to_base64_utf8(original),
        // |utf16|base64 means UTF-16LE with a BOM.
        Utf16Kind::Utf16 => to_base64_utf16le_with_bom(original, true),
        Utf16Kind::Utf16Le | Utf16Kind::Wide => to_base64_utf16le_with_bom(original, false),
        Utf16Kind::Utf16Be => to_base64_utf16be(original),
    }
}

/// `|base64offset|contains` (all three byte-alignment variants), optionally UTF-16-encoded first.
/// Plain `|utf16|` tries both byte orders.
pub(in crate::detections::rule::matchers) fn base64offset_fast_match(
    utf16: &Utf16Kind,
    original: &str,
    err_msgs: &mut Vec<String>,
) -> Option<Vec<FastMatch>> {
    match utf16 {
        Utf16Kind::None => convert_to_base64_str(None, original, err_msgs),
        Utf16Kind::Utf16 => {
            let le = convert_to_base64_str(Some(&PipeElement::Utf16Le), original, err_msgs);
            let be = convert_to_base64_str(Some(&PipeElement::Utf16Be), original, err_msgs);
            match (le, be) {
                (Some(mut le), Some(be)) => {
                    le.extend(be);
                    Some(le)
                }
                _ => None,
            }
        }
        Utf16Kind::Utf16Le => convert_to_base64_str(Some(&PipeElement::Utf16Le), original, err_msgs),
        Utf16Kind::Utf16Be => convert_to_base64_str(Some(&PipeElement::Utf16Be), original, err_msgs),
        Utf16Kind::Wide => convert_to_base64_str(Some(&PipeElement::Wide), original, err_msgs),
    }
}

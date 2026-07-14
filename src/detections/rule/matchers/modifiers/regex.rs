//! The inline-flag regex modifiers `re|i` / `re|m` / `re|s`.

use super::PipeElement;

/// Prepends the inline regex flag corresponding to the `re|i` / `re|m` / `re|s` modifier
/// (`(?i)` / `(?m)` / `(?s)`). Any other modifier returns the pattern unchanged.
pub(in crate::detections::rule::matchers) fn add_flag(
    pipe: &PipeElement,
    pattern: String,
) -> String {
    match pipe {
        PipeElement::ReIgnoreCase => "(?i)".to_string() + pattern.as_str(),
        PipeElement::ReMultiLine => "(?m)".to_string() + pattern.as_str(),
        PipeElement::ReSingleLine => "(?s)".to_string() + pattern.as_str(),
        _ => pattern,
    }
}

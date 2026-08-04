//! The numeric comparison modifiers `gt` / `lt` / `gte` / `lte`.

use super::PipeElement;

/// `|gt` / `|lt` / `|gte` / `|lte`: compares the event value numerically against the rule's
/// threshold. Returns false when the event value is not a base-10 `usize`.
pub(super) fn is_match(pipe: &PipeElement, event_value: Option<&String>) -> bool {
    let val = String::default();
    let event_val_str = event_value.unwrap_or(&val);
    match event_val_str.parse::<usize>() {
        Ok(event_val) => match pipe {
            PipeElement::Gt(n) => event_val > *n,
            PipeElement::Lt(n) => event_val < *n,
            PipeElement::Gte(n) => event_val >= *n,
            PipeElement::Lte(n) => event_val <= *n,
            _ => false,
        },
        Err(_) => false, // The event value is not numeric.
    }
}

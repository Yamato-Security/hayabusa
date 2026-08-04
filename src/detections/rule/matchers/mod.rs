use nested::Nested;
use yaml_rust2::Yaml;

use crate::detections::detection::EvtxRecordInfo;
use downcast_rs::Downcast;

mod default_matcher;
mod leaf_matchers;
mod modifiers;
mod pipe_element;

#[cfg(test)]
mod tests;

pub use default_matcher::DefaultMatcher;
pub use leaf_matchers::{AllowlistFileMatcher, MinlengthMatcher, RegexesFileMatcher};
pub use pipe_element::PipeElement;

#[cfg(test)]
pub use crate::detections::rule::fast_match::FastMatch;

/// Represents the logic for comparing event log values at leaf nodes.
/// A class implementing this trait exists for each kind of comparison logic, such as regex
/// matching and character count limits.
///
/// When creating a new class that implements LeafMatcher,
/// add an instance of the newly created class to the array returned by
/// LeafSelectionNode::get_matchers().
pub trait LeafMatcher: Downcast + Send + Sync {
    /// Determines whether this is a LeafMatcher matching the specified key_list.
    fn is_target_key(&self, key_list: &Nested<String>) -> bool;

    /// Determines whether the given event value matches. The value comes from the Windows event
    /// record after conversion to JSON in main.rs; e.g. a regex-based matcher performs its regex
    /// matching here.
    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool;

    /// Initializes the matcher from the rule file. Returns Err with parse error messages when
    /// the rule file format is invalid.
    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>>;

    /// Whether this matcher negates its result (i.e. the `neq` modifier is used).
    /// Callers that aggregate multiple values (e.g. multi-valued `EventData.Data`) need this so
    /// that the negation is applied once over the whole comparison rather than per value.
    fn is_negated(&self) -> bool {
        false
    }
}
downcast_rs::impl_downcast!(LeafMatcher);

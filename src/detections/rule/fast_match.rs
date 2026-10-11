use crate::detections::configs::WINDASH_CHARACTERS;
use crate::detections::rule::matchers::{PipeElement, SigmaPatternToken, parse_sigma_pattern};
use crate::detections::utils;

/// Since regex matching is slow, patterns that allow it are instead matched with the faster
/// std::string methods (len/starts_with/ends_with/contains) via this enum.
#[derive(PartialEq, Debug)]
pub enum FastMatch {
    Exact(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    // Produced by a leading "|all" modifier (a key such as "|all" with no field name); matched
    // the same way as Contains, but kept distinct so that callers can tell the two apart.
    AllOnly(String),
}

/// ASCII case-insensitive string equality.
pub fn eq_ignore_case(event_value_str: &str, match_str: &str) -> bool {
    if match_str.len() == event_value_str.len() {
        return match_str.eq_ignore_ascii_case(event_value_str);
    }
    false
}

/// ASCII case-insensitive starts_with. Returns None when the event value is not pure ASCII, in
/// which case the caller has to fall back to a regex match.
pub fn starts_with_ignore_case(event_value_str: &str, match_str: &str) -> Option<bool> {
    let len = match_str.len();
    if len > event_value_str.len() {
        return Some(false);
    }
    // ASCII only, because multibyte characters would cause an index out of bounds.
    if event_value_str.is_ascii() {
        let match_result = match_str.eq_ignore_ascii_case(&event_value_str[0..len]);
        return Some(match_result);
    }
    None
}

/// ASCII case-insensitive ends_with. Returns None when the event value is not pure ASCII, in
/// which case the caller has to fall back to a regex match.
pub fn ends_with_ignore_case(event_value_str: &str, match_str: &str) -> Option<bool> {
    let len1 = match_str.len();
    let len2 = event_value_str.len();
    if len1 > len2 {
        return Some(false);
    }
    // ASCII only, because multibyte characters would cause an index out of bounds.
    if event_value_str.is_ascii() {
        let match_result = match_str.eq_ignore_ascii_case(&event_value_str[len2 - len1..]);
        return Some(match_result);
    }
    None
}

/// Converts a wildcard pattern to FastMatch operations backed by the faster std::string methods
/// (len/starts_with/ends_with/contains) where possible, returning None for patterns that only
/// the regex engine can handle. When `ignore_case` is true, Contains/AllOnly patterns are stored
/// lowercased and check_fast_match() lowercases the event value before comparing;
/// Exact/StartsWith/EndsWith compare ASCII case-insensitively at match time instead.
pub fn convert_to_fast_match(pattern: &str, ignore_case: bool) -> Option<Vec<FastMatch>> {
    let tokens = parse_sigma_pattern(pattern);
    let has_wildcard = tokens.iter().any(|token| {
        matches!(
            token,
            SigmaPatternToken::AnyChars | SigmaPatternToken::AnyChar
        )
    });

    // `?`, complex `*` layouts, and non-ASCII wildcard patterns are evaluated by the regex path.
    if tokens
        .iter()
        .any(|token| matches!(token, SigmaPatternToken::AnyChar))
        || (!pattern.is_ascii() && has_wildcard)
    {
        return None;
    }

    let normalized_contains = |value: &str| {
        if ignore_case {
            value.to_lowercase()
        } else {
            value.to_string()
        }
    };

    match tokens.as_slice() {
        // `allOnly*` is an internal sentinel added by MatchPlan::build_fast_match() for `|all`.
        [
            SigmaPatternToken::Literal(prefix),
            SigmaPatternToken::AnyChars,
            SigmaPatternToken::Literal(value),
            SigmaPatternToken::AnyChars,
        ] if prefix == "allOnly" => Some(vec![FastMatch::AllOnly(normalized_contains(value))]),
        [
            SigmaPatternToken::Literal(prefix),
            SigmaPatternToken::AnyChars,
            SigmaPatternToken::AnyChars,
        ] if prefix == "allOnly" => Some(vec![FastMatch::AllOnly(String::new())]),
        [
            SigmaPatternToken::Literal(prefix),
            SigmaPatternToken::AnyChars,
        ] if prefix == "allOnly" => Some(vec![FastMatch::AllOnly(String::new())]),
        [] => Some(vec![FastMatch::Exact(String::new())]),
        [SigmaPatternToken::Literal(value)] => Some(vec![FastMatch::Exact(value.clone())]),
        [SigmaPatternToken::AnyChars] => Some(vec![FastMatch::EndsWith(String::new())]),
        [SigmaPatternToken::AnyChars, SigmaPatternToken::AnyChars] => {
            Some(vec![FastMatch::Contains(String::new())])
        }
        [
            SigmaPatternToken::Literal(value),
            SigmaPatternToken::AnyChars,
        ] => Some(vec![FastMatch::StartsWith(value.clone())]),
        [
            SigmaPatternToken::AnyChars,
            SigmaPatternToken::Literal(value),
        ] => Some(vec![FastMatch::EndsWith(value.clone())]),
        [
            SigmaPatternToken::AnyChars,
            SigmaPatternToken::Literal(value),
            SigmaPatternToken::AnyChars,
        ] => Some(vec![FastMatch::Contains(normalized_contains(value))]),
        _ => None,
    }
}

/// Evaluates the fast matchers against a field value. Returns None when the fast path cannot
/// decide (a non-ASCII value in a starts_with/ends_with comparison); the caller then falls back
/// to the regex match. A matcher list with more than one element holds alternative variants of a
/// single pattern (windash dash replacements or base64offset alignments), so any one Contains hit
/// is a match; base64 is case-sensitive, which is why that branch compares without lowercasing.
pub fn check_fast_match(
    pipes: &[PipeElement],
    event_value_str: &str,
    fast_matcher: &[FastMatch],
) -> Option<bool> {
    let windash_chars = WINDASH_CHARACTERS.as_slice();
    if fast_matcher.len() == 1 {
        match &fast_matcher[0] {
            FastMatch::Exact(s) => Some(eq_ignore_case(event_value_str, s)),
            FastMatch::StartsWith(s) => {
                if pipes.contains(&PipeElement::Cased) {
                    Some(event_value_str.starts_with(s))
                } else {
                    starts_with_ignore_case(event_value_str, s)
                }
            }
            FastMatch::EndsWith(s) => {
                if pipes.contains(&PipeElement::Cased) {
                    Some(event_value_str.ends_with(s))
                } else {
                    ends_with_ignore_case(event_value_str, s)
                }
            }
            FastMatch::Contains(s) | FastMatch::AllOnly(s) => {
                // For windash, compare with the value's first dash-like character replaced by
                // "/", mirroring how the windash pattern variants were generated.
                if pipes.contains(&PipeElement::Windash) {
                    Some(utils::contains_str(
                        &event_value_str
                            .replacen(windash_chars, "/", 1)
                            .to_lowercase(),
                        s,
                    ))
                } else if pipes.contains(&PipeElement::Cased) {
                    Some(utils::contains_str(event_value_str, s))
                } else {
                    Some(utils::contains_str(&event_value_str.to_lowercase(), s))
                }
            }
        }
    } else {
        Some(fast_matcher.iter().any(|fm| match fm {
            FastMatch::Contains(s) => {
                if pipes.contains(&PipeElement::Windash) {
                    utils::contains_str(
                        &event_value_str
                            .replacen(windash_chars, "/", 1)
                            .to_lowercase(),
                        s,
                    )
                } else {
                    utils::contains_str(event_value_str, s)
                }
            }
            // Variant lists are only ever built from Contains entries.
            _ => false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::rule::fast_match::{
        FastMatch, convert_to_fast_match, ends_with_ignore_case, eq_ignore_case,
        starts_with_ignore_case,
    };

    #[test]
    fn test_eq_ignore_case() {
        assert!(eq_ignore_case("abc", "abc"));
        assert!(eq_ignore_case("AbC", "abc"));
        assert!(!eq_ignore_case("abc", "ab"));
        assert!(!eq_ignore_case("ab", "abc"));
    }

    #[test]
    fn test_starts_with_ignore_case() {
        assert!(starts_with_ignore_case("abc", "ab").unwrap(),);
        assert!(starts_with_ignore_case("AbC", "ab").unwrap(),);
        assert!(!starts_with_ignore_case("abc", "abcd").unwrap(),);
        assert!(!starts_with_ignore_case("aab", "ab").unwrap(),);
    }

    #[test]
    fn test_ends_with_ignore_case() {
        assert!(ends_with_ignore_case("abc", "bc").unwrap());
        assert!(ends_with_ignore_case("AbC", "bc").unwrap());
        assert!(!ends_with_ignore_case("bc", "bcd").unwrap());
        assert!(!ends_with_ignore_case("bcd", "abc").unwrap());
    }

    #[test]
    fn test_convert_to_fast_match() {
        assert_eq!(convert_to_fast_match("ab?", true), None);
        assert_eq!(convert_to_fast_match("a*c", true), None);
        assert_eq!(convert_to_fast_match("*a*b", true), None);
        assert_eq!(convert_to_fast_match("*a*b*", true), None);
        assert_eq!(
            convert_to_fast_match(r"a\*", true).unwrap(),
            vec![FastMatch::Exact("a*".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"a\\\*", true).unwrap(),
            vec![FastMatch::Exact(r"a\*".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("abc*", true).unwrap(),
            vec![FastMatch::StartsWith("abc".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"abc\\*", true).unwrap(),
            vec![FastMatch::StartsWith(r"abc\".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"C:\Windows\\*", true).unwrap(),
            vec![FastMatch::StartsWith(r"C:\Windows\".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("*abc", true).unwrap(),
            vec![FastMatch::EndsWith("abc".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("*abc*", true).unwrap(),
            vec![FastMatch::Contains("abc".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("abc", true).unwrap(),
            vec![FastMatch::Exact("abc".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("あいう", true).unwrap(),
            vec![FastMatch::Exact("あいう".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"\\\\127.0.0.1\\", true).unwrap(),
            vec![FastMatch::Exact(r"\\127.0.0.1\".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"\\\\\*\\IPC$", true).unwrap(),
            vec![FastMatch::Exact(r"\\*\IPC$".to_string())]
        );
        assert_eq!(
            convert_to_fast_match("allOnly*", true).unwrap(),
            vec![FastMatch::AllOnly(String::new())]
        );
    }
}

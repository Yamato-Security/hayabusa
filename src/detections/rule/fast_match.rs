use crate::detections::configs::WINDASH_CHARACTERS;
use crate::detections::rule::matchers::PipeElement;
use crate::detections::utils;

// 正規表現マッチは遅いため、できるだけ高速なstd::stringのlen/starts_with/ends_with/containsでマッチ判定するためのenum
#[derive(PartialEq, Debug)]
pub enum FastMatch {
    Exact(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    AllOnly(String),
}

pub fn eq_ignore_case(event_value_str: &str, match_str: &str) -> bool {
    if match_str.len() == event_value_str.len() {
        return match_str.eq_ignore_ascii_case(event_value_str);
    }
    false
}

pub fn starts_with_ignore_case(event_value_str: &str, match_str: &str) -> Option<bool> {
    let len = match_str.len();
    if len > event_value_str.len() {
        return Some(false);
    }
    // マルチバイト文字を含む場合は、index out of boundsになるため、asciiのみ
    if event_value_str.is_ascii() {
        let match_result = match_str.eq_ignore_ascii_case(&event_value_str[0..len]);
        return Some(match_result);
    }
    None
}

pub fn ends_with_ignore_case(event_value_str: &str, match_str: &str) -> Option<bool> {
    let len1 = match_str.len();
    let len2 = event_value_str.len();
    if len1 > len2 {
        return Some(false);
    }
    // マルチバイト文字を含む場合は、index out of boundsになるため、asciiのみ
    if event_value_str.is_ascii() {
        let match_result = match_str.eq_ignore_ascii_case(&event_value_str[len2 - len1..]);
        return Some(match_result);
    }
    None
}

// ワイルドカードマッチを高速なstd::stringのlen/starts_with/ends_withに変換するための関数
pub fn convert_to_fast_match(s: &str, ignore_case: bool) -> Option<Vec<FastMatch>> {
    let wildcard_count = s.chars().filter(|c| *c == '*').count();
    let is_literal_asterisk = |s: &str| s.ends_with(r"\*") && !s.ends_with(r"\\*");
    if utils::contains_str(s, "?")
        || s.ends_with(r"\\\*")
        || (!s.is_ascii() && utils::contains_str(s, "*"))
    {
        // 高速なマッチに変換できないパターンは、正規表現マッチのみ
        return None;
    } else if s.starts_with("allOnly*") && s.ends_with('*') && wildcard_count == 2 {
        let removed_asterisk = s[8..(s.len() - 1)].replace(r"\\", r"\");
        if ignore_case {
            return Some(vec![FastMatch::AllOnly(removed_asterisk.to_lowercase())]);
        }
        return Some(vec![FastMatch::AllOnly(removed_asterisk)]);
    } else if s.starts_with('*')
        && s.ends_with('*')
        && wildcard_count == 2
        && !is_literal_asterisk(s)
    {
        let removed_asterisk = s[1..(s.len() - 1)].replace(r"\\", r"\");
        // *が先頭と末尾だけは、containsに変換
        if ignore_case {
            return Some(vec![FastMatch::Contains(removed_asterisk.to_lowercase())]);
        }
        return Some(vec![FastMatch::Contains(removed_asterisk)]);
    } else if s.starts_with('*') && wildcard_count == 1 && !is_literal_asterisk(s) {
        // *が先頭は、ends_withに変換
        return Some(vec![FastMatch::EndsWith(s[1..].replace(r"\\", r"\"))]);
    } else if s.ends_with('*') && wildcard_count == 1 && !is_literal_asterisk(s) {
        // *が末尾は、starts_withに変換
        return Some(vec![FastMatch::StartsWith(
            s[..(s.len() - 1)].replace(r"\\", r"\"),
        )]);
    } else if utils::contains_str(s, "*") {
        // *が先頭・末尾以外にあるパターンは、starts_with/ends_withに変換できないため、正規表現マッチのみ
        return None;
    }
    // *を含まない場合は、文字列長マッチに変換
    Some(vec![FastMatch::Exact(s.replace(r"\\", r"\"))])
}

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
            _ => false,
        }))
    }
}

pub fn create_fast_match(pipes: &[PipeElement], pattern: &[String]) -> Option<Vec<FastMatch>> {
    if let Some(element) = pipes.first() {
        match element {
            PipeElement::Startswith => {
                convert_to_fast_match(format!("{}*", pattern[0]).as_str(), true)
            }
            PipeElement::Endswith => {
                convert_to_fast_match(format!("*{}", pattern[0]).as_str(), true)
            }
            PipeElement::Contains => {
                convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true)
            }
            PipeElement::AllOnly => {
                convert_to_fast_match(format!("allOnly*{}*", pattern[0]).as_str(), true)
            }
            _ => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::rule::fast_match::{
        convert_to_fast_match, ends_with_ignore_case, eq_ignore_case, starts_with_ignore_case,
        FastMatch,
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
        assert_eq!(convert_to_fast_match(r"a\*", true), None);
        assert_eq!(convert_to_fast_match(r"a\\\*", true), None);
        assert_eq!(
            convert_to_fast_match("abc*", true).unwrap(),
            vec![FastMatch::StartsWith("abc".to_string())]
        );
        assert_eq!(
            convert_to_fast_match(r"abc\\*", true).unwrap(),
            vec![FastMatch::StartsWith(r"abc\".to_string())]
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
    }
}

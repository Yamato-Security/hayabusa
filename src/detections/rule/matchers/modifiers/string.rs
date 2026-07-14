//! The string-wrapping modifiers (`startswith`, `endswith`, `contains`) and the
//! wildcard-to-regex conversion used for the default (implicit) wildcard match.

use super::PipeElement;

/// Applies a `startswith`/`endswith`/`contains` wrap to `pattern` by inserting the surrounding
/// wildcards, and converts `wildcard` patterns to a regex. Any other modifier returns `pattern`
/// unchanged.
pub(in crate::detections::rule::matchers) fn wrap_pattern(
    pipe: &PipeElement,
    pattern: String,
) -> String {
    // When implementing polymorphism with an enum, every variant's implementation ends up in a
    // single method. This may feel odd to developers used to Java-style class hierarchies.
    let add_asterisk_end = |pattern: String| {
        if pattern.ends_with("//*") {
            pattern
        } else if pattern.ends_with("/*") {
            pattern + "*"
        } else if pattern.ends_with('*') {
            pattern
        } else if pattern.ends_with('\\') {
            // If the pattern ends with \ (a single backslash), turn the ending into \\*
            // (two backslashes and an asterisk): in wildcard notation a trailing \\* means a
            // literal backslash followed by the * wildcard.
            pattern + "\\*"
        } else {
            pattern + "*"
        }
    };
    let add_asterisk_begin = |pattern: String| {
        if pattern.starts_with("//*") {
            pattern
        } else if pattern.starts_with("/*") {
            "*".to_string() + &pattern
        } else if pattern.starts_with('*') {
            pattern
        } else {
            "*".to_string() + &pattern
        }
    };

    match pipe {
        // For startswith, handle by appending a wildcard to the end of pattern.
        PipeElement::Startswith => add_asterisk_end(pattern),
        // For endswith, handle by prepending a wildcard to the beginning of pattern.
        PipeElement::Endswith => add_asterisk_begin(pattern),
        // For contains, handle by prepending and appending wildcards to pattern.
        PipeElement::Contains => add_asterisk_end(add_asterisk_begin(pattern)),
        // Convert WildCard to regex.
        PipeElement::Wildcard => wildcard_to_regex(pattern),
        _ => pattern,
    }
}

/// Converts SIGMA rule wildcard notation (`*`, `?`) into a case-insensitive regex.
/// This processing could have been included in `wrap_pattern`, but it became complex, so it was
/// split out into its own function.
pub(in crate::detections::rule::matchers) fn wildcard_to_regex(pattern: String) -> String {
    let wildcards = vec!["*", "?"];

    // Put the result of splitting pattern by wildcard into pattern_splits.
    // With the following algorithm, elements at even indices of pattern_splits are non-wildcard strings, and elements at odd indices contain wildcards.
    let mut idx = 0;
    let mut pattern_splits = vec![];
    let mut cur_str = String::default();
    while idx < pattern.len() {
        let prev_idx = idx;
        for wildcard in &wildcards {
            let cur_pattern: String = pattern.chars().skip(idx).collect::<String>();
            if cur_pattern.starts_with(&format!(r"\\{wildcard}")) {
                // When there are two escape characters before the wildcard.
                cur_str = format!("{}{}", cur_str, r"\");
                pattern_splits.push(cur_str);
                pattern_splits.push(wildcard.to_string());

                cur_str = String::default();
                idx += 3;
                break;
            } else if cur_pattern.starts_with(&format!(r"\{wildcard}")) {
                // When there is one escape character before the wildcard.
                cur_str = format!("{cur_str}{wildcard}");
                idx += 2;
                break;
            } else if cur_pattern.starts_with(wildcard) {
                // When it is a wildcard.
                pattern_splits.push(cur_str);
                pattern_splits.push(wildcard.to_string());

                cur_str = String::default();
                idx += 1;
                break;
            }
        }
        // If one of the wildcard branches above matched, idx has already been advanced, so
        // continue with the next chunk.
        if prev_idx != idx {
            continue;
        }

        cur_str = format!(
            "{}{}",
            cur_str,
            pattern.chars().skip(idx).take(1).collect::<String>()
        );
        idx += 1;
    }
    // If the last character is not a wildcard, cur_str contains characters, so put them into pattern_splits.
    if !cur_str.is_empty() {
        pattern_splits.push(cur_str);
    }

    // Convert from SIGMA rule wildcard notation to regex notation.
    let ret =
        pattern_splits
            .iter()
            .enumerate()
            .fold(String::default(), |acc: String, (idx, pattern)| {
                let regex_value = if idx % 2 == 0 {
                    // If not a wildcard, return the escaped string.
                    regex::escape(pattern)
                } else {
                    // When it is a wildcard, convert "*" into a ".*"-style regex (an alternation
                    // that additionally matches the newline, which "." alone does not) and convert
                    // "?" into ".".
                    let wildcard_regex_value = if *pattern == "*" {
                        "(.|\\a|\\f|\\t|\\n|\\r|\\v)*"
                    } else {
                        "."
                    };
                    wildcard_regex_value.to_string()
                };

                format!("{acc}{regex_value}")
            });

    // Sigma wildcards are case-insensitive.
    // Therefore, prepend the case-insensitive flag to the regex.
    "(?i)".to_string() + &ret
}

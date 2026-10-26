//! The string-wrapping modifiers (`startswith`, `endswith`, `contains`) and the
//! wildcard-to-regex conversion used for the default (implicit) wildcard match.

use super::PipeElement;
use crate::detections::configs::WINDASH_CHARACTERS;

/// One element of a Sigma string after its escape sequences have been parsed.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::detections::rule) enum SigmaPatternToken {
    Literal(String),
    AnyChars,
    AnyChar,
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Expands Windows command-line option prefixes into every configured `windash` spelling.
///
/// A dash is an option prefix when it is not preceded by a word character and is followed by one,
/// matching pySigma's `\B[-/]\b` boundary behavior. Expanding the rule instead of normalizing the
/// complete event preserves literal dashes whose boundary context differs between the rule and the
/// event, such as the trailing dash in a `contains|windash: ' -'` pattern. Internal dashes such as
/// the one in `param-name` are left untouched.
pub(in crate::detections::rule) fn expand_windash(value: &str) -> Vec<String> {
    let characters = value.chars().collect::<Vec<_>>();
    let mut dash_characters = vec!['-', '/'];
    dash_characters.extend(WINDASH_CHARACTERS.iter().copied());
    dash_characters.sort_unstable();
    dash_characters.dedup();
    let mut variants = vec![String::new()];

    for (index, character) in characters.iter().copied().enumerate() {
        let previous = index.checked_sub(1).map(|index| characters[index]);
        let next = characters.get(index + 1).copied();
        let is_dash = character == '/' || WINDASH_CHARACTERS.contains(&character);
        let is_option_prefix = is_dash
            && previous.is_none_or(|previous| !is_word_character(previous))
            && next.is_some_and(is_word_character);

        if is_option_prefix {
            variants = variants
                .into_iter()
                .flat_map(|variant| {
                    dash_characters.iter().map(move |dash| {
                        let mut expanded = variant.clone();
                        expanded.push(*dash);
                        expanded
                    })
                })
                .collect();
        } else {
            for variant in &mut variants {
                variant.push(character);
            }
        }
    }

    variants
}

/// Parses Sigma escaping from left to right. Backslashes escape `\\`, `*`, and `?`; a
/// backslash before any other character remains literal. Pairing the escapes before classifying
/// wildcards is important for values such as `\\\*`: this is a literal backslash followed by
/// a literal asterisk, not two backslashes followed by a wildcard.
pub(in crate::detections::rule) fn parse_sigma_pattern(pattern: &str) -> Vec<SigmaPatternToken> {
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut chars = pattern.chars().peekable();

    let flush_literal = |tokens: &mut Vec<SigmaPatternToken>, literal: &mut String| {
        if !literal.is_empty() {
            tokens.push(SigmaPatternToken::Literal(std::mem::take(literal)));
        }
    };

    while let Some(character) = chars.next() {
        match character {
            '\\' => match chars.peek().copied() {
                Some(next @ ('\\' | '*' | '?')) => {
                    chars.next();
                    literal.push(next);
                }
                _ => literal.push('\\'),
            },
            '*' => {
                flush_literal(&mut tokens, &mut literal);
                tokens.push(SigmaPatternToken::AnyChars);
            }
            '?' => {
                flush_literal(&mut tokens, &mut literal);
                tokens.push(SigmaPatternToken::AnyChar);
            }
            _ => literal.push(character),
        }
    }
    flush_literal(&mut tokens, &mut literal);
    tokens
}

fn starts_with_any_chars(pattern: &str) -> bool {
    matches!(
        parse_sigma_pattern(pattern).first(),
        Some(SigmaPatternToken::AnyChars)
    )
}

fn ends_with_any_chars(pattern: &str) -> bool {
    matches!(
        parse_sigma_pattern(pattern).last(),
        Some(SigmaPatternToken::AnyChars)
    )
}

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
        if ends_with_any_chars(&pattern) {
            pattern
        } else {
            // Preserve the number of literal trailing backslashes when placing an unescaped
            // wildcard after them. An odd run needs one more backslash to complete its final
            // escape pair; an even run can be followed by `*` directly.
            let trailing_backslashes = pattern.chars().rev().take_while(|c| *c == '\\').count();
            if trailing_backslashes % 2 == 1 {
                pattern + "\\*"
            } else {
                pattern + "*"
            }
        }
    };
    let add_asterisk_begin = |pattern: String| {
        if starts_with_any_chars(&pattern) {
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
    let ret =
        parse_sigma_pattern(&pattern)
            .iter()
            .fold(String::new(), |mut regex_pattern, token| {
                match token {
                    SigmaPatternToken::Literal(value) => {
                        regex_pattern.push_str(&regex::escape(value))
                    }
                    // Use an alternation so `*` also matches newlines, which `.` alone does not.
                    SigmaPatternToken::AnyChars => {
                        regex_pattern.push_str("(.|\\a|\\f|\\t|\\n|\\r|\\v)*")
                    }
                    SigmaPatternToken::AnyChar => regex_pattern.push('.'),
                }
                regex_pattern
            });

    // Sigma wildcards are case-insensitive.
    // Therefore, prepend the case-insensitive flag to the regex.
    "(?i)".to_string() + &ret
}

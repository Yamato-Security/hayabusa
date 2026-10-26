//! The string-wrapping modifiers (`startswith`, `endswith`, `contains`) and the
//! wildcard-to-regex conversion used for the default (implicit) wildcard match.

use super::PipeElement;
use crate::detections::configs::WINDASH_CHARACTERS;

// Reserved noncharacter used only while a rule pattern is being converted to regex. It keeps a
// windash position distinct from ordinary literals without exposing regex syntax to Sigma's
// wildcard parser.
const WINDASH_MARKER: char = '\u{FDD0}';

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

/// Marks Windows command-line option prefixes for compact `windash` regex generation.
///
/// A dash is an option prefix when it is not preceded by a word character and is followed by one,
/// matching pySigma's `\B[-/]\b` boundary behavior. Marking the rule instead of normalizing the
/// complete event preserves literal dashes whose boundary context differs between the rule and the
/// event, such as the trailing dash in a `contains|windash: ' -'` pattern. Each marker becomes one
/// regex character class, avoiding Cartesian expansion when a pattern has several options.
pub(in crate::detections::rule) fn mark_windash(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let mut marked = String::with_capacity(value.len());

    for (index, character) in characters.iter().copied().enumerate() {
        let previous = index.checked_sub(1).map(|index| characters[index]);
        let next = characters.get(index + 1).copied();
        let is_dash = character == '/' || WINDASH_CHARACTERS.contains(&character);
        let is_option_prefix = is_dash
            && previous.is_none_or(|previous| !is_word_character(previous))
            && next.is_some_and(is_word_character);

        if is_option_prefix {
            marked.push(WINDASH_MARKER);
        } else {
            marked.push(character);
        }
    }

    marked
}

fn windash_regex_class() -> String {
    let mut dash_characters = vec!['-', '/'];
    dash_characters.extend(WINDASH_CHARACTERS.iter().copied());
    dash_characters.sort_unstable();
    dash_characters.dedup();

    let alternatives = dash_characters
        .iter()
        .map(|character| regex::escape(&character.to_string()))
        .collect::<String>();
    format!("[{alternatives}]")
}

/// Replaces markers inserted by [`mark_windash`] with compact regex character classes. This is
/// used for an explicit regex path, where no wildcard conversion runs afterward.
pub(in crate::detections::rule::matchers) fn render_marked_windash(pattern: String) -> String {
    pattern.replace(WINDASH_MARKER, &windash_regex_class())
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
    wildcard_to_regex_with_options(pattern, true, false)
}

/// Converts Sigma wildcard notation to regex, optionally preserving case and expanding the
/// internal markers inserted by [`mark_windash`] into one compact character class each.
pub(in crate::detections::rule::matchers) fn wildcard_to_regex_with_options(
    pattern: String,
    ignore_case: bool,
    has_windash: bool,
) -> String {
    let windash_class = has_windash.then(windash_regex_class);
    let ret =
        parse_sigma_pattern(&pattern)
            .iter()
            .fold(String::new(), |mut regex_pattern, token| {
                match token {
                    SigmaPatternToken::Literal(value) if has_windash => {
                        for (index, literal) in value.split(WINDASH_MARKER).enumerate() {
                            if index > 0 {
                                regex_pattern.push_str(windash_class.as_ref().unwrap());
                            }
                            regex_pattern.push_str(&regex::escape(literal));
                        }
                    }
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

    if ignore_case {
        // Sigma wildcards are case-insensitive unless the `cased` modifier is present.
        "(?i)".to_string() + &ret
    } else {
        ret
    }
}

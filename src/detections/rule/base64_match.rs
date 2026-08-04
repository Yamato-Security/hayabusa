use crate::detections::rule::fast_match::{FastMatch, convert_to_fast_match};
use crate::detections::rule::matchers::PipeElement;
use base64::Engine;
use base64::engine::general_purpose;
use std::io::Write;
use std::string::FromUtf8Error;

/// Implements the Sigma base64offset modifier. Base64 encodes each group of 3 input bytes into 4
/// output characters, so a value embedded somewhere inside an encoded stream can appear in one of
/// three forms depending on its byte offset (0, 1 or 2) within a group. This generates all three
/// variants and returns them as FastMatch::Contains patterns (any one of them matching is a hit).
/// `encode` optionally converts the pattern to UTF-16LE/BE before base64-encoding it.
pub fn convert_to_base64_str(
    encode: Option<&PipeElement>,
    original_str: &str,
    err_msgs: &mut Vec<String>,
) -> Option<Vec<FastMatch>> {
    let mut fastmatches = vec![];
    for offset in 0..3 {
        let encoded_result = make_base64_str(encode, original_str, offset);
        match encoded_result {
            Ok(b64_str) => {
                let b64_s_null_filtered = b64_str.replace('\0', "");
                let b64_offset_contents = base64_offset(offset, b64_str, b64_s_null_filtered);
                if let Some(fm) = convert_to_fast_match(&format!("*{b64_offset_contents}*"), false)
                {
                    fastmatches.extend(fm);
                }
            }
            Err(e) => {
                err_msgs.push(format!("Failed base64 encoding: {e}"));
            }
        }
    }
    if fastmatches.is_empty() {
        return None;
    }
    Some(fastmatches)
}

/// Base64-encodes `original_str` (as UTF-8, or as UTF-16LE/BE when `encode` says so) after prepending
/// `variant_index` (0-2) dummy NUL bytes, which shifts the value to the corresponding offset
/// within the base64 3-byte groups. The result can contain trailing NUL bytes because the output
/// buffer is oversized; the caller strips them.
fn make_base64_str(
    encode: Option<&PipeElement>,
    original_str: &str,
    variant_index: usize,
) -> Result<String, FromUtf8Error> {
    let mut b64_result = vec![];
    let mut target_byte = vec![];
    // Prepend variant_index dummy NUL bytes to shift the encoding alignment.
    target_byte.resize_with(variant_index, || 0b0);
    if let Some(en) = encode.as_ref() {
        match en {
            PipeElement::Utf16Be => {
                let mut buffer = Vec::new();
                for utf16 in original_str.encode_utf16() {
                    buffer.write_all(&utf16.to_be_bytes()).unwrap();
                }
                target_byte.extend_from_slice(buffer.as_slice())
            }
            PipeElement::Utf16Le | PipeElement::Wide => {
                let mut buffer = Vec::new();
                for utf16 in original_str.encode_utf16() {
                    buffer.write_all(&utf16.to_le_bytes()).unwrap();
                }
                target_byte.extend_from_slice(buffer.as_slice())
            }
            _ => target_byte.extend_from_slice(original_str.as_bytes()),
        }
    } else {
        target_byte.extend_from_slice(original_str.as_bytes());
    }
    // Reserve more than enough space for encode_slice(); unused bytes stay NUL.
    b64_result.resize_with(target_byte.len() * 4 / 3 + 4, || 0b0);
    general_purpose::STANDARD
        .encode_slice(target_byte, &mut b64_result)
        .ok();
    String::from_utf8(b64_result)
}

/// Cuts off the characters of an offset-shifted base64 string that are not fully determined by
/// the original value, leaving a substring that always appears in a real encoded stream:
/// - Start: the characters produced by the dummy NUL bytes plus the one character that mixes
///   dummy and real bits, i.e. offset + 1 characters when offset != 0.
/// - End: the characters that share bits with whatever (unknown) bytes follow the value in the
///   stream, derived from the padding position. A first '=' at index % 4 == 2 means the last
///   group held one real byte, so the ambiguous second character and "==" are dropped (3 chars);
///   index % 4 == 3 means two real bytes, so one character and '=' are dropped (2 chars). With no
///   padding the last group is complete and nothing is dropped (find() returns None and
///   unwrap_or_default() yields 0, which selects the fall-through arm).
fn base64_offset(offset: usize, b64_str: String, b64_str_null_filtered: String) -> String {
    match b64_str.find('=').unwrap_or_default() % 4 {
        2 => {
            if offset == 0 {
                b64_str_null_filtered[..b64_str_null_filtered.len() - 3].to_string()
            } else {
                b64_str_null_filtered[(offset + 1)..b64_str_null_filtered.len() - 3].to_string()
            }
        }
        3 => {
            if offset == 0 {
                b64_str_null_filtered[..b64_str_null_filtered.len() - 2].to_string()
            } else {
                b64_str_null_filtered.replace('\0', "")
                    [(offset + 1)..b64_str_null_filtered.len() - 2]
                    .to_string()
            }
        }
        _ => {
            if offset == 0 {
                b64_str_null_filtered
            } else {
                b64_str_null_filtered[(offset + 1)..].to_string()
            }
        }
    }
}

/// Base64-encodes `input` as UTF-8 without padding, so that the result can be used as a substring
/// (contains) pattern inside a longer base64 stream.
pub fn to_base64_utf8(input: &str) -> String {
    general_purpose::STANDARD_NO_PAD.encode(input)
}

/// Base64-encodes `input` as UTF-16LE without padding, optionally prefixed with a BOM
/// (0xFF 0xFE): Sigma's |utf16|base64 implies UTF-16LE with a BOM, whereas |utf16le|/|wide|
/// encode without one.
pub fn to_base64_utf16le_with_bom(input: &str, with_bom: bool) -> String {
    let mut utf16_bytes: Vec<u8> = Vec::new();

    if with_bom {
        utf16_bytes.extend_from_slice(&[0xFF, 0xFE]);
    }

    utf16_bytes.extend(
        input
            .encode_utf16()
            .flat_map(|code_unit| code_unit.to_le_bytes()),
    );

    general_purpose::STANDARD_NO_PAD.encode(&utf16_bytes)
}

/// Base64-encodes `input` as UTF-16BE without padding.
pub fn to_base64_utf16be(input: &str) -> String {
    let utf16_bytes: Vec<u8> = input
        .encode_utf16()
        .flat_map(|code_unit| code_unit.to_be_bytes())
        .collect();
    general_purpose::STANDARD_NO_PAD.encode(&utf16_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_offset() {
        let b64_str = "aGVsbG8gd29ybGQ=".to_string();
        let b64_str_null_filtered = "aGVsbG8gd29ybGQ=".to_string();
        assert_eq!(
            base64_offset(0, b64_str.clone(), b64_str_null_filtered.clone()),
            "aGVsbG8gd29ybG"
        );
        assert_eq!(
            base64_offset(1, b64_str.clone(), b64_str_null_filtered.clone()),
            "VsbG8gd29ybG"
        );
        assert_eq!(
            base64_offset(2, b64_str.clone(), b64_str_null_filtered.clone()),
            "sbG8gd29ybG"
        );
    }

    #[test]
    fn test_convert_to_base64_str_utf8() {
        let mut err_msgs = vec![];
        let val = "Hello, world!";
        let matches = convert_to_base64_str(None, val, &mut err_msgs).unwrap();
        assert_eq!(
            matches[0],
            FastMatch::Contains("SGVsbG8sIHdvcmxkI".to_string())
        );
        assert_eq!(
            matches[1],
            FastMatch::Contains("hlbGxvLCB3b3JsZC".to_string())
        );
        assert_eq!(
            matches[2],
            FastMatch::Contains("IZWxsbywgd29ybGQh".to_string())
        );
    }

    #[test]
    fn test_convert_to_base64_str_wide() {
        let mut err_msgs = vec![];
        let val = "Hello, world!";
        let matches = convert_to_base64_str(Some(&PipeElement::Wide), val, &mut err_msgs).unwrap();
        assert_eq!(
            matches[0],
            FastMatch::Contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ".to_string())
        );
        assert_eq!(
            matches[1],
            FastMatch::Contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA".to_string())
        );
        assert_eq!(
            matches[2],
            FastMatch::Contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA".to_string())
        );
    }
    #[test]
    fn test_convert_to_base64_str_utf16le() {
        let mut err_msgs = vec![];
        let val = "Hello, world!";
        let matches =
            convert_to_base64_str(Some(&PipeElement::Utf16Le), val, &mut err_msgs).unwrap();
        assert_eq!(
            matches[0],
            FastMatch::Contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ".to_string())
        );
        assert_eq!(
            matches[1],
            FastMatch::Contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA".to_string())
        );
        assert_eq!(
            matches[2],
            FastMatch::Contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA".to_string())
        );
    }

    #[test]
    fn test_convert_to_base64_str_utf16be() {
        let mut err_msgs = vec![];
        let val = "Hello, world!";
        let matches =
            convert_to_base64_str(Some(&PipeElement::Utf16Be), val, &mut err_msgs).unwrap();
        assert_eq!(
            matches[0],
            FastMatch::Contains("AEgAZQBsAGwAbwAsACAAdwBvAHIAbABkAC".to_string())
        );
        assert_eq!(
            matches[1],
            FastMatch::Contains("BIAGUAbABsAG8ALAAgAHcAbwByAGwAZAAh".to_string())
        );
        assert_eq!(
            matches[2],
            FastMatch::Contains("ASABlAGwAbABvACwAIAB3AG8AcgBsAGQAI".to_string())
        );
    }

    #[test]
    fn test_to_base64_utf16be() {
        assert_eq!(to_base64_utf16be("A"), "AEE");
        assert_eq!(to_base64_utf16be("Hello"), "AEgAZQBsAGwAbw");
        assert_eq!(to_base64_utf16be("こんにちは"), "MFMwkzBrMGEwbw");
        assert_eq!(to_base64_utf16be(""), "");
    }

    #[test]
    fn test_to_base64_utf16le_with_bom() {
        // Without a BOM (same result as the pre-existing function)
        assert_eq!(to_base64_utf16le_with_bom("A", false), "QQA");
        assert_eq!(to_base64_utf16le_with_bom("Hello", false), "SABlAGwAbABvAA");
        assert_eq!(to_base64_utf16le_with_bom("", false), "");

        // With a BOM (0xFF 0xFE is prepended)
        assert_eq!(to_base64_utf16le_with_bom("A", true), "//5BAA");
        assert_eq!(
            to_base64_utf16le_with_bom("Hello", true),
            "//5IAGUAbABsAG8A"
        );
        assert_eq!(to_base64_utf16le_with_bom("", true), "//4");

        // Test with Japanese strings
        assert_eq!(
            to_base64_utf16le_with_bom("こんにちは", false),
            "UzCTMGswYTBvMA"
        );
        assert_eq!(
            to_base64_utf16le_with_bom("こんにちは", true),
            "//5TMJMwazBhMG8w"
        );
    }

    #[test]
    fn test_utf16_comparison() {
        let input = "テスト";
        let utf16le = to_base64_utf16le_with_bom(input, false);
        let utf16be = to_base64_utf16be(input);

        // Verify that UTF-16LE and UTF-16BE produce different results
        assert_ne!(utf16le, utf16be);

        // Verify that UTF-8 and UTF-16 also produce different results
        let utf8 = to_base64_utf8(input);
        assert_ne!(utf8, utf16le);
        assert_ne!(utf8, utf16be);
    }

    #[test]
    fn test_to_base64_utf8() {
        // Basic English strings
        assert_eq!(to_base64_utf8("Hello"), "SGVsbG8");
        assert_eq!(to_base64_utf8("A"), "QQ");
        assert_eq!(to_base64_utf8("Hello, World!"), "SGVsbG8sIFdvcmxkIQ");

        // Empty string
        assert_eq!(to_base64_utf8(""), "");

        // Japanese strings
        assert_eq!(to_base64_utf8("こんにちは"), "44GT44KT44Gr44Gh44Gv");
        assert_eq!(to_base64_utf8("テスト"), "44OG44K544OI");

        // Digits and symbols
        assert_eq!(to_base64_utf8("123"), "MTIz");
        assert_eq!(to_base64_utf8("!@#$%"), "IUAjJCU");

        // String containing a newline character
        assert_eq!(to_base64_utf8("line1\nline2"), "bGluZTEKbGluZTI");

        // Special UTF-8 characters
        assert_eq!(to_base64_utf8("🎉"), "8J+OiQ");
        assert_eq!(to_base64_utf8("café"), "Y2Fmw6k");
    }
}

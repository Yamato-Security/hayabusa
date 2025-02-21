use crate::detections::rule::fast_match::{FastMatch, convert_to_fast_match};
use crate::detections::rule::matchers::PipeElement;
use base64::Engine;
use base64::engine::general_purpose;
use std::io::Write;
use std::string::FromUtf8Error;

pub fn convert_to_base64_str(
    encode: Option<&PipeElement>,
    org_str: &str,
    err_msges: &mut Vec<String>,
) -> Option<Vec<FastMatch>> {
    let mut fastmatches = vec![];
    for i in 0..3 {
        let convstr_b64 = make_base64_str(encode, org_str, i);
        match convstr_b64 {
            Ok(b64_str) => {
                let b64_s_null_filtered = b64_str.replace('\0', "");
                let b64_offset_contents = base64_offset(i, b64_str, b64_s_null_filtered);
                if let Some(fm) = convert_to_fast_match(&format!("*{b64_offset_contents}*"), false)
                {
                    fastmatches.extend(fm);
                }
            }
            Err(e) => {
                err_msges.push(format!("Failed base64 encoding: {}", e));
            }
        }
    }
    if fastmatches.is_empty() {
        return None;
    }
    Some(fastmatches)
}

fn make_base64_str(
    encode: Option<&PipeElement>,
    org_str: &str,
    variant_index: usize,
) -> Result<String, FromUtf8Error> {
    let mut b64_result = vec![];
    let mut target_byte = vec![];
    target_byte.resize_with(variant_index, || 0b0);
    if let Some(en) = encode.as_ref() {
        match en {
            PipeElement::Utf16Be => {
                let mut buffer = Vec::new();
                for utf16 in org_str.encode_utf16() {
                    buffer.write_all(&utf16.to_be_bytes()).unwrap();
                }
                target_byte.extend_from_slice(buffer.as_slice())
            }
            PipeElement::Utf16Le | PipeElement::Wide => {
                let mut buffer = Vec::new();
                for utf16 in org_str.encode_utf16() {
                    buffer.write_all(&utf16.to_le_bytes()).unwrap();
                }
                target_byte.extend_from_slice(buffer.as_slice())
            }
            _ => target_byte.extend_from_slice(org_str.as_bytes()),
        }
    } else {
        target_byte.extend_from_slice(org_str.as_bytes());
    }
    b64_result.resize_with(target_byte.len() * 4 / 3 + 4, || 0b0);
    general_purpose::STANDARD
        .encode_slice(target_byte, &mut b64_result)
        .ok();
    String::from_utf8(b64_result)
}

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
        let mut err_msges = vec![];
        let val = "Hello, world!";
        let m = convert_to_base64_str(None, val, &mut err_msges).unwrap();
        assert_eq!(m[0], FastMatch::Contains("SGVsbG8sIHdvcmxkI".to_string()));
        assert_eq!(m[1], FastMatch::Contains("hlbGxvLCB3b3JsZC".to_string()));
        assert_eq!(m[2], FastMatch::Contains("IZWxsbywgd29ybGQh".to_string()));
    }

    #[test]
    fn test_convert_to_base64_str_wide() {
        let mut err_msges = vec![];
        let val = "Hello, world!";
        let m = convert_to_base64_str(Some(&PipeElement::Wide), val, &mut err_msges).unwrap();
        assert_eq!(
            m[0],
            FastMatch::Contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ".to_string())
        );
        assert_eq!(
            m[1],
            FastMatch::Contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA".to_string())
        );
        assert_eq!(
            m[2],
            FastMatch::Contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA".to_string())
        );
    }
    #[test]
    fn test_convert_to_base64_str_utf16le() {
        let mut err_msges = vec![];
        let val = "Hello, world!";
        let m = convert_to_base64_str(Some(&PipeElement::Utf16Le), val, &mut err_msges).unwrap();
        assert_eq!(
            m[0],
            FastMatch::Contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ".to_string())
        );
        assert_eq!(
            m[1],
            FastMatch::Contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA".to_string())
        );
        assert_eq!(
            m[2],
            FastMatch::Contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA".to_string())
        );
    }

    #[test]
    fn test_convert_to_base64_str_utf16be() {
        let mut err_msges = vec![];
        let val = "Hello, world!";
        let m = convert_to_base64_str(Some(&PipeElement::Utf16Be), val, &mut err_msges).unwrap();
        assert_eq!(
            m[0],
            FastMatch::Contains("AEgAZQBsAGwAbwAsACAAdwBvAHIAbABkAC".to_string())
        );
        assert_eq!(
            m[1],
            FastMatch::Contains("BIAGUAbABsAG8ALAAgAHcAbwByAGwAZAAh".to_string())
        );
        assert_eq!(
            m[2],
            FastMatch::Contains("ASABlAGwAbABvACwAIAB3AG8AcgBsAGQAI".to_string())
        );
    }
}

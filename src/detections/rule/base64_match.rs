use crate::detections::rule::fast_match::{convert_to_fast_match, FastMatch};
use base64::engine::general_purpose;
use base64::Engine;

pub fn convert_to_base64_str(val: &str, err_msges: &mut Vec<String>) -> Option<Vec<FastMatch>> {
    // |base64offset|containsの場合
    let mut fastmatches = vec![];
    for i in 0..3 {
        let mut b64_result = vec![];
        let mut target_byte = vec![];
        target_byte.resize_with(i, || 0b0);
        target_byte.extend_from_slice(val.as_bytes());
        b64_result.resize_with(target_byte.len() * 4 / 3 + 4, || 0b0);
        general_purpose::STANDARD
            .encode_slice(target_byte, &mut b64_result)
            .ok();
        let convstr_b64 = String::from_utf8(b64_result);
        if let Ok(b64_str) = convstr_b64 {
            // ここでContainsのfastmatch対応を行う
            let b64_s_null_filtered = b64_str.replace('\0', "");
            let b64_offset_contents = base64_offset(i, b64_str, b64_s_null_filtered);
            if let Some(fm) = convert_to_fast_match(&format!("*{b64_offset_contents}*"), false) {
                fastmatches.extend(fm);
            }
        } else {
            err_msges.push(format!(
                "Failed base64 encoding: {}",
                convstr_b64.unwrap_err()
            ));
        }
    }
    if fastmatches.is_empty() {
        return None;
    }
    Some(fastmatches)
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
    fn test_convert_to_base64_str() {
        let mut err_msges = vec![];
        let val = "Hello, world!";
        let fastmatches = convert_to_base64_str(val, &mut err_msges).unwrap();
        assert_eq!(
            fastmatches[0],
            FastMatch::Contains("SGVsbG8sIHdvcmxkI".to_string())
        );
        assert_eq!(
            fastmatches[1],
            FastMatch::Contains("hlbGxvLCB3b3JsZC".to_string())
        );
        assert_eq!(
            fastmatches[2],
            FastMatch::Contains("IZWxsbywgd29ybGQh".to_string())
        );
    }
}

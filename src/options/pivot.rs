use indexmap::{IndexMap, IndexSet};
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::RwLock;
use termcolor::{BufferWriter, Color, ColorChoice};

use crate::detections::utils::{
    get_event_value, get_serde_number_to_string, get_writable_color, write_color_buffer,
};

use crate::detections::configs::{EventKeyAliasConfig, StoredStatic};

/// One pivot keyword category (e.g. "Ip Addresses" or "Users") defined in the pivot keywords
/// config file.
#[derive(Debug)]
pub struct PivotKeyword {
    /// Unique field values harvested from the scanned records.
    pub keywords: IndexSet<String>,
    /// Event field names (eventkey aliases) whose values should be collected for this category.
    pub fields: IndexSet<String>,
}

/// Map of pivot keyword category name -> PivotKeyword. The categories and their fields are loaded
/// from the pivot keywords config file, and the keyword values are filled in while scanning
/// records. Owned by `StoredStatic::pivot_keyword` (behind an `Arc<RwLock<..>>` so the per-record
/// parallel tasks can fill it in) rather than a process global.
pub type PivotKeywordMap = IndexMap<String, PivotKeyword>;

impl Default for PivotKeyword {
    fn default() -> Self {
        Self::new()
    }
}

impl PivotKeyword {
    pub fn new() -> PivotKeyword {
        PivotKeyword {
            keywords: IndexSet::new(),
            fields: IndexSet::new(),
        }
    }
}

/// For records with a level of low or higher, collects the values of every configured pivot
/// field found in the record into the `pivot_keyword` map's keyword sets.
pub fn insert_pivot_keyword(
    event_record: &Value,
    eventkey_alias: &EventKeyAliasConfig,
    pivot_keyword: &RwLock<PivotKeywordMap>,
) {
    if let Some(record_level) = get_event_value("Event.System.Level", event_record, eventkey_alias)
    {
        if let Some(event_record_str) = get_serde_number_to_string(record_level, false) {
            let exclude_check_str = event_record_str.as_str();
            // Skip low-value records: informational, undefined, or unknown ("-") level.
            // (Records of low or higher severity fall through and are processed below.)
            if exclude_check_str == "informational"
                || exclude_check_str == "undefined"
                || exclude_check_str == "-"
            {
                return;
            }
        }
    } else {
        return;
    }

    // For every pivot category, resolve each configured field against the record and collect its
    // value.
    let mut pivots = pivot_keyword.write().unwrap();
    pivots.iter_mut().for_each(|(_, pivot)| {
        for field in &pivot.fields {
            if let Some(event_key_path) = eventkey_alias.get_event_key(&String::from(field)) {
                let mut event_key_found = false;
                let mut tmp_event_record: &Value = event_record;
                // Walk the dot-separated event key path as far as it matches the record. If the
                // walk stops on a JSON object (i.e. the full path did not resolve to a scalar),
                // get_serde_number_to_string below returns None and the field is skipped.
                for segment in event_key_path.split('.') {
                    if let Some(record) = tmp_event_record.get(segment) {
                        event_key_found = true;
                        tmp_event_record = record;
                    }
                }
                if event_key_found {
                    let hash_value = get_serde_number_to_string(tmp_event_record, false);

                    if let Some(value) = hash_value {
                        // Skip placeholder ("-") and localhost values, which are useless as pivot
                        // keywords.
                        if value == "-" || value == "127.0.0.1" || value == "::1" {
                            continue;
                        }
                        pivot.keywords.insert(value.to_string());
                    };
                }
            }
        }
    });
}

/// Formats one pivot keyword section for output. When `place` is "standard" the section is
/// printed directly to stdout (with a colored header) and an empty string is returned; otherwise
/// ("file") the formatted section is appended to `output` and returned so the caller can write it
/// to a file.
pub fn create_output(
    mut output: String,
    key: &String,
    pivot_keyword: &PivotKeyword,
    place: &str,
    stored_static: &StoredStatic,
) -> String {
    if place == "standard" {
        // Print the section header (category name and its fields) in green.
        let output = String::default();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(Some(Color::Green), stored_static.common_options.no_color),
            &fmt_headers(output, key, pivot_keyword),
            false,
        )
        .ok();

        // Print the collected keyword values.
        let output = String::default();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            &fmt_keywords_results(output, pivot_keyword),
            true,
        )
        .ok();
        "".to_string()
    } else {
        output = fmt_headers(output, key, pivot_keyword);
        fmt_keywords_results(output, pivot_keyword)
    }
}

/// Appends the section header, e.g. `Ip Addresses: ( %IpAddress% ):`, to `output`.
pub fn fmt_headers(mut output: String, key: &String, pivot_keyword: &PivotKeyword) -> String {
    write!(output, "{key}: ( ").ok();
    for field in pivot_keyword.fields.iter() {
        write!(output, "%{field}% ").ok();
    }

    // Only add a trailing newline when keyword values will follow the header.
    if pivot_keyword.keywords.is_empty() {
        write!(output, "):").ok();
    } else {
        writeln!(output, "):").ok();
    }

    output
}

/// Appends each collected keyword value on its own line to `output`.
pub fn fmt_keywords_results(mut output: String, pivot_keyword: &PivotKeyword) -> String {
    for keyword in pivot_keyword.keywords.iter() {
        writeln!(output, "{keyword}").ok();
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::configs::load_pivot_keywords;
    use crate::detections::utils;
    use crate::options::pivot::{PivotKeywordMap, insert_pivot_keyword};
    use serde_json;
    use std::sync::RwLock;

    #[test]
    fn insert_pivot_keyword_local_ip4() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "high"
                },
                "EventData": {
                    "IpAddress": "127.0.0.1"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            !pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("127.0.0.1")
        );
    }

    #[test]
    fn insert_pivot_keyword_ip4() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "high"
                },
                "EventData": {
                    "IpAddress": "10.0.0.1"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("10.0.0.1")
        );
    }

    #[test]
    fn insert_pivot_keyword_ip_empty() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "high"
                },
                "EventData": {
                    "IpAddress": "-"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            !pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("-")
        );
    }

    #[test]
    fn insert_pivot_keyword_local_ip6() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "high"
                },
                "EventData": {
                    "IpAddress": "::1"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            !pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("::1")
        );
    }

    #[test]
    fn insert_pivot_keyword_level_informational() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "informational"
                },
                "EventData": {
                    "IpAddress": "10.0.0.2"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            !pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("10.0.0.2")
        );
    }

    #[test]
    fn insert_pivot_keyword_level_low() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "low"
                },
                "EventData": {
                    "IpAddress": "10.0.0.1"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("10.0.0.1")
        );
    }

    #[test]
    fn insert_pivot_keyword_level_none() {
        let pivot_keyword = RwLock::new(PivotKeywordMap::new());
        load_pivot_keywords("test_files/config/pivot_keywords.txt", &pivot_keyword);
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "-"
                },
                "EventData": {
                    "IpAddress": "10.0.0.3"
                }
            }
        }"#;
        insert_pivot_keyword(
            &serde_json::from_str(record_json_str).unwrap(),
            &load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            ),
            &pivot_keyword,
        );

        assert!(
            !pivot_keyword
                .write()
                .unwrap()
                .get_mut("Ip Addresses")
                .unwrap()
                .keywords
                .contains("10.0.0.3")
        );
    }
}

use indexmap::{IndexMap, IndexSet};
use lazy_static::lazy_static;
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::RwLock;
use termcolor::{BufferWriter, Color, ColorChoice};

use crate::detections::utils::{
    get_event_value, get_serde_number_to_string, get_writable_color, write_color_buffer,
};

use crate::detections::configs::{EventKeyAliasConfig, StoredStatic};

#[derive(Debug)]
pub struct PivotKeyword {
    pub keywords: IndexSet<String>,
    pub fields: IndexSet<String>,
}

lazy_static! {
    pub static ref PIVOT_KEYWORD: RwLock<IndexMap<String, PivotKeyword>> =
        RwLock::new(IndexMap::new());
}

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

///levelがlowより大きいレコードの場合、keywordがrecord内にみつかれば、
///それをPIVOT_KEYWORD.keywordsに入れる。
pub fn insert_pivot_keyword(event_record: &Value, eventkey_alias: &EventKeyAliasConfig) {
    if let Some(record_level) = get_event_value("Event.System.Level", event_record, eventkey_alias)
    {
        match get_serde_number_to_string(record_level, false) { Some(event_record_str) => {
            let exclude_check_str = event_record_str.as_str();
            //levelがlow以上なら続ける
            if exclude_check_str == "infomational"
                || exclude_check_str == "undefined"
                || exclude_check_str == "-"
            {
                return;
            }
        } _ => {}}
    } else {
        return;
    }

    let mut pivots = PIVOT_KEYWORD.write().unwrap();
    pivots.iter_mut().for_each(|(_, pivot)| {
        for field in &pivot.fields {
            if let Some(array_str) = eventkey_alias.get_event_key(&String::from(field)) {
                let mut is_exist_event_key = false;
                let mut tmp_event_record: &Value = event_record;
                for s in array_str.split('.') {
                    if let Some(record) = tmp_event_record.get(s) {
                        is_exist_event_key = true;
                        tmp_event_record = record;
                    }
                }
                if is_exist_event_key {
                    let hash_value = get_serde_number_to_string(tmp_event_record, false);

                    if let Some(value) = hash_value {
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

//pivot_keywordsの標準出力などに関する関数たち
pub fn create_output(
    mut output: String,
    key: &String,
    pivot_keyword: &PivotKeyword,
    place: &str,
    stored_static: &StoredStatic,
) -> String {
    if place == "standard" {
        //headers
        let output = String::default();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(Some(Color::Green), stored_static.common_options.no_color),
            &fmt_headers(output, key, pivot_keyword),
            false,
        )
        .ok();

        //keywords_results
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

pub fn fmt_headers(mut output: String, key: &String, pivot_keyword: &PivotKeyword) -> String {
    write!(output, "{key}: ( ").ok();
    for i in pivot_keyword.fields.iter() {
        write!(output, "%{i}% ").ok();
    }

    if pivot_keyword.keywords.is_empty() {
        write!(output, "):").ok();
    } else {
        writeln!(output, "):").ok();
    }

    output
}

pub fn fmt_keywords_results(mut output: String, pivot_keyword: &PivotKeyword) -> String {
    for i in pivot_keyword.keywords.iter() {
        writeln!(output, "{i}").ok();
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::configs::load_pivot_keywords;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::utils;
    use crate::options::pivot::insert_pivot_keyword;
    use crate::options::pivot::PIVOT_KEYWORD;
    use serde_json;

    #[test]
    fn insert_pivot_keyword_local_ip4() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(!PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("127.0.0.1"));
    }

    #[test]
    fn insert_pivot_keyword_ip4() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("10.0.0.1"));
    }

    #[test]
    fn insert_pivot_keyword_ip_empty() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(!PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("-"));
    }

    #[test]
    fn insert_pivot_keyword_local_ip6() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(!PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("::1"));
    }

    #[test]
    fn insert_pivot_keyword_level_infomational() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
        let record_json_str = r#"
        {
            "Event": {
                "System": {
                    "Level": "infomational"
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
        );

        assert!(!PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("10.0.0.2"));
    }

    #[test]
    fn insert_pivot_keyword_level_low() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("10.0.0.1"));
    }

    #[test]
    fn insert_pivot_keyword_level_none() {
        PIVOT_KEYWORD.write().unwrap().clear();
        load_pivot_keywords("test_files/config/pivot_keywords.txt");
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
        );

        assert!(!PIVOT_KEYWORD
            .write()
            .unwrap()
            .get_mut("Ip Addresses")
            .unwrap()
            .keywords
            .contains("10.0.0.3"));
    }
}

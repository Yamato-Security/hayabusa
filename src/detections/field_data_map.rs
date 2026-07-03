use crate::detections::configs::ONE_CONFIG_MAP;
use crate::detections::field_data_map::FieldDataConverter::{HexToDecimal, ReplaceStr};
use crate::detections::message::AlertMessage;
use crate::detections::utils::get_serde_number_to_string;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::string::String;
use yaml_rust2::{Yaml, YamlLoader};

/// All field data conversion rules loaded from the data_mapping config files, keyed by the
/// (channel, event ID) pair each rule set applies to.
pub type FieldDataMap = HashMap<FieldDataMapKey, FieldDataMapEntry>;
/// Conversion rules for one event type: lowercase field name -> converter for that field's value.
pub type FieldDataMapEntry = HashMap<String, FieldDataConverter>;

/// How a raw field value should be rewritten into a more readable form.
#[derive(Debug, Clone)]
pub enum FieldDataConverter {
    /// Converts a hex string such as "0x44c" into its decimal representation.
    HexToDecimal,
    /// Replaces substrings via an Aho-Corasick automaton whose patterns pair up with the Vec of
    /// replacement strings (same index = same rule). The HashSet limits the rewrite to events
    /// whose provider name is in the set; an empty set means any provider.
    ReplaceStr((AhoCorasick, Vec<String>), HashSet<String>),
}

/// Identifies the event type a mapping applies to: lowercase channel name plus event ID.
#[derive(Debug, Eq, Hash, PartialEq, Default, Clone)]
pub struct FieldDataMapKey {
    pub channel: CompactString,
    pub event_id: CompactString,
}

impl FieldDataMapKey {
    /// Builds a key from the Channel and EventID values of a data_mapping YAML document.
    fn new(yaml_data: Yaml) -> FieldDataMapKey {
        FieldDataMapKey {
            channel: CompactString::from(
                yaml_data["Channel"]
                    .as_str()
                    .unwrap_or_default()
                    .to_lowercase(),
            ),
            event_id: CompactString::from(
                yaml_data["EventID"]
                    .as_i64()
                    .unwrap_or_default()
                    .to_string(),
            ),
        }
    }
}

/// Parses one data_mapping YAML document (see rules/config/data_mapping/*.yaml) into the event
/// type key it applies to and the per-field converters it defines. Returns default (empty) values
/// when the document defines neither RewriteFieldData nor HexToDecimal.
fn build_field_data_map(yaml_data: Yaml) -> (FieldDataMapKey, FieldDataMapEntry) {
    let rewrite_field_data = yaml_data["RewriteFieldData"].as_hash();
    // HexToDecimal may be given as a single scalar or as a list of field names; normalize both
    // forms into a list of YAML values.
    let hex2decimal = if let Some(s) = yaml_data["HexToDecimal"].as_str() {
        Some(YamlLoader::load_from_str(s).unwrap_or_default())
    } else {
        yaml_data["HexToDecimal"].as_vec().map(|v| v.to_owned())
    };
    if rewrite_field_data.is_none() && hex2decimal.is_none() {
        return (FieldDataMapKey::default(), FieldDataMapEntry::default());
    }
    // Provider_Name is optional and may be a single name or a list. When present, the string
    // rewrites only apply to events emitted by one of these providers.
    let mut providers = HashSet::new();
    if let Some(providers_yaml) = yaml_data["Provider_Name"].as_vec() {
        for provider in providers_yaml {
            providers.insert(provider.as_str().unwrap_or_default().to_string());
        }
    } else if let Some(provider_name) = yaml_data["Provider_Name"].as_str() {
        providers.insert(provider_name.to_string());
    }
    let mut mapping = HashMap::new();
    if let Some(x) = rewrite_field_data {
        for (key_yaml, val_yaml) in x.iter() {
            let field = key_yaml.as_str().unwrap_or_default();
            let replace_values = val_yaml.as_vec();
            if field.is_empty() || replace_values.is_none() {
                continue;
            }
            // Each list element is a one-entry hash of pattern -> replacement. Collect them as
            // parallel vectors, which is the form AhoCorasick's replace_all expects.
            let mut ptns = vec![];
            let mut reps = vec![];
            for rep_val in replace_values.unwrap() {
                let entry = rep_val.as_hash();
                if entry.is_none() {
                    continue;
                }
                for (ptn, rep) in entry.unwrap().iter() {
                    ptns.push(ptn.as_str().unwrap_or_default().to_string());
                    reps.push(rep.as_str().unwrap_or_default().to_string());
                }
            }
            let ac = AhoCorasick::new(ptns);
            if ac.is_err() {
                continue;
            }
            mapping.insert(
                field.to_string().to_lowercase(),
                ReplaceStr((ac.unwrap(), reps), providers.clone()),
            );
        }
    }

    if let Some(fields) = hex2decimal {
        for field in fields {
            if let Some(key) = field.as_str() {
                mapping.insert(key.to_lowercase(), HexToDecimal);
            }
        }
    }
    (FieldDataMapKey::new(yaml_data), mapping)
}

/// Rewrites a field value according to the loaded data_mapping rules. Returns None when no
/// mapping exists for the (channel, event ID) key or for the field (lowercase), in which case the
/// caller should keep the original value. When a mapping exists but does not change the value
/// (e.g. the provider does not match, or the value is not a valid hex string), the original
/// string is returned wrapped in Some.
pub fn convert_field_data(
    data_map: &FieldDataMap,
    data_map_key: &FieldDataMapKey,
    field: &str,
    field_data_str: &str,
    record: &Value,
) -> Option<CompactString> {
    match data_map.get(data_map_key) {
        None => None,
        Some(data_map_entry) => match data_map_entry.get(field) {
            None => None,
            Some(ReplaceStr(x, providers)) => {
                // A provider restriction is defined: pass the value through unchanged when this
                // record's provider is not in the set.
                if !providers.is_empty() {
                    let provider = get_serde_number_to_string(
                        &record["Event"]["System"]["Provider_attributes"]["Name"],
                        false,
                    )
                    .unwrap_or_default();
                    if !providers.contains(&provider.to_string()) {
                        return Some(CompactString::from(field_data_str));
                    }
                };
                let (ac, rep) = x;
                let mut wtr = vec![];
                let _ = ac.try_stream_replace_all(field_data_str.as_bytes(), &mut wtr, rep);
                Some(CompactString::from(std::str::from_utf8(&wtr).unwrap()))
            }
            // Only values with a 0x/0X prefix that parse as u64 are converted; anything else is
            // passed through unchanged.
            Some(HexToDecimal) => match field_data_str
                .strip_prefix("0x")
                .or_else(|| field_data_str.strip_prefix("0X"))
            {
                Some(hex) if !hex.is_empty() => match u64::from_str_radix(hex, 16) {
                    Ok(decimal_value) => Some(CompactString::from(decimal_value.to_string())),
                    Err(_) => Some(CompactString::from(field_data_str)),
                },
                _ => Some(CompactString::from(field_data_str)),
            },
        },
    }
}

/// Loads every YAML document from the .yaml files directly under the given directory.
fn load_yaml_files(dir_path: &Path) -> Result<Vec<Yaml>, String> {
    let path = dir_path.as_os_str().to_str().unwrap_or_default();
    if !dir_path.exists() || !dir_path.is_dir() {
        let msg = format!("Field mapping dir[{path}] does not exist.");
        AlertMessage::warn(&msg).ok();
        return Err(msg);
    }
    match fs::read_dir(dir_path) {
        Ok(files) => Ok(files
            .filter_map(|d| d.ok())
            .filter(|d| d.path().extension().unwrap_or_default() == "yaml")
            .map(|f| YamlLoader::load_from_str(&fs::read_to_string(f.path()).unwrap_or_default()))
            .filter_map(|y| y.ok())
            .flatten()
            .collect()),
        Err(e) => {
            let mut msg = format!("Failed to open field mapping dir[{path}]. ",);
            // Windows OS error 123 (ERROR_INVALID_NAME): invalid path syntax. This typically
            // happens when a quoted path ends with a backslash, which escapes the closing quote
            // and mangles the command-line argument.
            if e.to_string().ends_with("123)") {
                msg = format!(
                    "{msg}. You may not be able to load evtx files when there are spaces in the directory path. Please enclose the path with double quotes and remove any trailing slash at the end of the path."
                );
            }
            AlertMessage::warn(&msg).ok();
            Err(e.to_string())
        }
    }
}

/// Builds the whole field data map, either from the all-in-one config bundle (when present) or
/// from the .yaml files in the given data_mapping directory. Returns None when the directory
/// cannot be read.
pub fn create_field_data_map(dir_path: &Path) -> Option<FieldDataMap> {
    // In the all-in-one config bundle, every embedded .yaml file except the GeoIP field mapping
    // is assumed to be a data_mapping file.
    let one_config_values: Vec<String> = ONE_CONFIG_MAP
        .iter()
        .filter(|(key, _)| key.contains(".yaml") && !key.contains("geoip_field_mapping.yaml"))
        .map(|(_, value)| value.clone())
        .collect();
    if !one_config_values.is_empty() {
        let yaml_contents: Vec<Yaml> = one_config_values
            .iter()
            .flat_map(|value| YamlLoader::load_from_str(value).unwrap_or_default())
            .collect();
        return Some(
            yaml_contents
                .into_iter()
                .map(build_field_data_map)
                .collect(),
        );
    }
    let yaml_data = load_yaml_files(dir_path);
    match yaml_data {
        Ok(y) => Some(y.into_iter().map(build_field_data_map).collect()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::field_data_map::{
        FieldDataConverter, FieldDataMap, FieldDataMapKey, build_field_data_map,
        convert_field_data, create_field_data_map, load_yaml_files,
    };
    use crate::detections::utils;
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use serde_json::Value;
    use std::path::Path;
    use yaml_rust2::{Yaml, YamlLoader};

    fn build_yaml(s: &str) -> Yaml {
        YamlLoader::load_from_str(s)
            .unwrap_or_default()
            .first()
            .unwrap()
            .clone()
    }

    #[test]
    fn test_load_yaml_files_not_exists_dir() {
        assert!(load_yaml_files(Path::new("notexists")).is_err());
        assert!(load_yaml_files(Path::new("./")).unwrap().is_empty())
    }

    #[test]
    fn test_convert_field_data_empty_data1() {
        let r = convert_field_data(
            &HashMap::new(),
            &FieldDataMapKey::default(),
            "",
            "",
            &Value::Null,
        );
        assert!(r.is_none());
    }

    #[test]
    fn test_convert_field_data_empty_data2() {
        let mut map = HashMap::new();
        let key = FieldDataMapKey {
            channel: CompactString::from("Security".to_lowercase()),
            event_id: CompactString::from("4625".to_string()),
        };
        map.insert(key.clone(), HashMap::new());
        let r = convert_field_data(&map, &key, "", "", &Value::Null);
        assert!(r.is_none());
    }

    #[test]
    fn test_convert_field_data() {
        let s = r#"
            Channel: Security
            EventID: 4624
            RewriteFieldData:
                LogonType:
                    - '0': '0 - SYSTEM'
                    - '2': '2 - INTERACTIVE'
        "#;
        let (key, entry) = build_field_data_map(build_yaml(s));
        let mut map = HashMap::new();
        map.insert(key.clone(), entry);
        let r = convert_field_data(&map, &key, "logontype", "Foo 0", &Value::Null);
        assert_eq!(r.unwrap(), "Foo 0 - SYSTEM");
    }

    #[test]
    fn test_build_field_data_map_invalid0() {
        let s = r#"
            INVALID
        "#;
        let r = build_field_data_map(build_yaml(s));
        assert_eq!(r.0, FieldDataMapKey::default());
    }

    #[test]
    fn test_build_field_data_map_invalid1() {
        let s = r#"
            Foo:
                Bar:
                    - 'A': '1'
        "#;
        let r = build_field_data_map(build_yaml(s));
        assert_eq!(r.0, FieldDataMapKey::default());
    }

    #[test]
    fn test_build_field_data_map_invalid2() {
        let s = r#"
            Channel: Security
            EventID: 4624
            INVALID: 1
        "#;
        let r = build_field_data_map(build_yaml(s));
        assert_eq!(r.0, FieldDataMapKey::default());
        assert!(r.1.is_empty());
    }

    #[test]
    fn test_build_field_data_map_invalid3() {
        let s = r#"
            Channel: Security
            EventID: 4624
            RewriteFieldData: 'INVALID'
        "#;
        let r = build_field_data_map(build_yaml(s));
        assert_eq!(r.0, FieldDataMapKey::default());
        assert!(r.1.is_empty());
    }

    #[test]
    fn test_build_field_data_map_valid() {
        let s = r#"
            Channel: Security
            EventID: 4624
            RewriteFieldData:
                ElevatedToken:
                    - '%%1842': 'YES'
                    - '%%1843': 'NO'
                ImpersonationLevel:
                    - '%%1832': 'A'
                    - '%%1833': 'B'
        "#;
        let r = build_field_data_map(build_yaml(s));
        let mut wtr = vec![];
        match r.1.get("elevatedtoken").unwrap() {
            FieldDataConverter::HexToDecimal => panic!(),
            FieldDataConverter::ReplaceStr(x, _) => {
                let (ac, rp) = x;
                let _ = ac.try_stream_replace_all("foo, %%1842, %%1843".as_bytes(), &mut wtr, rp);
                assert_eq!(b"foo, YES, NO".to_vec(), wtr);
            }
        }
        match r.1.get("impersonationlevel").unwrap() {
            FieldDataConverter::HexToDecimal => panic!(),
            FieldDataConverter::ReplaceStr(x, _) => {
                let mut wtr = vec![];
                let (ac, rp) = x;
                let _ = ac.try_stream_replace_all("foo, %%1832, %%1833".as_bytes(), &mut wtr, rp);
                assert_eq!(b"foo, A, B".to_vec(), wtr);
            }
        }
    }

    #[test]
    fn test_create_field_data_map() {
        let r = create_field_data_map(Path::new("notexists"));
        assert!(r.is_none());
    }

    #[test]
    fn test_create_recordinfos_with_field_data_map() {
        let record_json_str = r#"
        {
            "Event": {
                "System": {"EventID": 4624, "Channel": "Security", "Computer":"DESKTOP"},
                "EventData": {
                    "ElevatedToken": "%%1843",
                    "ImpersonationLevel": "%%1832",
                    "NewProcessId": "0x1980",
                    "ProcessId": "0x44c"
                },
                "EventData_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let s = r#"
            Channel: Security
            EventID: 4624
            RewriteFieldData:
                ElevatedToken:
                    - '%%1842': 'YES'
                    - '%%1843': 'NO'
                ImpersonationLevel:
                    - '%%1832': 'A'
                    - '%%1833': 'B'
            HexToDecimal:
                    - 'NewProcessId'
                    - 'ProcessId'
        "#;
        let (key, entry) = build_field_data_map(build_yaml(s));
        let mut map: FieldDataMap = HashMap::new();
        map.insert(key.clone(), entry);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let ret = utils::create_recordinfos(&record, &key, &Some(map));
                let expected = "ElevatedToken: NO ¦ ImpersonationLevel: A ¦ NewProcessId: 6528 ¦ ProcessId: 1100".to_string();
                assert_eq!(ret.join(" ¦ "), expected);
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }
}

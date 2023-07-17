use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use hashbrown::HashMap;
use std::fs;
use std::path::Path;
use std::string::String;
use yaml_rust::{Yaml, YamlLoader};

pub type FieldDataMap = HashMap<FieldDataMapKey, FieldDataMapEntry>;
pub type FieldDataMapEntry = HashMap<String, (AhoCorasick, Vec<String>)>;

#[derive(Debug, Eq, Hash, PartialEq, Default, Clone)]
pub struct FieldDataMapKey {
    pub channel: CompactString,
    pub event_id: CompactString,
}

impl FieldDataMapKey {
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

fn build_field_data_map(yaml_data: Yaml) -> (FieldDataMapKey, FieldDataMapEntry) {
    let rewrite_field_data = yaml_data["RewriteFieldData"].as_hash();
    if rewrite_field_data.is_none() {
        return (FieldDataMapKey::default(), FieldDataMapEntry::default());
    }
    let mut mapping = HashMap::new();
    for (key_yaml, val_yaml) in rewrite_field_data.unwrap().iter() {
        let field = key_yaml.as_str().unwrap_or_default();
        let replace_values = val_yaml.as_vec();
        if field.is_empty() || replace_values.is_none() {
            continue;
        }
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
        mapping.insert(field.to_string().to_lowercase(), (ac.unwrap(), reps));
    }
    (FieldDataMapKey::new(yaml_data), mapping)
}

pub fn convert_field_data(
    data_map: &FieldDataMap,
    data_map_key: &FieldDataMapKey,
    field: &str,
    field_data_str: &str,
) -> Option<CompactString> {
    match data_map.get(data_map_key) {
        None => None,
        Some(data_map_entry) => match data_map_entry.get(field) {
            None => None,
            Some((ac, rep)) => {
                let mut wtr = vec![];
                let _ = ac.try_stream_replace_all(field_data_str.as_bytes(), &mut wtr, rep);
                Some(CompactString::from(std::str::from_utf8(&wtr).unwrap()))
            }
        },
    }
}

fn load_yaml_files(dir_path: &Path) -> Result<Vec<Yaml>, String> {
    if !dir_path.exists() || !dir_path.is_dir() {
        return Err("".to_string());
    }
    match fs::read_dir(dir_path) {
        Ok(files) => Ok(files
            .filter_map(|d| d.ok())
            .filter(|d| d.path().extension().unwrap_or_default() == "yaml")
            .map(|f| YamlLoader::load_from_str(&fs::read_to_string(f.path()).unwrap_or_default()))
            .filter_map(|y| y.ok())
            .flatten()
            .collect()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn create_field_data_map(dir_path: &Path) -> Option<FieldDataMap> {
    let yaml_data = load_yaml_files(dir_path);
    match yaml_data {
        Ok(y) => Some(y.into_iter().map(build_field_data_map).collect()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::field_data_map::{
        build_field_data_map, convert_field_data, create_field_data_map, load_yaml_files,
        FieldDataMapKey,
    };
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use std::path::Path;
    use yaml_rust::{Yaml, YamlLoader};

    fn build_yaml(s: &str) -> Yaml {
        YamlLoader::load_from_str(s)
            .unwrap_or_default()
            .get(0)
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
        let r = convert_field_data(&HashMap::new(), &FieldDataMapKey::default(), "", "");
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
        let r = convert_field_data(&map, &key, "", "");
        assert!(r.is_none());
    }

    #[test]
    fn test_convert_field_data() {
        let s = r##"
            Channel: Security
            EventID: 4624
            RewriteFieldData:
                LogonType:
                    - '0': '0 - SYSTEM'
                    - '2': '2 - INTERACTIVE'
        "##;
        let y = build_yaml(s);
        let (key, entry) = build_field_data_map(y);
        let mut map = HashMap::new();
        map.insert(key.clone(), entry);
        let r = convert_field_data(&map, &key, "logontype", "Foo 0");
        assert_eq!(r.unwrap(), "Foo 0 - SYSTEM");
    }

    #[test]
    fn test_build_field_data_map_invalid0() {
        let s = r##"
            INVALID
        "##;
        let y = build_yaml(s);
        let r = build_field_data_map(y);
        assert_eq!(r.0, FieldDataMapKey::default());
    }

    #[test]
    fn test_build_field_data_map_invalid1() {
        let s = r##"
            Foo:
                Bar:
                    - 'A': '1'
        "##;
        let y = build_yaml(s);
        let r = build_field_data_map(y);
        assert_eq!(r.0, FieldDataMapKey::default());
    }

    #[test]
    fn test_build_field_data_map_invalid2() {
        let s = r##"
            Channel: Security
            EventID: 4624
            INVALID: 1
        "##;
        let y = build_yaml(s);
        let r = build_field_data_map(y);
        assert_eq!(r.0, FieldDataMapKey::default());
        assert!(r.1.is_empty());
    }

    #[test]
    fn test_build_field_data_map_invalid3() {
        let s = r##"
            Channel: Security
            EventID: 4624
            RewriteFieldData: 'INVALID'
        "##;
        let y = build_yaml(s);
        let r = build_field_data_map(y);
        assert_eq!(r.0, FieldDataMapKey::default());
        assert!(r.1.is_empty());
    }

    #[test]
    fn test_build_field_data_map_valid() {
        let s = r##"
            Channel: Security
            EventID: 4624
            RewriteFieldData:
                ElevatedToken:
                    - '%%1842': 'YES'
                    - '%%1843': 'NO'
                ImpersonationLevel:
                    - '%%1832': 'A'
                    - '%%1833': 'B'
        "##;
        let y = build_yaml(s);
        let r = build_field_data_map(y);
        let mut wtr = vec![];
        let ac = r.1.get("elevatedtoken").unwrap().0.clone();
        let rp = r.1.get("elevatedtoken").unwrap().1.clone();
        let _ = ac.try_stream_replace_all("foo, %%1842, %%1843".as_bytes(), &mut wtr, &rp);
        assert_eq!(b"foo, YES, NO".to_vec(), wtr);

        let mut wtr = vec![];
        let ac = r.1.get("impersonationlevel").unwrap().0.clone();
        let rp = r.1.get("impersonationlevel").unwrap().1.clone();
        let _ = ac.try_stream_replace_all("foo, %%1832, %%1833".as_bytes(), &mut wtr, &rp);
        assert_eq!(b"foo, A, B".to_vec(), wtr);
    }

    #[test]
    fn test_create_field_data_map() {
        let r = create_field_data_map(Path::new("notexists"));
        assert!(r.is_none());
    }
}

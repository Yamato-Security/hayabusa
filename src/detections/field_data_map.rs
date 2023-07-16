use aho_corasick::AhoCorasick;
use hashbrown::HashMap;
use std::fs;
use std::path::Path;
use std::string::String;
use yaml_rust::{Yaml, YamlLoader};

pub type FieldDataMap = HashMap<String, (AhoCorasick, Vec<String>)>;

#[derive(Debug, Eq, Hash, PartialEq, Default, Clone)]
pub struct FieldDataMapKey {
    channel: String,
    event_id: String,
}

impl FieldDataMapKey {
    pub fn new(yaml_data: Yaml) -> FieldDataMapKey {
        FieldDataMapKey {
            channel: yaml_data["Channel"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase(),
            event_id: yaml_data["EventID"]
                .as_i64()
                .unwrap_or_default()
                .to_string(),
        }
    }
}

pub fn build_field_data_map(yaml_data: Yaml) -> (FieldDataMapKey, FieldDataMap) {
    let rewrite_field_data = yaml_data["RewriteFieldData"].as_hash();
    if rewrite_field_data.is_none() {
        return (FieldDataMapKey::default(), FieldDataMap::default());
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
    map: HashMap<FieldDataMapKey, FieldDataMap>,
    data_map_key: FieldDataMapKey,
    field: &str,
    field_data_str: &str,
) -> Option<String> {
    match map.get(&data_map_key) {
        None => None,
        Some(data_map) => match data_map.get(field) {
            None => None,
            Some((ac, rep)) => {
                let mut wtr = vec![];
                let _ = ac.try_stream_replace_all(field_data_str.as_bytes(), &mut wtr, rep);
                Some(std::str::from_utf8(&wtr).unwrap().to_string())
            }
        },
    }
}

pub fn load_yaml_files(dir_path: &Path) -> Result<Vec<Yaml>, String> {
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
        Err(_) => Err("".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::field_data_map::{
        build_field_data_map, convert_field_data, load_yaml_files, FieldDataMapKey,
    };
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
        assert_eq!(load_yaml_files(Path::new("notexists")).is_err(), true);
        assert_eq!(load_yaml_files(Path::new("./")).unwrap().is_empty(), true)
    }

    #[test]
    fn test_convert_field_data_empty_data1() {
        let r = convert_field_data(HashMap::new(), FieldDataMapKey::default(), "", "");
        assert_eq!(r.is_none(), true);
    }

    #[test]
    fn test_convert_field_empty_data2() {
        let mut map = HashMap::new();
        let key = FieldDataMapKey {
            channel: "Security".to_lowercase(),
            event_id: "4625".to_string(),
        };
        map.insert(key.clone(), HashMap::new());
        let r = convert_field_data(map, key, "", "");
        assert_eq!(r.is_none(), true);
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
        assert_eq!(r.1.is_empty(), true);
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
        assert_eq!(r.1.is_empty(), true);
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
}

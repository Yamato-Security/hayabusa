use crate::detections::configs::{self, StoredStatic};
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use crate::detections::rule::RuleNode;
use evtx::EvtxParser;
use hashbrown::HashMap;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use yaml_rust::Yaml;

#[derive(Debug)]
pub struct DataFilterRule {
    pub regex_rule: Regex,
    pub replace_str: String,
}

#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub no_use_rule: HashMap<String, String>,
}

impl RuleExclude {
    pub fn new() -> RuleExclude {
        RuleExclude {
            no_use_rule: HashMap::new(),
        }
    }
}

impl Default for RuleExclude {
    fn default() -> Self {
        Self::new()
    }
}

pub fn exclude_ids(stored_static: &StoredStatic) -> RuleExclude {
    let mut exclude_ids = RuleExclude::default();
    exclude_ids.insert_ids(
        &format!(
            "{}/noisy_rules.txt",
            stored_static.config_path.as_path().display(),
        ),
        stored_static,
    );

    exclude_ids.insert_ids(
        &format!(
            "{}/exclude_rules.txt",
            stored_static.config_path.as_path().display(),
        ),
        stored_static,
    );

    exclude_ids
}

impl RuleExclude {
    fn insert_ids(&mut self, filename: &str, stored_static: &StoredStatic) {
        let f = File::open(filename);
        if f.is_err() {
            if stored_static.verbose_flag {
                AlertMessage::warn(&format!("{filename} does not exist")).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("{filename} does not exist"));
            }
            return;
        }
        let reader = BufReader::new(f.unwrap());
        for v in reader.lines() {
            let v = v.unwrap().split('#').collect::<Vec<&str>>()[0]
                .trim()
                .to_string();
            if v.is_empty() || !configs::IDS_REGEX.is_match(&v) {
                // 空行は無視する。IDの検証
                continue;
            }
            self.no_use_rule.insert(v, filename.to_owned());
        }
    }
}

fn peek_channel_from_evtx_first_record(
    evtx_files: &Vec<PathBuf>,
) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut channels = HashSet::new();
    for path in evtx_files {
        let mut parser = EvtxParser::from_path(path)?;
        let mut records = parser.records_json_value();
        match records.next() {
            Some(Ok(rec)) => channels.insert(
                rec.data["Event"]["System"]["Channel"]
                    .to_string()
                    .replace('"', ""),
            ),
            _ => continue,
        };
    }
    Ok(channels)
}

fn extract_channel_from_rules(
    rule_files: &Vec<RuleNode>,
    evtx_channels: &HashSet<String>,
) -> Vec<String> {
    fn visit_value(
        key: &str,
        value: &Yaml,
        evtx_channels: &HashSet<String>,
        stacked_channels: &mut Vec<String>,
    ) {
        match *value {
            Yaml::String(ref s) => {
                if key == "Channel" && evtx_channels.contains(s) {
                    stacked_channels.push(s.clone());
                }
            }
            Yaml::Hash(ref map) => {
                for (k, v) in map {
                    visit_value(k.as_str().unwrap(), v, evtx_channels, stacked_channels);
                }
            }
            Yaml::Array(ref seq) => {
                for v in seq {
                    visit_value(key, v, evtx_channels, stacked_channels);
                }
            }
            _ => {}
        }
    }
    let mut stacked_channels = vec![];
    let mut filtered_rulespathes = vec![];
    for rule in rule_files {
        let before_visit_len = stacked_channels.len();
        visit_value("", &rule.yaml, evtx_channels, &mut stacked_channels);
        if before_visit_len < stacked_channels.len() {
            filtered_rulespathes.push(rule.rulepath.to_string());
        }
    }
    filtered_rulespathes
}

pub fn filter_rules_by_evtx_channel(
    evtx_files: &Vec<PathBuf>,
    rule_nodes: &Vec<RuleNode>,
) -> Vec<String> {
    let channels = peek_channel_from_evtx_first_record(evtx_files);
    match channels {
        Ok(ch) => extract_channel_from_rules(rule_nodes, &ch),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_peek_channel_from_evtx_first_record_invalid_evtx() {
        let evtx_files = vec![PathBuf::from("test_files/evtx/test1.evtx")];
        let result = peek_channel_from_evtx_first_record(&evtx_files);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_channel_from_rules_hash_match() {
        let rule_str = r#"
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_files = vec![rule];
        let evtx_channels = HashSet::from_iter(vec!["Microsoft-Windows-Sysmon/Operational".into()]);
        let result = extract_channel_from_rules(&rule_files, &evtx_channels);
        assert_eq!(result, vec!["test_files/evtx/test1.evtx"]);
    }

    #[test]
    fn test_extract_channel_from_rules_hash_not_match() {
        let rule_str = r#"
        detection:
            selection1:
                Channel: 'Security'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_files = vec![rule];
        let evtx_channels = HashSet::from_iter(vec!["Microsoft-Windows-Sysmon/Operational".into()]);
        let result = extract_channel_from_rules(&rule_files, &evtx_channels);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_extract_channel_from_rules_array_match() {
        let rule_str = r#"
        detection:
            selection1:
                Channel:
                    - 'Security'
                    - 'Microsoft-Windows-Sysmon/Operational'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_files = vec![rule];
        let evtx_channels = HashSet::from_iter(vec!["Microsoft-Windows-Sysmon/Operational".into()]);
        let result = extract_channel_from_rules(&rule_files, &evtx_channels);
        assert_eq!(result, vec!["test_files/evtx/test1.evtx"]);
    }

    #[test]
    fn test_extract_channel_from_rules_array_not_match() {
        let rule_str = r#"
        detection:
            selection1:
                Channel:
                    - 'Security'
                    - 'System'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_files = vec![rule];
        let evtx_channels = HashSet::from_iter(vec!["Microsoft-Windows-Sysmon/Operational".into()]);
        let result = extract_channel_from_rules(&rule_files, &evtx_channels);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_filter_rules_by_evtx_channel_invalid_evtx() {
        let evtx_files = vec![PathBuf::from("test_files/evtx/test1.evtx")];
        let rule_str = r#"
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_nodes = vec![rule];
        let result = filter_rules_by_evtx_channel(&evtx_files, &rule_nodes);
        assert_eq!(result.len(), 0);
    }
}

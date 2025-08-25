use crate::detections::configs::{self, ONE_CONFIG_MAP, StoredStatic};
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use crate::detections::rule::RuleNode;
use evtx::EvtxParser;
use hashbrown::HashMap;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
use yaml_rust2::Yaml;

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
        let re = Regex::new(r".*/").unwrap();
        let one_config_path = &re.replace(filename, "").to_string();
        let lines: Vec<String> = if ONE_CONFIG_MAP.contains_key(one_config_path) {
            ONE_CONFIG_MAP
                .get(one_config_path)
                .unwrap()
                .split('\n')
                .map(|s| s.to_string())
                .collect()
        } else {
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
            reader.lines().map_while(Result::ok).collect()
        };
        for v in lines {
            let v = v.split('#').collect::<Vec<&str>>()[0].trim().to_string();
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
    quiet_errors_flag: bool,
) -> HashMap<String, Vec<PathBuf>> {
    let start_time = Instant::now();
    let mut channels = HashMap::new();
    for path in evtx_files {
        match EvtxParser::from_path(path) {
            Ok(mut parser) => {
                let mut records = parser.records_json_value();
                match records.next() {
                    Some(Ok(rec)) => {
                        let key = rec.data["Event"]["System"]["Channel"]
                            .as_str()
                            .unwrap_or("")
                            .trim_matches('"')
                            .to_string();
                        channels
                            .entry(key)
                            .or_insert_with(Vec::new)
                            .push(path.to_path_buf());
                    }
                    _ => continue,
                };
            }
            Err(_) => {
                if !quiet_errors_flag {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("Failed to open evtx file: {}", path.display()));
                }
            }
        }
        let elapsed = start_time.elapsed();
        println!(
            "peek_channel_from_evtx_first_record: {:.2}秒, {:?}",
            elapsed.as_secs_f64(),
            path.display()
        );
    }
    channels
}

fn extract_channel_from_rules(
    rule_files: &Vec<RuleNode>,
    evtx_channels: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    fn visit_value(
        key: &str,
        value: &Yaml,
        evtx_channels: &HashSet<String>,
        intersection_channels: &mut Vec<String>,
    ) {
        match *value {
            Yaml::String(ref s) => {
                if key == "Channel" {
                    if s.contains('*') {
                        // SigmaルールでChannelにワイルドカードが使われた場合
                        for ch in evtx_channels {
                            if ch.contains(s.trim_matches('*')) {
                                intersection_channels.push(ch.to_string());
                            }
                        }
                    } else if evtx_channels.contains(s) {
                        intersection_channels.push(s.clone());
                    }
                }
            }
            Yaml::Hash(ref map) => {
                for (k, v) in map {
                    visit_value(k.as_str().unwrap(), v, evtx_channels, intersection_channels);
                }
            }
            Yaml::Array(ref seq) => {
                for v in seq {
                    visit_value(key, v, evtx_channels, intersection_channels);
                }
            }
            _ => {}
        }
    }
    let mut intersection_channels = vec![];
    let mut filtered_rulespathes = vec![];
    for rule in rule_files {
        let before_visit_len = intersection_channels.len();
        visit_value("", &rule.yaml, evtx_channels, &mut intersection_channels);
        if before_visit_len < intersection_channels.len() {
            filtered_rulespathes.push(rule.rulepath.to_string());
        }
    }
    (filtered_rulespathes, intersection_channels)
}

pub struct ChannelFilter {
    pub rulepathes: Vec<String>,
    pub intersec_channels: HashSet<String>, // evtxとruleのchannelの積集合
    pub evtx_channels_map: HashMap<String, Vec<PathBuf>>, // key=channel, val=evtxパスのリスト
}

impl ChannelFilter {
    pub fn new() -> ChannelFilter {
        ChannelFilter {
            rulepathes: vec![],
            intersec_channels: HashSet::new(),
            evtx_channels_map: HashMap::new(),
        }
    }

    pub fn scanable_rule_exists(&mut self, path: &PathBuf) -> bool {
        for (channel, rulepathes) in &self.evtx_channels_map {
            if rulepathes.contains(path) && self.intersec_channels.contains(channel) {
                return true;
            }
        }
        false
    }
}

impl Default for ChannelFilter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_channel_filter(
    evtx_files: &Vec<PathBuf>,
    rule_nodes: &Vec<RuleNode>,
    quiet_errors_flag: bool,
) -> ChannelFilter {
    let channels = peek_channel_from_evtx_first_record(evtx_files, quiet_errors_flag);
    if !channels.is_empty() {
        let (x, y) = extract_channel_from_rules(rule_nodes, &channels.keys().cloned().collect());
        ChannelFilter {
            rulepathes: x,
            intersec_channels: y.into_iter().collect(),
            evtx_channels_map: channels,
        }
    } else {
        ChannelFilter::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use yaml_rust2::YamlLoader;

    #[test]
    fn test_channel_filter_scanable_rule_exists() {
        let mut channel_filter = ChannelFilter::new();
        channel_filter
            .evtx_channels_map
            .insert("channel1".to_string(), vec![PathBuf::from("path1")]);
        channel_filter
            .intersec_channels
            .insert("channel1".to_string());

        assert!(channel_filter.scanable_rule_exists(&PathBuf::from("path1")));
        assert!(!channel_filter.scanable_rule_exists(&PathBuf::from("path2")));
    }

    #[test]
    fn test_peek_channel_from_evtx_first_record_invalid_evtx() {
        let evtx_files = vec![PathBuf::from("test_files/evtx/test1.evtx")];
        let result = peek_channel_from_evtx_first_record(&evtx_files, false);
        assert!(result.is_empty());
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
        let (result, _) = extract_channel_from_rules(&rule_files, &evtx_channels);
        assert_eq!(result, vec!["test_files/evtx/test1.evtx"]);
    }

    #[test]
    fn test_extract_channel_from_rules_hash_wildcard_match() {
        let rule_str = r#"
        detection:
            selection1:
                Channel: 'Microsoft-Windows-Security-Mitigations*'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test_yaml_data = rule_yaml.next().unwrap();
        let rule = RuleNode::new("test_files/evtx/test1.evtx".to_string(), test_yaml_data);
        let rule_files = vec![rule];
        let evtx_channels = HashSet::from_iter(vec![
            "Microsoft-Windows-Security-Mitigations%4KernelMode.evtx".into(),
            "Microsoft-Windows-Security-Mitigations%4UserMode.evtx".into(),
        ]);
        let (result, _) = extract_channel_from_rules(&rule_files, &evtx_channels);
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
        let (result, _) = extract_channel_from_rules(&rule_files, &evtx_channels);
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
        let (result, _) = extract_channel_from_rules(&rule_files, &evtx_channels);
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
        let (result, _) = extract_channel_from_rules(&rule_files, &evtx_channels);
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
        let result = create_channel_filter(&evtx_files, &rule_nodes, false);
        assert_eq!(result.rulepathes.len(), 0);
    }
}

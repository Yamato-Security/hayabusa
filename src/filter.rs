use crate::detections::configs::{self, ONE_CONFIG_MAP, StoredStatic};
use crate::detections::message::AlertMessage;
use crate::detections::rule::RuleNode;
use evtx::EvtxParser;
use hashbrown::HashMap;
use itertools::Itertools;
use nested::Nested;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Mutex;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug)]
pub struct DataFilterRule {
    pub regex_rule: Regex,
    pub replace_str: String,
}

/// Rule IDs to filter out at rule-loading time, mapped to the filter file (noisy_rules.txt or
/// exclude_rules.txt) each ID came from. IDs from exclude_rules.txt are always skipped; IDs from
/// noisy_rules.txt are skipped unless --enable-noisy-rules is set.
#[derive(Clone, Debug)]
pub struct RuleExclude {
    pub excluded_rule_sources: HashMap<String, String>,
}

impl RuleExclude {
    pub fn new() -> RuleExclude {
        RuleExclude {
            excluded_rule_sources: HashMap::new(),
        }
    }
}

impl Default for RuleExclude {
    fn default() -> Self {
        Self::new()
    }
}

/// Loads the rule IDs listed in noisy_rules.txt and exclude_rules.txt under the config directory
/// so that the corresponding detection rules can be skipped at rule-loading time.
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
        // ONE_CONFIG_MAP (the all-in-one config bundle) is keyed by bare file name, so strip the
        // directory part. If the file is bundled there, read the ID list from the bundle instead
        // of from disk.
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
            let file = File::open(filename);
            if file.is_err() {
                if stored_static.verbose_flag {
                    AlertMessage::warn(&format!("{filename} does not exist")).ok();
                }
                if !stored_static.quiet_errors_flag {
                    stored_static
                        .error_log_stack
                        .lock()
                        .unwrap()
                        .push(format!("{filename} does not exist"));
                }
                return;
            }
            let reader = BufReader::new(file.unwrap());
            reader.lines().map_while(Result::ok).collect()
        };
        for line in lines {
            // Strip inline comments: everything after the first '#' is ignored.
            let rule_id = line.split('#').collect::<Vec<&str>>()[0].trim().to_string();
            if rule_id.is_empty() || !configs::IDS_REGEX.is_match(&rule_id) {
                // Skip blank lines and entries that are not UUID-formatted rule IDs.
                continue;
            }
            self.excluded_rule_sources
                .insert(rule_id, filename.to_owned());
        }
    }
}

/// Reads only the first record of each evtx file to determine which channel the file holds, and
/// groups the file paths by channel name. This assumes all records in a file share the channel of
/// its first record. Files that fail to open are logged unless quiet_errors_flag is set; files
/// whose first record cannot be parsed are skipped silently.
fn peek_channel_from_evtx_first_record(
    evtx_files: &Vec<PathBuf>,
    quiet_errors_flag: bool,
    error_log_stack: &Mutex<Nested<String>>,
) -> HashMap<String, Vec<PathBuf>> {
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
                    error_log_stack
                        .lock()
                        .unwrap()
                        .push(format!("Failed to open evtx file: {}", path.display()));
                }
            }
        }
    }
    channels
}

/// Matches the Channel values referenced by each rule against the channels actually present in
/// the loaded evtx files. Returns the paths of the rules whose Channel matches at least one evtx
/// channel, together with the matched channel names.
fn extract_channel_from_rules(
    rule_files: &Vec<RuleNode>,
    evtx_channels: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    // Recursively walks a rule's YAML tree and records every evtx channel matched by any
    // "Channel:" value found in it.
    fn visit_value(
        key: &str,
        value: &Yaml,
        evtx_channels: &HashSet<String>,
        intersection_channels: &mut Vec<String>,
    ) {
        match *value {
            Yaml::String(ref s) if key == "Channel" => {
                if s.contains('*') {
                    // The rule uses a wildcard in its Channel value: strip the leading/trailing
                    // wildcards and treat the remainder as a substring match against each evtx
                    // channel name.
                    for ch in evtx_channels {
                        if ch.contains(s.trim_matches('*')) {
                            intersection_channels.push(ch.to_string());
                        }
                    }
                } else if evtx_channels.contains(s) {
                    intersection_channels.push(s.clone());
                }
            }
            Yaml::Hash(ref map) => {
                for (entry_key, entry_value) in map {
                    visit_value(
                        entry_key.as_str().unwrap(),
                        entry_value,
                        evtx_channels,
                        intersection_channels,
                    );
                }
            }
            Yaml::Array(ref seq) => {
                for element in seq {
                    visit_value(key, element, evtx_channels, intersection_channels);
                }
            }
            _ => {}
        }
    }
    let mut intersection_channels = vec![];
    let mut filtered_rule_paths = vec![];
    for rule in rule_files {
        let before_visit_len = intersection_channels.len();
        visit_value("", &rule.yaml, evtx_channels, &mut intersection_channels);
        // If the visit added any channel, this rule targets at least one loaded evtx channel.
        if before_visit_len < intersection_channels.len() {
            filtered_rule_paths.push(rule.rule_path.to_string());
        }
    }
    (filtered_rule_paths, intersection_channels)
}

/// Result of matching rule Channel values against the channels found in the loaded evtx files.
/// Used to skip evtx files that no loaded rule targets, and rules that no loaded evtx file can
/// trigger.
pub struct ChannelFilter {
    pub rule_paths: Vec<String>, // paths of rules whose Channel matches some loaded evtx file
    pub intersection_channels: HashSet<String>, // intersection of evtx and rule channels
    pub evtx_channels_map: HashMap<String, Vec<PathBuf>>, // key=channel, val=list of evtx paths
}

impl ChannelFilter {
    pub fn new() -> ChannelFilter {
        ChannelFilter {
            rule_paths: vec![],
            intersection_channels: HashSet::new(),
            evtx_channels_map: HashMap::new(),
        }
    }

    /// Returns true when the given evtx file holds a channel that at least one loaded rule
    /// targets, i.e. scanning the file can possibly produce a detection.
    pub fn scannable_rule_exists(&mut self, path: &PathBuf) -> bool {
        for (channel, evtx_paths) in &self.evtx_channels_map {
            if evtx_paths.contains(path) && self.intersection_channels.contains(channel) {
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

/// Builds a ChannelFilter by peeking at the channel of each evtx file and intersecting those
/// channels with the Channel values referenced by the loaded rules. Returns an empty filter when
/// no channel could be read from any evtx file.
pub fn create_channel_filter(
    evtx_files: &Vec<PathBuf>,
    rule_nodes: &Vec<RuleNode>,
    quiet_errors_flag: bool,
    error_log_stack: &Mutex<Nested<String>>,
) -> ChannelFilter {
    let channels =
        peek_channel_from_evtx_first_record(evtx_files, quiet_errors_flag, error_log_stack);
    if !channels.is_empty() {
        let (filtered_rule_paths, intersection_channels) =
            extract_channel_from_rules(rule_nodes, &channels.keys().cloned().collect());
        ChannelFilter {
            rule_paths: filtered_rule_paths,
            intersection_channels: intersection_channels.into_iter().collect(),
            evtx_channels_map: channels,
        }
    } else {
        ChannelFilter::new()
    }
}

/// Narrows down the evtx files to load according to the --include-channel/--exclude-channel and
/// --include-filename/--exclude-filename command line options.
pub fn filter_evtx_files(
    mut evtx_files: Vec<PathBuf>,
    include_channel: &Option<Vec<String>>,
    include_filename: &Option<Vec<String>>,
    exclude_channel: &Option<Vec<String>>,
    exclude_filename: &Option<Vec<String>>,
    error_log_stack: &Mutex<Nested<String>>,
) -> Vec<PathBuf> {
    evtx_files = apply_channel_filter(evtx_files, include_channel, false, error_log_stack);
    evtx_files = apply_channel_filter(evtx_files, exclude_channel, true, error_log_stack);
    evtx_files = apply_filename_filter(evtx_files, include_filename, false);
    apply_filename_filter(evtx_files, exclude_filename, true)
}

/// Filters evtx files by the channel recorded in their first event. Builds a minimal synthetic
/// rule that lists the requested channels and reuses the rule-vs-evtx channel matching logic
/// (create_channel_filter) to decide which files match.
fn apply_channel_filter(
    mut evtx_files: Vec<PathBuf>,
    channels: &Option<Vec<String>>,
    is_exclude: bool,
    error_log_stack: &Mutex<Nested<String>>,
) -> Vec<PathBuf> {
    if let Some(channels) = channels {
        let channels_yaml = channels
            .iter()
            .map(|channel| format!("            - '{}'", channel))
            .join("\n");
        let yaml_str = format!(
            r#"
detection:
    selection:
        Channel:
{}"#,
            channels_yaml
        );
        let yaml_data = YamlLoader::load_from_str(yaml_str.as_str());
        let maybe_doc = yaml_data.ok().and_then(|docs| docs.into_iter().next());
        if let Some(doc) = maybe_doc {
            // The rule path label ("log-metrics") is arbitrary: only channel matching matters
            // here, so the synthetic rule never surfaces to the user.
            let node = RuleNode::new("log-metrics".to_string(), doc);
            let node = vec![node];
            let mut channel_filter =
                create_channel_filter(&evtx_files, &node, false, error_log_stack);
            // Keep the files whose match result differs from is_exclude: matching files for an
            // include filter, non-matching files for an exclude filter.
            evtx_files.retain(|path| channel_filter.scannable_rule_exists(path) != is_exclude);
        }
    }
    evtx_files
}

/// Filters evtx files by file name using case-insensitive wildcard patterns (e.g. "*.evtx").
fn apply_filename_filter(
    mut evtx_files: Vec<PathBuf>,
    patterns: &Option<Vec<String>>,
    is_exclude: bool,
) -> Vec<PathBuf> {
    if let Some(patterns) = patterns {
        evtx_files.retain(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|filename| {
                    let matches = patterns.iter().any(|pattern| {
                        wildmatch::WildMatch::new(pattern.to_ascii_lowercase().as_str())
                            .matches(filename.to_ascii_lowercase().as_str())
                    });
                    matches != is_exclude
                })
        });
    }
    evtx_files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use yaml_rust2::YamlLoader;

    #[test]
    fn test_channel_filter_scannable_rule_exists() {
        let mut channel_filter = ChannelFilter::new();
        channel_filter
            .evtx_channels_map
            .insert("channel1".to_string(), vec![PathBuf::from("path1")]);
        channel_filter
            .intersection_channels
            .insert("channel1".to_string());

        assert!(channel_filter.scannable_rule_exists(&PathBuf::from("path1")));
        assert!(!channel_filter.scannable_rule_exists(&PathBuf::from("path2")));
    }

    #[test]
    fn test_peek_channel_from_evtx_first_record_invalid_evtx() {
        let evtx_files = vec![PathBuf::from("test_files/evtx/test1.evtx")];
        let result =
            peek_channel_from_evtx_first_record(&evtx_files, false, &Mutex::new(Nested::new()));
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
        let result =
            create_channel_filter(&evtx_files, &rule_nodes, false, &Mutex::new(Nested::new()));
        assert_eq!(result.rule_paths.len(), 0);
    }
}

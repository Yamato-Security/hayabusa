extern crate csv;

use chrono::{Duration, TimeZone, Utc};
use compact_str::CompactString;
use hashbrown::HashMap;
use itertools::Itertools;
use nested::Nested;
use num_format::{Locale, ToFormattedString};
use serde_json::Value;
use std::collections::HashSet;
use std::default::Default;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;
use termcolor::{BufferWriter, Color, ColorChoice};
use tokio::{runtime::Runtime, spawn, task::JoinHandle};
use yaml_rust2::Yaml;

use crate::detections::configs::Action;
use crate::detections::field_data_map::FieldDataMapKey;
use crate::detections::message::{AlertMessage, DetectInfo, ERROR_LOG_STACK, TAGS_CONFIG};
use crate::detections::rule::correlation_parser::parse_correlation_rules;
use crate::detections::rule::count::{AggRecordTimeInfo, get_sec_timeframe};
use crate::detections::rule::{self, AggResult, CorrelationType, RuleNode};
use crate::detections::utils::{
    create_recordinfos, format_time, get_writable_color, write_color_buffer,
};
use crate::detections::utils::{get_serde_number_to_string, make_ascii_titlecase};
use crate::filter;
use crate::level::LEVEL;
use crate::options::htmlreport;
use crate::options::pivot::insert_pivot_keyword;
use crate::options::profile::Profile::{
    self, Channel, Computer, EventID, EvtxFile, Level, MitreTactics, MitreTags, OtherTags,
    Provider, RecordID, RecoveredRecord, RenderedMessage, RuleAuthor, RuleCreationDate, RuleFile,
    RuleID, RuleModifiedDate, RuleTitle, SrcASN, SrcCity, SrcCountry, Status, TgtASN, TgtCity,
    TgtCountry, Timestamp,
};
use crate::yaml::ParseYaml;

use super::configs::{EventKeyAliasConfig, STORED_STATIC, StoredStatic};
use super::message::{self, COMPUTER_MITRE_ATTCK_MAP, COMPUTER_MITRE_ATTCK_UNIQUE_KEYS};

/// Struct to hold information for one record of an event file.
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // File path of the event file, used when outputting logs.
    pub record: Value,         // Data for one record serialized in JSON format.
    pub data_string: String,   // Data within one record converted to a string.
    pub key_to_value: HashMap<String, String>, // Map of hierarchical keys joined by "." and their values.
    pub recovered_record: bool,                // Whether the record was recovered.
}

impl EvtxRecordInfo {
    pub fn get_value(&self, key: &str) -> Option<&String> {
        self.key_to_value.get(key)
    }
}

/// Holds all loaded detection rules and runs them against event records.
#[derive(Debug)]
pub struct Detection {
    rules: Vec<RuleNode>,
}

impl Detection {
    pub fn new(rule_nodes: Vec<RuleNode>) -> Detection {
        Detection { rules: rule_nodes }
    }

    pub fn start(self, runtime: &Runtime, records: Vec<EvtxRecordInfo>) -> (Self, Vec<DetectInfo>) {
        runtime.block_on(self.execute_rules(records))
    }

    /// Parses the rule files under the given path and returns the successfully initialized rules,
    /// after applying the level/status/ID filters and resolving correlation rules.
    pub fn parse_rule_files(
        min_level: &str,
        target_level: &str,
        rulespath: &Path,
        exclude_ids: &filter::RuleExclude,
        stored_static: &StoredStatic,
        html_reporter: &mut htmlreport::HtmlReporter,
    ) -> Vec<RuleNode> {
        // Execute rule file parsing.
        let mut rulefile_loader = ParseYaml::new(stored_static);
        let result_readdir = rulefile_loader.read_dir(
            rulespath,
            min_level,
            target_level,
            exclude_ids,
            stored_static,
        );
        if let Err(e) = result_readdir {
            let errmsg = format!("{}", e);
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
            }
            return vec![];
        }
        let mut parse_error_count = rulefile_loader.error_rule_count;
        let return_if_success = |mut rule: RuleNode| {
            let err_msgs_result = rule.init(stored_static);
            if err_msgs_result.is_ok() {
                return Some(rule);
            }

            // Output an error if rule file parsing fails.
            err_msgs_result.err().iter().for_each(|err_msgs| {
                let errmsg_body =
                    format!("Failed to parse rule file. (FilePath : {})", rule.rule_path);
                if stored_static.verbose_flag {
                    AlertMessage::warn(&errmsg_body).ok();
                    err_msgs.iter().for_each(|err_msg| {
                        AlertMessage::warn(err_msg).ok();
                    });
                    println!();
                }
                if !stored_static.quiet_errors_flag {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[WARN] {errmsg_body}"));
                    err_msgs.iter().for_each(|err_msg| {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {err_msg}"));
                    });
                }
                parse_error_count += 1;
            });
            None
        };
        // Create a RuleNode from each loaded YAML document and keep only the rules that
        // initialize successfully.
        let mut ret = rulefile_loader
            .files
            .clone()
            .into_iter()
            .map(|rule_file_tuple| rule::create_rule(rule_file_tuple.0, rule_file_tuple.1))
            .filter_map(return_if_success)
            .collect();
        ret = parse_correlation_rules(ret, stored_static, &mut parse_error_count);
        if !(stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.metrics_flag
            || stored_static.computer_metrics_flag
            || stored_static.log_metrics_flag)
        {
            Detection::print_rule_load_info(
                &rulefile_loader,
                &parse_error_count,
                stored_static,
                html_reporter,
            );
        }
        ret
    }

    // Execute all rules against all event records; each rule runs in its own async task.
    async fn execute_rules(mut self, records: Vec<EvtxRecordInfo>) -> (Self, Vec<DetectInfo>) {
        let records_arc = Arc::new(records);
        // Spawn an async task for each rule and start executing them.
        let rules = self.rules;
        let handles: Vec<JoinHandle<(RuleNode, Vec<DetectInfo>)>> = rules
            .into_iter()
            .map(|rule| {
                let records_cloned = Arc::clone(&records_arc);
                spawn(async move { Detection::execute_rule(rule, records_cloned) })
            })
            .collect();

        // Wait for all tasks to complete execution.
        let mut rules = vec![];
        let mut all_log_records = vec![];
        for handle in handles {
            let (ret_rule, log_records) = handle.await.unwrap();
            rules.push(ret_rule);
            for log_record in log_records {
                all_log_records.push(log_record);
            }
        }

        // rules.into_iter() at the top of this function moved every rule out of self.rules and
        // into execute_rule(), so self.rules no longer has ownership. Returning an object whose
        // member variable has been moved out of is a compile error (E0382), so ownership is given
        // back to self.rules here. This is why Detection::execute_rule returns the rule it
        // received as an argument.
        self.rules = rules;

        (self, all_log_records)
    }

    /// Creates the detection messages for rules with an aggregation condition
    /// (count() rules and correlation rules). Must run after all records have been processed.
    pub fn add_aggcondition_msgs(
        self,
        runtime: &Runtime,
        stored_static: &StoredStatic,
    ) -> Vec<DetectInfo> {
        runtime.block_on(self.add_aggcondition_msg(stored_static))
    }

    /// Evaluates a Sigma temporal correlation: for each aggregation result of the first
    /// referenced rule (`ids[0]`), checks that every other referenced rule also produced a
    /// result within `timeframe`. Only results sharing the base result's `group-by` value
    /// (`AggResult.key`) are considered, so events from different groups (e.g. different
    /// Computers) are never correlated together. When `temporal_ordered` is true the referenced
    /// rules must match in the order they are listed: each match must occur at or after the
    /// previous rule's match and within the single timeframe window anchored at the base result.
    /// When false, any result within +/- `timeframe` of the base result counts. Returns the
    /// base results for which all referenced rules matched.
    fn detect_within_timeframe(
        ids: &[String],
        temporal_ref_all_results: &HashMap<String, Vec<AggResult>>,
        timeframe: Duration,
        temporal_ordered: bool,
    ) -> Vec<AggResult> {
        let mut result = Vec::new();
        let key = ids.first();
        if let Some(key) = key
            && let Some(base_records) = temporal_ref_all_results.get(key.as_str())
        {
            for base in base_records {
                let mut found = false;
                // Ordered correlations must match the referenced rules in sequence, so track the
                // timestamp the next rule is allowed to match at. It starts at the base event and
                // advances to each matched event; every match must also stay within the timeframe
                // window anchored at the base event.
                let mut order_floor = base.start_datetime;
                let window_end = base.start_datetime + timeframe;
                for id in ids.iter().skip(1) {
                    found = false;
                    if let Some(target_records) = temporal_ref_all_results.get(id.as_str()) {
                        if temporal_ordered {
                            // Only consider matches sharing the base's group-by value
                            // (AggResult.key), then pick the earliest candidate at or after the
                            // previous match so the remaining rules keep the widest window.
                            if let Some(next) = target_records
                                .iter()
                                .filter(|t| t.key == base.key)
                                .map(|t| t.start_datetime)
                                .filter(|&t| t >= order_floor && t <= window_end)
                                .min()
                            {
                                found = true;
                                order_floor = next;
                            }
                        } else {
                            found = target_records.iter().any(|t| {
                                t.key == base.key
                                    && (t.start_datetime >= base.start_datetime - timeframe)
                                    && (t.start_datetime <= base.start_datetime + timeframe)
                            });
                        }
                        if !found {
                            break;
                        }
                    }
                }
                if found {
                    result.push(base.clone());
                }
            }
        }
        result
    }

    async fn add_aggcondition_msg(&self, stored_static: &StoredStatic) -> Vec<DetectInfo> {
        let mut ret = vec![];
        let mut detected_temporal_refs: HashMap<String, Vec<AggResult>> = HashMap::new();
        // First pass: evaluate each rule's aggregation condition. Results of rules referenced by
        // a temporal correlation rule are stashed in detected_temporal_refs and are only output
        // directly when the referenced rule has generate: true.
        for rule in &self.rules {
            if !rule.has_agg_condition() {
                continue;
            }
            for value in rule.judge_satisfy_aggcondition(stored_static) {
                let mut output = true;
                if let CorrelationType::TemporalRef(generate, uuid) = &rule.correlation_type {
                    detected_temporal_refs
                        .entry(uuid.clone())
                        .or_insert_with(Vec::new)
                        .push(value.clone());
                    output = *generate;
                }
                if output {
                    ret.push(Detection::create_agg_log_record(rule, value, stored_static));
                }
            }
        }
        // Temporal correlation rules can only be evaluated after all individual rule evaluations
        // are complete, so loop through the rules again to evaluate them.
        for rule in self.rules.iter() {
            let (ref_ids, temporal_ordered) = match &rule.correlation_type {
                CorrelationType::Temporal(ref_ids) => (ref_ids, false),
                CorrelationType::TemporalOrdered(ref_ids) => (ref_ids, true),
                _ => continue,
            };
            if ref_ids
                .iter()
                .all(|x| detected_temporal_refs.contains_key(x))
            {
                let mut data = HashMap::new();
                for id in ref_ids {
                    let entry = detected_temporal_refs.get_key_value(id);
                    data.insert(entry.unwrap().0.clone(), entry.unwrap().1.clone());
                }
                let timeframe = get_sec_timeframe(rule, stored_static);
                if let Some(timeframe) = timeframe {
                    let duration = Duration::seconds(timeframe);
                    let results = Detection::detect_within_timeframe(
                        ref_ids,
                        &data,
                        duration,
                        temporal_ordered,
                    );
                    for res in results {
                        ret.push(Detection::create_agg_log_record(rule, res, stored_static));
                    }
                }
            }
        }
        ret
    }

    // Execute one rule against multiple event records.
    fn execute_rule(
        mut rule: RuleNode,
        records: Arc<Vec<EvtxRecordInfo>>,
    ) -> (RuleNode, Vec<DetectInfo>) {
        let agg_condition = rule.has_agg_condition();
        let binding = STORED_STATIC.read().unwrap();
        let stored_static = binding.as_ref().unwrap();
        let mut ret = vec![];
        for record_info in records.as_ref() {
            let result = rule.select(
                record_info,
                stored_static.verbose_flag,
                stored_static.quiet_errors_flag,
                stored_static.json_input_flag,
                &stored_static.eventkey_alias,
            );
            if !result {
                continue;
            }

            if stored_static.pivot_keyword_list_flag {
                insert_pivot_keyword(
                    &record_info.record,
                    &stored_static.eventkey_alias,
                    &stored_static.pivot_keyword,
                );
                continue;
            }

            // If the rule has no aggregation condition, output the detection as-is. Rules with an
            // aggregation condition count matches inside rule.select() and their messages are
            // created later by add_aggcondition_msg().
            if !agg_condition {
                ret.push(Detection::create_log_record(
                    &rule,
                    record_info,
                    stored_static,
                ));
            }
        }

        (rule, ret)
    }

    /// Creates a DetectInfo detection message for a single record that matched a rule, filling in
    /// every column requested by the output profile (timestamp, channel, level, MITRE tags,
    /// GeoIP data, etc.).
    fn create_log_record(
        rule: &RuleNode,
        record_info: &EvtxRecordInfo,
        stored_static: &StoredStatic,
    ) -> DetectInfo {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let rec_id = if stored_static
            .profiles
            .as_ref()
            .unwrap()
            .iter()
            .any(|(_s, p)| *p == RecordID(Default::default()))
        {
            get_serde_number_to_string(
                &record_info.record["Event"]["System"]["EventRecordID"],
                false,
            )
            .unwrap_or_default()
        } else {
            CompactString::from("")
        };
        let channel_str =
            &get_serde_number_to_string(&record_info.record["Event"]["System"]["Channel"], false)
                .unwrap_or_default();
        let provider = get_serde_number_to_string(
            &record_info.record["Event"]["System"]["Provider_attributes"]["Name"],
            false,
        )
        .unwrap_or_default()
        .replace('\'', "");
        let eid =
            get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"], false)
                .unwrap_or_else(|| "".into());
        let recovered_record = if record_info.recovered_record {
            "Y"
        } else {
            ""
        };

        let default_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let time = message::get_event_time(&record_info.record, stored_static.json_input_flag)
            .unwrap_or(default_time);
        let level_str = rule.yaml["level"].as_str().unwrap_or("-");
        let mut level = &LEVEL::from(level_str);

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();
        let eventkey_alias = &stored_static.eventkey_alias;
        let is_json_timeline = matches!(stored_static.config.action, Some(Action::JsonTimeline(_)));
        let computer_name = CompactString::from(
            record_info.record["Event"]["System"]["Computer"]
                .as_str()
                .unwrap_or_default()
                .replace('\"', ""),
        );
        let mut computer_name_to_mitre_tactics = CompactString::default();
        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(
                            format_time(
                                &time,
                                false,
                                &stored_static
                                    .output_option
                                    .as_ref()
                                    .unwrap()
                                    .time_format_options,
                            )
                            .into(),
                        ),
                    );
                }
                Computer(_) => {
                    if stored_static.html_report_flag {
                        computer_name_to_mitre_tactics = computer_name.clone();
                    }
                    profile_converter.insert(key.as_str(), Computer(computer_name.clone().into()));
                }
                Channel(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Channel(
                            stored_static
                                .generic_abbr_matcher
                                .replace_all(
                                    stored_static
                                        .channel_abbr_config
                                        .get(&channel_str.to_ascii_lowercase())
                                        .unwrap_or(channel_str)
                                        .as_str(),
                                    &stored_static.generic_abbr_values,
                                )
                                .into(),
                        ),
                    );
                }
                Level(_) => {
                    level = level.convert(computer_name.as_str());

                    let level_str = if stored_static.disable_abbreviation {
                        level.to_full()
                    } else {
                        level.to_abbrev()
                    };
                    let prof_level = if stored_static.output_path.is_none() {
                        level_str
                    } else {
                        level_str.trim()
                    };
                    profile_converter.insert(key.as_str(), Level(prof_level.to_string().into()));
                }
                EventID(_) => {
                    profile_converter.insert(key.as_str(), EventID(eid.to_string().into()));
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID(rec_id.to_string().into()));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(
                            rule.yaml["title"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string()
                                .into(),
                        ),
                    );
                }
                RuleFile(_) => {
                    let rule_file_path = CompactString::from(
                        Path::new(&rule.rule_path)
                            .file_name()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or_default(),
                    );
                    profile_converter.insert(key.as_str(), RuleFile(rule_file_path.into()));
                }
                EvtxFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EvtxFile(
                            Path::new(&record_info.evtx_filepath)
                                .display()
                                .to_string()
                                .into(),
                        ),
                    );
                }
                MitreTactics(_) => {
                    let tactics = tag_info
                        .iter()
                        .filter(|x| tags_config_values.contains(&&CompactString::from(*x)));
                    // .map(|x| TAGS_CONFIG.get(x.into()).unwrap());
                    let output_tactics_str = CompactString::from(
                        tactics
                            .clone()
                            .filter_map(|x| x.split(',').next())
                            .join(" ¦ "),
                    );

                    profile_converter.insert(
                        key.as_str(),
                        MitreTactics(output_tactics_str.clone().into()),
                    );

                    let html_output_tactics_str = tactics
                        .into_iter()
                        .map(|x| x.split(',').nth(1).unwrap_or_default())
                        .collect_vec();
                    if stored_static.html_report_flag && !html_output_tactics_str.is_empty() {
                        let mut v = COMPUTER_MITRE_ATTCK_MAP
                            .entry(computer_name_to_mitre_tactics.clone())
                            .or_default();
                        let (_, attack_tactics) = v.pair_mut();
                        for html_attck_tac in html_output_tactics_str {
                            let tactic_key: CompactString = html_attck_tac.into();
                            let unique_key = CompactString::from(format!(
                                "{}|{}|{}",
                                computer_name_to_mitre_tactics, tactic_key, rule.rule_path
                            ));
                            let is_unique = COMPUTER_MITRE_ATTCK_UNIQUE_KEYS.insert(unique_key);
                            if let Some(entry) =
                                attack_tactics.iter_mut().find(|(t, _, _)| t == tactic_key)
                            {
                                entry.1 += if is_unique { 1 } else { 0 };
                                entry.2 += 1;
                            } else {
                                attack_tactics.push((tactic_key, if is_unique { 1 } else { 0 }, 1));
                                attack_tactics.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                            }
                        }
                    }
                    // profile_converter.insert(key.as_str(), MitreTactics(output_tactics_str.into()));
                }
                MitreTags(_) => {
                    let techniques = tag_info
                        .iter()
                        .filter(|x| {
                            !tags_config_values.contains(&&CompactString::from(*x))
                                && (x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                        })
                        .map(|y| {
                            let replaced_tag = y.replace("attack.", "");
                            make_ascii_titlecase(&replaced_tag)
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), MitreTags(techniques.into()));
                }
                OtherTags(_) => {
                    let tags = tag_info
                        .iter()
                        .filter(|x| {
                            !(TAGS_CONFIG.values().contains(&CompactString::from(*x))
                                || x.starts_with("attack.t")
                                || x.starts_with("attack.g")
                                || x.starts_with("attack.s"))
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), OtherTags(tags.into()));
                }
                RuleAuthor(_) => {
                    // Store the raw author string; the multi-author formatting for multiline/tab
                    // CSV is applied at the output boundary (see results::csv::emit_csv_inner).
                    let author = rule.yaml["author"].as_str().unwrap_or("-").to_string();
                    profile_converter.insert(key.as_str(), RuleAuthor(author.into()));
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(
                            rule.yaml["date"].as_str().unwrap_or("-").to_string().into(),
                        ),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(
                            rule.yaml["modified"]
                                .as_str()
                                .unwrap_or("")
                                .to_string()
                                .into(),
                        ),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(
                            rule.yaml["status"]
                                .as_str()
                                .unwrap_or("-")
                                .to_string()
                                .into(),
                        ),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(rule.yaml["id"].as_str().unwrap_or("-").to_string().into()),
                    );
                }
                Provider(_) => {
                    let provider_value = CompactString::from(
                        record_info.record["Event"]["System"]["Provider_attributes"]["Name"]
                            .to_string()
                            .replace('\"', ""),
                    );
                    profile_converter.insert(
                        key.as_str(),
                        Provider(
                            stored_static
                                .generic_abbr_matcher
                                .replace_all(
                                    stored_static
                                        .provider_abbr_config
                                        .get(&provider_value)
                                        .unwrap_or(&provider_value),
                                    &stored_static.generic_abbr_values,
                                )
                                .into(),
                        ),
                    );
                }
                RecoveredRecord(_) => {
                    profile_converter
                        .insert("RecoveredRecord", RecoveredRecord(recovered_record.into()));
                }
                RenderedMessage(_) => {
                    let convert_value = if let Some(message) =
                        record_info.record["Event"]["RenderingInfo"]["Message"].as_str()
                    {
                        message
                            .replace('\t', "\\t")
                            .split("\r\n")
                            .map(|x| x.trim())
                            .join("\\r\\n")
                    } else {
                        "n/a".into()
                    };
                    profile_converter.insert(key.as_str(), RenderedMessage(convert_value.into()));
                }
                TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // Initialize the GeoIP Tgt-related fields.
                    profile_converter.insert("TgtASN", TgtASN("".into()));
                    profile_converter.insert("TgtCountry", TgtCountry("".into()));
                    profile_converter.insert("TgtCity", TgtCity("".into()));
                    let geo_ip_mapping = stored_static.geo_ip_db_yaml.as_ref().unwrap();
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping.get("TgtIP");
                    if target_alias.is_none() {
                        continue;
                    }
                    let target_condition = stored_static.geo_ip_filter.as_ref().unwrap();
                    let mut geoip_target_flag = false;
                    for condition in target_condition.iter() {
                        geoip_target_flag = condition.as_hash().unwrap().iter().any(
                            |(target_channel, target_eids)| {
                                channel_str.as_str() == target_channel.as_str().unwrap()
                                    && target_eids
                                        .as_vec()
                                        .unwrap()
                                        .contains(&Yaml::from_str(eid.as_str()))
                            },
                        );
                        if geoip_target_flag {
                            break;
                        }
                    }
                    if !geoip_target_flag {
                        continue;
                    }
                    let alias_data = Self::get_alias_data(
                        target_alias
                            .unwrap()
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                        false,
                    );
                    let geo_data = stored_static
                        .geo_ip_search
                        .as_ref()
                        .unwrap()
                        .convert_ip_to_geo(&alias_data);
                    if geo_data.is_err() {
                        continue;
                    }
                    let binding = geo_data.unwrap();
                    let mut tgt_data = binding
                        .split('🦅')
                        .map(|x| if x.is_empty() { "" } else { x });
                    profile_converter
                        .entry("TgtASN")
                        .and_modify(|p| *p = TgtASN(tgt_data.next().unwrap().to_owned().into()));
                    profile_converter.entry("TgtCountry").and_modify(|p| {
                        *p = TgtCountry(tgt_data.next().unwrap().to_owned().into())
                    });
                    profile_converter
                        .entry("TgtCity")
                        .and_modify(|p| *p = TgtCity(tgt_data.next().unwrap().to_owned().into()));
                }
                SrcASN(_) | SrcCountry(_) | SrcCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // Initialize the GeoIP Src-related fields.
                    profile_converter.insert("SrcASN", SrcASN("".into()));
                    profile_converter.insert("SrcCountry", SrcCountry("".into()));
                    profile_converter.insert("SrcCity", SrcCity("".into()));
                    let geo_ip_mapping = stored_static.geo_ip_db_yaml.as_ref().unwrap();
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping.get("SrcIP");
                    if target_alias.is_none() || stored_static.geo_ip_filter.is_none() {
                        continue;
                    }

                    let target_condition = stored_static.geo_ip_filter.as_ref().unwrap();
                    let mut geoip_target_flag = false;
                    for condition in target_condition.iter() {
                        geoip_target_flag = condition.as_hash().unwrap().iter().any(
                            |(target_channel, target_eids)| {
                                channel_str.as_str() == target_channel.as_str().unwrap()
                                    && target_eids
                                        .as_vec()
                                        .unwrap()
                                        .contains(&Yaml::from_str(eid.as_str()))
                            },
                        );
                        if geoip_target_flag {
                            break;
                        }
                    }
                    if !geoip_target_flag {
                        continue;
                    }

                    let alias_data = Self::get_alias_data(
                        target_alias
                            .unwrap()
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                        false,
                    );

                    let geo_data = stored_static
                        .geo_ip_search
                        .as_ref()
                        .unwrap()
                        .convert_ip_to_geo(&alias_data);
                    if geo_data.is_err() {
                        continue;
                    }
                    let binding = geo_data.unwrap();
                    let mut src_data = binding
                        .split('🦅')
                        .map(|x| if x.is_empty() { "" } else { x });
                    profile_converter
                        .entry("SrcASN")
                        .and_modify(|p| *p = SrcASN(src_data.next().unwrap().to_owned().into()));
                    profile_converter.entry("SrcCountry").and_modify(|p| {
                        *p = SrcCountry(src_data.next().unwrap().to_owned().into())
                    });
                    profile_converter
                        .entry("SrcCity")
                        .and_modify(|p| *p = SrcCity(src_data.next().unwrap().to_owned().into()));
                }
                _ => {}
            }
        }
        let field_data_map_key = if stored_static.field_data_map.is_none() {
            FieldDataMapKey::default()
        } else {
            FieldDataMapKey {
                channel: channel_str.clone().to_lowercase(),
                event_id: eid.clone(),
            }
        };
        // If the rule has a details entry, output it as-is. Otherwise fall back to the default
        // details configured for this provider and event ID combination, and if none exists,
        // output all of the record's field data.
        let details_fmt_str = match rule.yaml["details"].as_str() {
            Some(s) => s.to_string(),
            None => match stored_static
                .default_details
                .get(&CompactString::from(format!("{provider}_{eid}")))
            {
                Some(str) => str.to_string(),
                None => create_recordinfos(
                    &record_info.record,
                    &field_data_map_key,
                    &stored_static.field_data_map,
                )
                .join(" ¦ "),
            },
        };
        let detect_info = DetectInfo {
            detected_time: time,
            rule_path: CompactString::from(&rule.rule_path),
            ruleid: CompactString::from(rule.yaml["id"].as_str().unwrap_or("-")),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            ruleauthor: CompactString::from(rule.yaml["author"].as_str().unwrap_or("-")),
            level: level.clone(),
            computername: computer_name,
            eventid: eid,
            rec_id,
            detail: CompactString::default(),
            output_fields: stored_static.profiles.as_ref().unwrap().to_owned(),
            agg_result: None,
            details_convert_map: HashMap::default(),
        };

        message::create_message(
            &record_info.record,
            CompactString::new(details_fmt_str),
            detect_info,
            &profile_converter,
            (false, is_json_timeline),
            (
                eventkey_alias,
                &field_data_map_key,
                &stored_static.field_data_map,
            ),
        )
    }

    /// Creates a DetectInfo detection message for one aggregation condition (count/correlation)
    /// result. Record-specific profile columns are filled with "-" or with deduplicated joined
    /// values taken from all of the records that contributed to the aggregation.
    fn create_agg_log_record(
        rule: &RuleNode,
        agg_result: AggResult,
        stored_static: &StoredStatic,
    ) -> DetectInfo {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let output = Detection::create_count_output(rule, &agg_result);

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let level_str = rule.yaml["level"].as_str().unwrap_or("-");
        let mut level = &LEVEL::from(level_str);
        let computers =
            Detection::join_agg_values(&agg_result.agg_record_time_info, |x| x.computer.clone());
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();
        let is_json_timeline = matches!(stored_static.config.action, Some(Action::JsonTimeline(_)));
        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(
                            format_time(
                                &agg_result.start_datetime,
                                false,
                                &stored_static
                                    .output_option
                                    .as_ref()
                                    .unwrap()
                                    .time_format_options,
                            )
                            .into(),
                        ),
                    );
                }
                Computer(_) => {
                    profile_converter.insert(key.as_str(), Computer(computers.clone().into()));
                }
                Channel(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Channel(
                            Detection::join_agg_values(&agg_result.agg_record_time_info, |x| {
                                stored_static.generic_abbr_matcher.replace_all(
                                    stored_static
                                        .channel_abbr_config
                                        .get(&CompactString::from(&x.channel.to_ascii_lowercase()))
                                        .unwrap_or(&CompactString::from(&x.channel))
                                        .as_str(),
                                    &stored_static.generic_abbr_values,
                                )
                            })
                            .into(),
                        ),
                    );
                }
                Level(_) => {
                    level = level.convert(computers.as_str());
                    let level_str = if stored_static.disable_abbreviation {
                        level.to_full()
                    } else {
                        level.to_abbrev()
                    };
                    let prof_level = if stored_static.output_path.is_none() {
                        level_str
                    } else {
                        level_str.trim()
                    };
                    profile_converter.insert(key.as_str(), Level(prof_level.to_string().into()));
                }
                EventID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EventID(
                            Detection::join_agg_values(&agg_result.agg_record_time_info, |x| {
                                x.event_id.clone()
                            })
                            .into(),
                        ),
                    );
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID("".into()));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(
                            rule.yaml["title"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                RuleFile(_) => {
                    let rule_file_path = CompactString::from(
                        Path::new(&rule.rule_path)
                            .file_name()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or_default(),
                    );
                    profile_converter.insert(key.as_str(), RuleFile(rule_file_path.into()));
                }
                EvtxFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EvtxFile(
                            Detection::join_agg_values(&agg_result.agg_record_time_info, |x| {
                                x.evtx_file_path.clone()
                            })
                            .into(),
                        ),
                    );
                }
                MitreTactics(_) => {
                    let tactics = tag_info
                        .iter()
                        .filter(|x| tags_config_values.contains(&&CompactString::from(*x)));
                    let output_tactics_str = CompactString::from(
                        tactics
                            .clone()
                            .filter_map(|x| x.split(',').next())
                            .join(" ¦ "),
                    );
                    profile_converter.insert(
                        key.as_str(),
                        MitreTactics(output_tactics_str.clone().into()),
                    );
                }
                MitreTags(_) => {
                    let techniques = tag_info
                        .iter()
                        .filter(|x| {
                            !tags_config_values.contains(&&CompactString::from(*x))
                                && (x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                        })
                        .map(|y| {
                            let replaced_tag = y.replace("attack.", "");
                            make_ascii_titlecase(&replaced_tag)
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), MitreTags(techniques.into()));
                }
                OtherTags(_) => {
                    let tags = tag_info
                        .iter()
                        .filter(|x| {
                            !(tags_config_values.contains(&&CompactString::from(*x))
                                || x.starts_with("attack.t")
                                || x.starts_with("attack.g")
                                || x.starts_with("attack.s"))
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), OtherTags(tags.into()));
                }
                RuleAuthor(_) => {
                    // Store the raw author string; the multi-author formatting for multiline/tab
                    // CSV is applied at the output boundary (see results::csv::emit_csv_inner).
                    let author = rule.yaml["author"].as_str().unwrap_or("-").to_string();
                    profile_converter.insert(key.as_str(), RuleAuthor(author.into()));
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(
                            rule.yaml["date"].as_str().unwrap_or("-").to_owned().into(),
                        ),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(
                            rule.yaml["modified"]
                                .as_str()
                                .unwrap_or("")
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(
                            rule.yaml["status"]
                                .as_str()
                                .unwrap_or("-")
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(rule.yaml["id"].as_str().unwrap_or("-").to_owned().into()),
                    );
                }
                Provider(_) => {
                    profile_converter.insert(key.as_str(), Provider("-".into()));
                }
                RecoveredRecord(_) => {
                    profile_converter.insert("RecoveredRecord", RenderedMessage("".into()));
                }
                RenderedMessage(_) => {
                    profile_converter.insert(key.as_str(), RenderedMessage("-".into()));
                }
                TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    profile_converter.insert("TgtASN", TgtASN("-".into()));
                    profile_converter.insert("TgtCountry", TgtCountry("-".into()));
                    profile_converter.insert("TgtCity", TgtCity("-".into()));
                }
                SrcASN(_) | SrcCountry(_) | SrcCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    profile_converter.insert("SrcASN", SrcASN("-".into()));
                    profile_converter.insert("SrcCountry", SrcCountry("-".into()));
                    profile_converter.insert("SrcCity", SrcCity("-".into()));
                }
                _ => {}
            }
        }
        let detect_info = DetectInfo {
            detected_time: agg_result.start_datetime,
            rule_path: CompactString::from(&rule.rule_path),
            ruleid: CompactString::from(rule.yaml["id"].as_str().unwrap_or("-")),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            ruleauthor: CompactString::from(rule.yaml["author"].as_str().unwrap_or("-")),
            level: level.clone(),
            computername: CompactString::from("-"),
            eventid: CompactString::from("-"),
            rec_id: CompactString::from("-"),
            detail: output,
            output_fields: stored_static.profiles.as_ref().unwrap().to_owned(),
            agg_result: Some(agg_result),
            details_convert_map: HashMap::default(),
        };
        let eventkey_alias = &stored_static.eventkey_alias;

        let field_data_map_key = FieldDataMapKey::default();

        message::create_message(
            &Value::default(),
            CompactString::from(detect_info.detail.as_str()),
            detect_info,
            &profile_converter,
            (true, is_json_timeline),
            (eventkey_alias, &field_data_map_key, &None),
        )
    }

    /// Extracts a value from each aggregated record, removes duplicates, and joins the sorted
    /// values with " ¦ ".
    fn join_agg_values<F>(
        agg_record_time_infos: &[AggRecordTimeInfo],
        extractor: F,
    ) -> CompactString
    where
        F: Fn(&AggRecordTimeInfo) -> String,
    {
        agg_record_time_infos
            .iter()
            .map(&extractor)
            .collect::<HashSet<_>>() // Convert to HashSet to remove duplicates
            .into_iter()
            .sorted()
            .join(" ¦ ")
            .into()
    }
    /// Function to return the contents of tags in a rule as an array.
    fn get_tag_info(rule: &RuleNode) -> Nested<String> {
        Nested::from_iter(
            rule.yaml["tags"]
                .as_vec()
                .unwrap_or(&Vec::default())
                .iter()
                .map(|info| {
                    if let Some(tag) = TAGS_CONFIG.get(info.as_str().unwrap_or_default()) {
                        tag.to_owned()
                    } else {
                        CompactString::from(info.as_str().unwrap_or_default())
                    }
                }),
        )
    }

    /// Function that returns the detection output string for the count portion of the aggregation condition.
    fn create_count_output(rule: &RuleNode, agg_result: &AggResult) -> CompactString {
        let mut ret: String = "".to_string();
        // This function is only called for rules that have an aggregation condition, so the
        // unwrap() here is safe.
        let agg_condition = rule.get_agg_condition().unwrap();
        write!(ret, "Count:{}", agg_result.data).ok();
        let mut sorted_field_values = agg_result.field_values.clone();
        sorted_field_values.sort();
        if let Some(_field_name) = agg_condition._field_name.as_ref() {
            write!(ret, " ¦ {}:{}", _field_name, sorted_field_values.join("/")).ok();
        }

        if let Some(_by_field_name) = agg_condition._by_field_name.as_ref() {
            let field_name = _by_field_name;
            if field_name.contains(',') {
                write!(
                    ret,
                    " ¦ {}",
                    Self::zip_and_concat_strings(field_name, &agg_result.key)
                )
                .ok();
            } else {
                write!(ret, " ¦ {}:{}", field_name, agg_result.key).ok();
            }
        }

        CompactString::from(ret)
    }

    /// Pairs the comma-separated field names in `s1` with the comma-separated values in `s2` and
    /// joins the resulting "name:value" pairs with " ¦ " (used for `count() by fieldA,fieldB`
    /// output).
    fn zip_and_concat_strings(s1: &str, s2: &str) -> String {
        let v1: Vec<&str> = s1.split(',').collect();
        let v2: Vec<&str> = s2.split(',').collect();
        v1.into_iter()
            .zip(v2)
            .map(|(s1, s2)| format!("{s1}:{s2}"))
            .collect::<Vec<String>>()
            .join(" ¦ ")
    }

    /// Prints the rule loading summary to stdout (rule counts by category, status,
    /// correlation/expand rules and the total) and accumulates the same lines for the HTML
    /// report (except the expand-rule lines, which are printed to stdout only).
    pub fn print_rule_load_info(
        parse_yaml: &ParseYaml,
        err_rc: &u128,
        stored_static: &StoredStatic,
        html_reporter: &mut htmlreport::HtmlReporter,
    ) {
        let rc = &parse_yaml.rule_type_cnt;
        let ld_rc = &parse_yaml.rule_load_cnt;
        let st_rc = &parse_yaml.rule_status_cnt;
        let cor_rc = &parse_yaml.rule_cor_cnt;
        let cor_ref_rc = &parse_yaml.rule_cor_ref_cnt;

        let mut sorted_ld_rc: Vec<(&CompactString, &u128)> = ld_rc.iter().collect();
        sorted_ld_rc.sort_by(|a, b| a.0.cmp(b.0));
        let mut html_report_stock = Nested::<String>::new();

        sorted_ld_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let disable_flag = if key.as_str() == "noisy"
                    && !stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .enable_noisy_rules
                {
                    " (Disabled)"
                } else {
                    ""
                };
                // Change the first character to uppercase, assuming that the titles use ASCII characters.
                let key = format!("{} rules: ", make_ascii_titlecase(key));
                let val = format!("{}{}", value.to_formatted_string(&Locale::en), disable_flag);
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    get_writable_color(
                        Some(Color::Rgb(0, 255, 0)),
                        stored_static.common_options.no_color,
                    ),
                    key.as_str(),
                    false,
                )
                .ok();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    val.as_str(),
                    true,
                )
                .ok();
                if stored_static.html_report_flag {
                    let output_str = format!("{key}{val}");
                    html_report_stock.push(format!("- {output_str}"));
                }
            }
        });
        if err_rc != &0_u128 {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                Some(Color::Rgb(255, 0, 0)),
                &format!("Rule parsing errors: {err_rc}"),
                true,
            )
            .ok();
        }
        if !ld_rc.is_empty() {
            println!();
        }
        let mut sorted_st_rc: Vec<(&CompactString, &u128)> = st_rc.iter().collect();
        let output_opt = stored_static.output_option.as_ref().unwrap();
        let enable_deprecated_flag = output_opt.enable_deprecated_rules;
        let enable_unsupported_flag = output_opt.enable_unsupported_rules;
        let is_filtered_rule_flag = |x: &CompactString| {
            x == "deprecated" && !enable_deprecated_flag
                || x == "unsupported" && !enable_unsupported_flag
        };
        let total_loaded_rule_cnt: u128 = sorted_st_rc
            .iter()
            .filter(|(k, _)| !is_filtered_rule_flag(k))
            .map(|(_, v)| *v)
            .sum();
        sorted_st_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_st_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let rate = (*value as f64) / (total_loaded_rule_cnt as f64) * 100.0;
                let disabled_flag = if is_filtered_rule_flag(key) {
                    " (Disabled)"
                } else {
                    ""
                };
                let key = format!("{} rules: ", make_ascii_titlecase(key));
                let val = format!(
                    "{} ({:.2}%){}",
                    value.to_formatted_string(&Locale::en),
                    rate,
                    disabled_flag
                );
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    get_writable_color(
                        Some(Color::Rgb(0, 255, 0)),
                        stored_static.common_options.no_color,
                    ),
                    key.as_str(),
                    false,
                )
                .ok();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    val.as_str(),
                    true,
                )
                .ok();
                if stored_static.html_report_flag {
                    let output_str = format!("{key}{val}");
                    html_report_stock.push(format!("- {output_str}"));
                }
            }
        });
        println!();

        let cor_total: u128 = cor_rc.values().sum();
        let cor_ref_total: u128 = cor_ref_rc.values().sum();
        if cor_total != 0 {
            let key = "Correlation rules: ";
            let val = format!(
                "{} ({:.2}%)",
                cor_total.to_formatted_string(&Locale::en),
                (cor_total as f64) / (total_loaded_rule_cnt as f64) * 100.0
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(
                    Some(Color::Rgb(0, 255, 0)),
                    stored_static.common_options.no_color,
                ),
                key,
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(None, stored_static.common_options.no_color),
                val.as_str(),
                true,
            )
            .ok();
            let col = format!("{key}{val}");
            let key = "Correlation referenced rules: ";
            let val = format!(
                "{} ({:.2}%)",
                cor_ref_total.to_formatted_string(&Locale::en),
                (cor_ref_total as f64) / (total_loaded_rule_cnt as f64) * 100.0
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(
                    Some(Color::Rgb(0, 255, 0)),
                    stored_static.common_options.no_color,
                ),
                key,
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                val.as_str(),
                true,
            )
            .ok();
            let col_ref = format!("{key}{val}");
            if stored_static.html_report_flag {
                html_report_stock.push(format!("- {col}"));
                html_report_stock.push(format!("- {col_ref}"));
            }
            println!();
        }

        let expand_total = parse_yaml.rule_expand_cnt;
        let expand_enabled_total = parse_yaml.rule_expand_enabled_cnt;
        let rate = if total_loaded_rule_cnt != 0 {
            (expand_total as f64) / (total_loaded_rule_cnt as f64) * 100.0
        } else {
            0.0
        };
        let key = "Expand rules: ";
        let val = format!(
            "{} ({:.2}%)",
            expand_total.to_formatted_string(&Locale::en),
            rate
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            key,
            false,
        )
        .ok();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(None, stored_static.common_options.no_color),
            val.as_str(),
            true,
        )
        .ok();
        let rate = if total_loaded_rule_cnt != 0 {
            (expand_enabled_total as f64) / (total_loaded_rule_cnt as f64) * 100.0
        } else {
            0.0
        };
        let key = "Enabled expand rules: ";
        let val = format!(
            "{} ({:.2}%)",
            expand_enabled_total.to_formatted_string(&Locale::en),
            rate
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            key,
            false,
        )
        .ok();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            val.as_str(),
            true,
        )
        .ok();
        println!();

        let mut sorted_rc: Vec<(&CompactString, &u128)> = rc.iter().collect();
        sorted_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_rc.into_iter().for_each(|(key, value)| {
            let key = format!("{key} rules: ");
            let val = value.to_formatted_string(&Locale::en);
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(
                    Some(Color::Rgb(0, 255, 0)),
                    stored_static.common_options.no_color,
                ),
                key.as_str(),
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                val.as_str(),
                true,
            )
            .ok();
            if stored_static.html_report_flag {
                html_report_stock.push(format!("- {key}{val}"));
            }
        });
        let key = "Total detection rules: ";
        let val = total_loaded_rule_cnt.to_formatted_string(&Locale::en);
        let tmp_total_detect_output = format!(
            "Total detection rules: {}",
            total_loaded_rule_cnt.to_formatted_string(&Locale::en)
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            key,
            false,
        )
        .ok();
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            None,
            val.as_str(),
            true,
        )
        .ok();
        println!();
        if stored_static.html_report_flag {
            html_report_stock.push(format!("- {tmp_total_detect_output}"));
        }
        if !html_report_stock.is_empty() {
            html_reporter.add_md_data(htmlreport::GENERAL_OVERVIEW_SECTION, html_report_stock);
        }
    }

    /// Retrieves the value of the first alias that resolves in the record, or "-" when none of
    /// the given aliases yield a value.
    fn get_alias_data(
        target_alias: Vec<&str>,
        record: &Value,
        eventkey_alias: &EventKeyAliasConfig,
        is_csv_output: bool,
    ) -> CompactString {
        for alias in target_alias {
            let (search_data, _) = message::parse_message(
                record,
                &CompactString::from(alias),
                eventkey_alias,
                is_csv_output,
                &FieldDataMapKey::default(),
                &None,
            );
            if search_data != "n/a" {
                return search_data;
            }
        }
        CompactString::from("-")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::TimeZone;
    use chrono::Utc;
    use compact_str::CompactString;
    use serde_json::Value;
    use yaml_rust2::Yaml;
    use yaml_rust2::YamlLoader;

    use crate::detections;
    use crate::detections::configs::Action;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::detection::Detection;
    use crate::detections::rule::AggResult;
    use crate::detections::rule::RuleNode;
    use crate::detections::rule::create_rule;
    use crate::detections::utils;
    use crate::filter;
    use crate::options::profile::Profile;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    min_level: "informational".to_string(),
                    include_status: Some(vec!["*".to_string()]),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            ..Default::default()
        }))
    }

    #[test]
    fn test_parse_rule_files() {
        let level = "informational";
        let opt_rule_path = Path::new("./test_files/rules/level_yaml");
        let dummy_stored_static = create_dummy_stored_static();
        let cole = Detection::parse_rule_files(
            level,
            "",
            opt_rule_path,
            &filter::exclude_ids(&dummy_stored_static),
            &dummy_stored_static,
            &mut crate::options::htmlreport::HtmlReporter::default(),
        );
        assert_eq!(5, cole.len());
    }

    #[test]
    fn test_detect_within_timeframe_enforces_group_by() {
        use chrono::Duration;
        use hashbrown::HashMap;

        let base_time = Utc.with_ymd_and_hms(2024, 1, 1, 10, 0, 0).unwrap();
        let at = |min: i64| base_time + Duration::minutes(min);
        // `AggResult.key` holds the group-by value (e.g. the Computer name).
        let agg = |key: &str, t| AggResult::new(1, key.to_string(), vec![], t, vec![]);
        let ids = vec!["a".to_string(), "b".to_string()];
        let timeframe = Duration::minutes(10);

        // Base rule "a" matched for Host1, but rule "b" only matched for Host2 within the
        // window. The correlation must NOT fire because the matches are from different groups.
        let mut diff_group: HashMap<String, Vec<AggResult>> = HashMap::new();
        diff_group.insert("a".to_string(), vec![agg("Host1", at(0))]);
        diff_group.insert("b".to_string(), vec![agg("Host2", at(5))]);
        for ordered in [true, false] {
            assert!(
                Detection::detect_within_timeframe(&ids, &diff_group, timeframe, ordered)
                    .is_empty(),
                "matches from different group-by values must not correlate (ordered={ordered})"
            );
        }

        // When rule "b" also matched for Host1 within the window, the correlation fires and the
        // returned base result is the Host1 group (the mismatched Host2 candidate is ignored).
        let mut same_group: HashMap<String, Vec<AggResult>> = HashMap::new();
        same_group.insert("a".to_string(), vec![agg("Host1", at(0))]);
        same_group.insert(
            "b".to_string(),
            vec![agg("Host2", at(3)), agg("Host1", at(5))],
        );
        for ordered in [true, false] {
            let res = Detection::detect_within_timeframe(&ids, &same_group, timeframe, ordered);
            assert_eq!(
                res.len(),
                1,
                "same-group matches should correlate (ordered={ordered})"
            );
            assert_eq!(res[0].key, "Host1");
        }
    }

    #[test]
    fn test_detect_within_timeframe_ordered_enforces_order() {
        use chrono::Duration;
        use hashbrown::HashMap;

        let base = Utc.with_ymd_and_hms(2024, 1, 1, 10, 0, 0).unwrap();
        let at = |min: i64| base + Duration::minutes(min);
        let agg = |t| AggResult::new(1, "_".to_string(), vec![], t, vec![]);
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let timeframe = Duration::minutes(10);

        // In-order events a(0) -> b(5) -> c(8) satisfy an ordered correlation.
        let mut in_order: HashMap<String, Vec<AggResult>> = HashMap::new();
        in_order.insert("a".to_string(), vec![agg(at(0))]);
        in_order.insert("b".to_string(), vec![agg(at(5))]);
        in_order.insert("c".to_string(), vec![agg(at(8))]);
        assert_eq!(
            Detection::detect_within_timeframe(&ids, &in_order, timeframe, true).len(),
            1,
            "in-order events should satisfy an ordered correlation"
        );

        // Out-of-order events a(0), c(2), b(5): the rule order is a,b,c but c occurs before b,
        // so an ordered correlation must NOT fire (regression test for issue #1810).
        let mut out_of_order: HashMap<String, Vec<AggResult>> = HashMap::new();
        out_of_order.insert("a".to_string(), vec![agg(at(0))]);
        out_of_order.insert("b".to_string(), vec![agg(at(5))]);
        out_of_order.insert("c".to_string(), vec![agg(at(2))]);
        assert!(
            Detection::detect_within_timeframe(&ids, &out_of_order, timeframe, true).is_empty(),
            "out-of-order events must not satisfy an ordered correlation"
        );

        // The same events DO satisfy an unordered temporal correlation.
        assert_eq!(
            Detection::detect_within_timeframe(&ids, &out_of_order, timeframe, false).len(),
            1,
            "an unordered correlation ignores event order"
        );

        // Events that fall outside the timeframe window are not correlated even when ordered.
        let mut out_of_window: HashMap<String, Vec<AggResult>> = HashMap::new();
        out_of_window.insert("a".to_string(), vec![agg(at(0))]);
        out_of_window.insert("b".to_string(), vec![agg(at(5))]);
        out_of_window.insert("c".to_string(), vec![agg(at(12))]);
        assert!(
            Detection::detect_within_timeframe(&ids, &out_of_window, timeframe, true).is_empty(),
            "events beyond the timeframe window must not correlate"
        );
    }

    #[test]
    fn test_output_aggregation_output_with_output() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count() >= 1
        output: testdata
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_no_field_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 |   count() >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_timeframe() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 |   count() >= 1
            timeframe: 15m
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult = AggResult::new(
            2,
            "_".to_string(),
            vec!["7040".to_owned(), "9999".to_owned()],
            default_time,
            vec![],
        );
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count(EventID) >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2 ¦ EventID:7040/9999";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult = AggResult::new(
            2,
            "lsass.exe".to_string(),
            vec!["0000".to_owned(), "1111".to_owned()],
            default_time,
            vec![],
        );
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count(EventID) by process >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2 ¦ EventID:0000/1111 ¦ process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }
    #[test]
    fn test_output_aggregation_output_with_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "lsass.exe".to_string(), vec![], default_time, vec![]);
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count() by process >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "Count:2 ¦ process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_insert_message_with_geoip() {
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            geo_ip: Some(Path::new("test_files/mmdb").to_path_buf()),
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        {
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );

            let val = r#"
            {
                "Event": {
                    "EventData": {
                        "CommandRLine": "hoge",
                        "IpAddress": "89.160.20.128",
                        "DestAddress": "2.125.160.216"
                    },
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "1996-02-27T01:05:01Z"
                        },
                        "EventRecordID": "11111",
                        "Channel": "Security",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let dummy_rule = RuleNode::new(test_rule_path.to_string(), Yaml::from_str(""));
            let keys = detections::rule::get_detection_keys(&dummy_rule);

            let input_evtxrecord = utils::create_rec_info(
                event,
                test_filepath.to_owned(),
                &keys,
                &false,
                &false,
                &eventkey_alias,
            );
            {
                let rule = &dummy_rule;
                let record_info = &input_evtxrecord;
                let stored_static = &stored_static;
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

                let expect_geo_ip_data: Vec<(CompactString, Profile)> = vec![
                    ("SrcASN".into(), Profile::SrcASN("Bredband2 AB".into())),
                    ("SrcCountry".into(), Profile::SrcCountry("Sweden".into())),
                    ("SrcCity".into(), Profile::SrcCity("Linköping".into())),
                    ("TgtASN".into(), Profile::TgtASN("".into())),
                    (
                        "TgtCountry".into(),
                        Profile::TgtCountry("United Kingdom".into()),
                    ),
                    ("TgtCity".into(), Profile::TgtCity("Boxford".into())),
                ];
                let output_fields = detect_info.output_fields.clone();
                for expect in expect_geo_ip_data.iter() {
                    assert!(output_fields.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_filtered_insert_message_with_geoip() {
        let test_filepath: &str = "test.evtx";
        let test_rule_path: &str = "test-rule.yml";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            geo_ip: Some(Path::new("test_files/mmdb").to_path_buf()),
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        {
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );

            let val = r#"
            {
                "Event": {
                    "EventData": {
                        "CommandRLine": "hoge",
                        "IpAddress": "89.160.20.128",
                        "DestAddress": "2.125.160.216"
                    },
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "1996-02-27T01:05:01Z"
                        },
                        "EventRecordID": "11111",
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let dummy_rule = RuleNode::new(test_rule_path.to_string(), Yaml::from_str(""));
            let keys = detections::rule::get_detection_keys(&dummy_rule);

            let input_evtxrecord = utils::create_rec_info(
                event,
                test_filepath.to_owned(),
                &keys,
                &false,
                &false,
                &eventkey_alias,
            );
            {
                let rule = &dummy_rule;
                let record_info = &input_evtxrecord;
                let stored_static = &stored_static;
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);
                let expect_geo_ip_data: Vec<(CompactString, Profile)> = vec![
                    ("SrcASN".into(), Profile::SrcASN("".into())),
                    ("SrcCountry".into(), Profile::SrcCountry("".into())),
                    ("SrcCity".into(), Profile::SrcCity("".into())),
                    ("TgtASN".into(), Profile::TgtASN("".into())),
                    ("TgtCountry".into(), Profile::TgtCountry("".into())),
                    ("TgtCity".into(), Profile::TgtCity("".into())),
                ];
                let output_fields = detect_info.output_fields.clone();
                for expect in expect_geo_ip_data.iter() {
                    assert!(output_fields.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_insert_message_extra_field_info() {
        let test_filepath: &str = "test.evtx";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_summary: true,
                no_wizard: true,
                ..Default::default()
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: true,
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(dummy_config);
        stored_static.profiles.as_mut().unwrap().push((
            "ExtraFieldInfo".into(),
            Profile::ExtraFieldInfo(Default::default()),
        ));
        {
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );

            let val = r#"
            {
                "Event": {
                    "EventData": {
                        "CommandRLine": "hoge",
                        "IpAddress": "89.160.20.128",
                        "DestAddress": "2.125.160.216"
                    },
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "1996-02-27T01:05:01Z"
                        },
                        "EventRecordID": "11111",
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let rule_str = r#"
        enabled: true
        author: "Test, Test2/Test3; Test4 "
        detection:
            selection:
                Channel: 'Dummy'
        details: 'Channel: %Channel% ¦ EventID: %EventID% ¦ EventRecordID: %EventRecordID% ¦ TimeCreated: %TimeCreated% ¦ IpAddress: %IpAddress%'
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let rule_yaml = YamlLoader::load_from_str(rule_str);
            assert!(rule_yaml.is_ok());
            let rule_yamls = rule_yaml.unwrap();
            let mut rule_yaml = rule_yamls.into_iter();
            let mut rule_node = create_rule(test_filepath.to_string(), rule_yaml.next().unwrap());
            assert!(rule_node.init(&create_dummy_stored_static()).is_ok());

            let keys = detections::rule::get_detection_keys(&rule_node);
            let input_evtxrecord = utils::create_rec_info(
                event,
                test_filepath.to_owned(),
                &keys,
                &false,
                &false,
                &eventkey_alias,
            );
            {
                let rule = &rule_node;
                let record_info = &input_evtxrecord;
                let stored_static: &StoredStatic = &stored_static.clone();
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

                let expect_extra_field_data: Vec<(CompactString, Profile)> = vec![(
                    "ExtraFieldInfo".into(),
                    Profile::ExtraFieldInfo(
                        "CommandRLine: hoge ¦ DestAddress: 2.125.160.216".into(),
                    ),
                )];
                let output_fields = detect_info.output_fields.clone();
                for expect in expect_extra_field_data.iter() {
                    assert!(output_fields.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_insert_message_multiline_ruleauthor() {
        let test_filepath: &str = "test.evtx";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            },
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: true,
            ..Default::default()
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(dummy_config);
        stored_static
            .profiles
            .as_mut()
            .unwrap()
            .push(("RuleAuthor".into(), Profile::RuleAuthor(Default::default())));
        {
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );

            let val = r#"
            {
                "Event": {
                    "EventData": {
                        "CommandRLine": "hoge",
                        "IpAddress": "89.160.20.128",
                        "DestAddress": "2.125.160.216"
                    },
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "1996-02-27T01:05:01Z"
                        },
                        "EventRecordID": "11111",
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let rule_str = r#"
        enabled: true
        author: "Test, Test2/Test3; Test4 "
        detection:
            selection:
                Channel: 'Dummy'
        details: 'Test'
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let rule_yaml = YamlLoader::load_from_str(rule_str);
            assert!(rule_yaml.is_ok());
            let rule_yamls = rule_yaml.unwrap();
            let mut rule_yaml = rule_yamls.into_iter();
            let mut rule_node = create_rule(test_filepath.to_string(), rule_yaml.next().unwrap());
            assert!(rule_node.init(&create_dummy_stored_static()).is_ok());

            let keys = detections::rule::get_detection_keys(&rule_node);
            let input_evtxrecord = utils::create_rec_info(
                event,
                test_filepath.to_owned(),
                &keys,
                &false,
                &false,
                &eventkey_alias,
            );
            {
                let rule = &rule_node;
                let record_info = &input_evtxrecord;
                let stored_static: &StoredStatic = &stored_static.clone();
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

                println!("{:?}", detect_info.output_fields);
                // The RuleAuthor field now holds the raw author string; the multiline/tab
                // author formatting is applied at CSV emit time (results::csv).
                assert!(detect_info.output_fields.iter().any(|x| x
                    == &(
                        CompactString::from("RuleAuthor"),
                        Profile::RuleAuthor("Test, Test2/Test3; Test4 ".into())
                    )));
            }
        }
    }
}

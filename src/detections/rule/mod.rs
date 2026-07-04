extern crate regex;

use super::configs::{EventKeyAliasConfig, StoredStatic};
use super::detection::EvtxRecordInfo;
use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use nested::Nested;
use std::cmp::PartialEq;
use std::{fmt::Debug, sync::Arc, vec};
use yaml_rust2::Yaml;

use self::aggregation_parser::AggregationParseInfo;
use self::count::{AggRecordTimeInfo, TimeFrameInfo};
use self::selectionnodes::{LeafSelectionNode, SelectionNode};

mod aggregation_parser;
mod base64_match;
mod condition_parser;
pub mod correlation_parser;
pub(crate) mod count;
mod fast_match;
mod matchers;
mod selectionnodes;

pub fn create_rule(rule_path: String, yaml: Yaml) -> RuleNode {
    RuleNode::new(rule_path, yaml)
}

/// The `correlation.type` of a Sigma correlation rule.
#[derive(Debug, PartialEq, Eq)]
pub enum CorrelationType {
    /// Not a correlation rule (also used for unknown correlation types).
    None,
    /// `event_count`: counts matching events per group.
    EventCount,
    /// `value_count`: counts distinct field values per group.
    ValueCount,
    /// `temporal`: all referenced rules (matched by id, title or name) must match within the
    /// timespan, in any order.
    Temporal(Vec<String>),
    /// `temporal_ordered`: like `temporal`, but the referenced rules are expected to occur in
    /// the listed order (the current implementation only checks order relative to the first
    /// referenced rule's results).
    TemporalOrdered(Vec<String>),
    /// Assigned by the correlation parser (never by `CorrelationType::new`) to a rule that is
    /// referenced by a temporal correlation rule. The bool is the correlation rule's `generate`
    /// flag (whether the referenced rule's own matches are also output) and the String is the
    /// rule id used to link its results to the temporal rule.
    TemporalRef(bool, String),
}

impl CorrelationType {
    fn new(yaml: &Yaml) -> CorrelationType {
        if yaml["correlation"]["type"].as_str().is_none() {
            return CorrelationType::None;
        }
        let correlation_type = yaml["correlation"]["type"].as_str().unwrap();
        match correlation_type {
            "event_count" => CorrelationType::EventCount,
            "value_count" => CorrelationType::ValueCount,
            "temporal" | "temporal_ordered" => {
                let rules: Vec<String> = yaml["correlation"]["rules"]
                    .as_vec()
                    .unwrap()
                    .iter()
                    .map(|rule| rule.as_str().unwrap().to_string())
                    .collect();
                if correlation_type == "temporal" {
                    CorrelationType::Temporal(rules)
                } else {
                    CorrelationType::TemporalOrdered(rules)
                }
            }
            // Unknown correlation types map to None; the correlation parser later rejects such
            // rules with a parse error, so they never match.
            _ => CorrelationType::None,
        }
    }
}

/// Node representing a Rule file.
pub struct RuleNode {
    pub rule_path: String,
    pub yaml: Yaml,
    pub detection: DetectionNode,
    countdata: HashMap<String, Vec<AggRecordTimeInfo>>,
    pub correlation_type: CorrelationType,
}

// Debug cannot be derived because DetectionNode holds `dyn SelectionNode` trait objects, so this
// implementation intentionally produces no output.
impl Debug for RuleNode {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Result::Ok(())
    }
}

impl RuleNode {
    pub fn new(rule_path: String, yaml_data: Yaml) -> RuleNode {
        RuleNode {
            correlation_type: CorrelationType::new(&yaml_data),
            rule_path,
            yaml: yaml_data,
            detection: DetectionNode::new(),
            countdata: HashMap::new(),
        }
    }

    /// Creates a RuleNode with a pre-built DetectionNode. Used by the correlation parser, which
    /// assembles the detection from the rules referenced by a correlation rule.
    fn new_with_detection(
        rule_path: String,
        yaml_data: Yaml,
        detection: DetectionNode,
    ) -> RuleNode {
        RuleNode {
            correlation_type: CorrelationType::new(&yaml_data),
            rule_path,
            yaml: yaml_data,
            detection,
            countdata: HashMap::new(),
        }
    }

    /// Parses and validates the rule's detection section, collecting all error messages.
    pub fn init(&mut self, stored_static: &StoredStatic) -> Result<(), Vec<String>> {
        let mut errmsgs: Vec<String> = vec![];
        // Correlation rules get their DetectionNode built later by
        // correlation_parser::parse_correlation_rules, so there is nothing to initialize here.
        if !&self.yaml["correlation"].is_badvalue() {
            return Result::Ok(());
        }

        // Initialize the detection node.
        let detection_result = self.detection.init(&self.yaml["detection"], stored_static);
        if let Err(err_detail) = detection_result {
            errmsgs.extend(err_detail);
        }

        if errmsgs.is_empty() {
            Result::Ok(())
        } else {
            Result::Err(errmsgs)
        }
    }

    /// Evaluates this rule's condition against a single event record. When the record matches and
    /// the rule has an aggregation condition (count etc.), the record is also registered in
    /// countdata for later aggregation evaluation.
    pub fn select(
        &mut self,
        event_record: &EvtxRecordInfo,
        verbose_flag: bool,
        quiet_errors_flag: bool,
        json_input_flag: bool,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> bool {
        let result = self.detection.select(event_record, eventkey_alias);
        if result && self.has_agg_condition() {
            count::count(
                self,
                event_record,
                verbose_flag,
                quiet_errors_flag,
                json_input_flag,
            );
        }
        result
    }
    /// Returns whether an aggregation condition exists.
    pub fn has_agg_condition(&self) -> bool {
        self.detection.aggregation_condition.is_some()
    }
    /// Returns the results of evaluating the aggregation condition as an array.
    pub fn judge_satisfy_aggcondition(&self, stored_static: &StoredStatic) -> Vec<AggResult> {
        let mut ret = Vec::new();
        if !self.has_agg_condition() {
            return ret;
        }
        ret.append(&mut count::aggregation_condition_select(
            self,
            stored_static,
        ));
        ret
    }
    /// Returns whether any records have been accumulated for count aggregation.
    pub fn check_exist_countdata(&self) -> bool {
        !self.countdata.is_empty()
    }
    /// Returns the AggregationParseInfo (aggregation condition) of this rule, if any.
    pub fn get_agg_condition(&self) -> Option<&AggregationParseInfo> {
        if self.detection.aggregation_condition.as_ref().is_some() {
            return self.detection.aggregation_condition.as_ref();
        }
        None
    }
}

/// Collects every field key referenced by the leaf selection nodes in the rule's detection
/// section. These keys determine which values are extracted up front from each event record.
pub fn get_detection_keys(node: &RuleNode) -> Nested<String> {
    let mut ret = Nested::<String>::new();
    let detection = &node.detection;
    for key in detection.name_to_selection.keys() {
        let selection = &detection.name_to_selection[key];
        let desc = selection.get_descendants();
        desc.iter().for_each(|node| {
            if !node.is::<LeafSelectionNode>() {
                return;
            }

            let node = node.downcast_ref::<LeafSelectionNode>().unwrap();
            let keys = node.get_keys();
            let keys = keys.iter().filter_map(|key| {
                if key.is_empty() {
                    return None;
                }
                Some(key.to_string())
            });
            ret.extend(keys);
        });
    }

    ret
}

/// Node representing the detection of a Rule file.
pub struct DetectionNode {
    /// Compiled selection trees, keyed by their name under the detection node (e.g. "selection").
    pub name_to_selection: HashMap<String, Arc<Box<dyn SelectionNode>>>,
    /// The condition expression compiled into a single selection tree.
    pub condition: Option<Box<dyn SelectionNode>>,
    /// The aggregation part of the condition (after the pipe), e.g. `count() by field > 3`.
    pub aggregation_condition: Option<AggregationParseInfo>,
    /// The parsed `timeframe` value, used when evaluating the aggregation condition.
    pub timeframe: Option<TimeFrameInfo>,
}

impl DetectionNode {
    fn new() -> DetectionNode {
        DetectionNode {
            name_to_selection: HashMap::new(),
            condition: Option::None,
            aggregation_condition: Option::None,
            timeframe: Option::None,
        }
    }

    /// Builds a DetectionNode directly from pre-compiled parts. Used by the correlation parser.
    pub fn new_with_data(
        name_to_selection: HashMap<String, Arc<Box<dyn SelectionNode>>>,
        condition: Option<Box<dyn SelectionNode>>,
        aggregation_condition: Option<AggregationParseInfo>,
        timeframe: Option<TimeFrameInfo>,
    ) -> DetectionNode {
        DetectionNode {
            name_to_selection,
            condition,
            aggregation_condition,
            timeframe,
        }
    }

    fn init(
        &mut self,
        detection_yaml: &Yaml,
        stored_static: &StoredStatic,
    ) -> Result<(), Vec<String>> {
        // Initialize selection nodes.
        self.parse_name_to_selection(detection_yaml)?;

        // Get the value specified in timeframe.
        let timeframe = &detection_yaml["timeframe"].as_str();
        if timeframe.is_some() {
            self.timeframe = Some(TimeFrameInfo::parse_tframe(
                timeframe.unwrap().to_string(),
                stored_static,
            ));
        }

        // Get the expression specified in condition.
        let condition = &detection_yaml["condition"].as_str();
        let condition_str = if let Some(cond_str) = condition {
            *cond_str
        } else {
            // If condition is not specified, use the sole selection as the condition; having two
            // or more selections without a condition is an error.
            let mut keys = self.name_to_selection.keys();
            if keys.len() >= 2 {
                return Result::Err(vec![
                    "There is no condition node under detection.".to_string(),
                ]);
            }

            keys.next().unwrap()
        };

        // Parse condition and convert to SelectionNode.
        let mut err_msgs = vec![];
        let compiler = condition_parser::ConditionCompiler::new();
        let compile_result = compiler.compile_condition(condition_str, &self.name_to_selection);
        if let Result::Err(err_msg) = compile_result {
            err_msgs.extend(vec![err_msg]);
        } else {
            self.condition = Option::Some(compile_result.unwrap());
        }

        // Parse the aggregation condition (the part after the pipe in condition).
        let agg_compiler = aggregation_parser::AggregationConditionCompiler::new();
        let compile_result = agg_compiler.compile(condition_str);
        if let Result::Err(err_msg) = compile_result {
            err_msgs.push(err_msg);
        } else if let Result::Ok(info) = compile_result {
            self.aggregation_condition = info;
        }

        if err_msgs.is_empty() {
            Result::Ok(())
        } else {
            Result::Err(err_msgs)
        }
    }

    pub fn select(
        &self,
        event_record: &EvtxRecordInfo,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> bool {
        if self.condition.is_none() {
            return false;
        }

        let condition = &self.condition.as_ref().unwrap();
        condition.select(event_record, eventkey_alias)
    }

    /// Parses every named selection under the detection node into a selection tree and stores it
    /// in name_to_selection.
    fn parse_name_to_selection(&mut self, detection_yaml: &Yaml) -> Result<(), Vec<String>> {
        let detection_hash = detection_yaml.as_hash();
        if detection_hash.is_none() {
            return Result::Err(vec!["Detection node was not found.".to_string()]);
        }

        // Parse selection.
        let detection_hash = detection_hash.unwrap();
        let keys = detection_hash.keys();
        let mut err_msgs = vec![];
        for key in keys {
            let name = key.as_str().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            // Ignore special keywords such as condition.
            if name == "condition" || name == "timeframe" {
                continue;
            }

            // Parse; if there are error messages, accumulate them in an array and return them.
            let selection_node = self.parse_selection(&detection_hash[key]);
            if let Some(node) = selection_node {
                let mut selection_node = node;
                let init_result = selection_node.init();
                if let Err(err_detail) = init_result {
                    err_msgs.extend(err_detail);
                } else {
                    let rc_selection = Arc::new(selection_node);
                    self.name_to_selection
                        .insert(name.to_string(), rc_selection);
                }
            }
        }
        if !err_msgs.is_empty() {
            return Result::Err(err_msgs);
        }

        // Having no selection node is an error.
        if self.name_to_selection.is_empty() {
            return Result::Err(vec![
                "There is no selection node under detection.".to_string(),
            ]);
        }

        Result::Ok(())
    }

    /// Parses a single named selection into a selection tree.
    fn parse_selection(&self, selection_yaml: &Yaml) -> Option<Box<dyn SelectionNode>> {
        Option::Some(Self::parse_selection_recursively(
            &Nested::<String>::new(),
            selection_yaml,
        ))
    }

    /// Recursively converts a selection's YAML into a tree of SelectionNodes: hashes become AND
    /// nodes, arrays become OR nodes (or AND/All nodes when the `|all` modifier is present), and
    /// scalars become leaf nodes holding the key path (`key_list`) and the value to match.
    fn parse_selection_recursively(
        key_list: &Nested<String>,
        yaml: &Yaml,
    ) -> Box<dyn SelectionNode> {
        if yaml.as_hash().is_some() {
            // Associative arrays are interpreted as AND conditions.
            let yaml_hash = yaml.as_hash().unwrap();
            let mut and_node = selectionnodes::AndSelectionNode::new();

            yaml_hash.keys().for_each(|hash_key| {
                let child_yaml = yaml_hash.get(hash_key).unwrap();
                let mut child_key_list = key_list.clone();
                child_key_list.push(hash_key.as_str().unwrap());
                let child_node = Self::parse_selection_recursively(&child_key_list, child_yaml);
                and_node.child_nodes.push(child_node);
            });
            Box::new(and_node)
        } else if yaml.as_vec().is_some() && key_list.len() == 1 && key_list[0].eq("|all") {
            // If the key is just "|all" (the keyless all modifier), every keyword in the list has
            // to match, so combine the children with an AllSelectionNode (AND semantics).
            let mut all_node = selectionnodes::AllSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                all_node.child_nodes.push(child_node);
            });
            Box::new(all_node)
        } else if yaml.as_vec().is_some() && key_list.iter().any(|k: &str| k.contains("|all")) {
            // If the key carries the |all modifier (e.g. field|contains|all), the array of child
            // elements is interpreted as an AND condition.
            let mut and_node = selectionnodes::AndSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                and_node.child_nodes.push(child_node);
            });
            Box::new(and_node)
        } else if yaml.as_vec().is_some() {
            // Arrays are interpreted as OR conditions.
            let mut or_node = selectionnodes::OrSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                or_node.child_nodes.push(child_node);
            });
            Box::new(or_node)
        } else {
            // Items other than associative arrays and arrays are leaf nodes.
            Box::new(selectionnodes::LeafSelectionNode::new(
                key_list.clone(),
                yaml.to_owned(),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// Struct that outputs the results of aggregation such as count.
pub struct AggResult {
    /// The aggregated value, e.g. the count.
    pub data: i64,
    /// The grouping value taken from the record for the field specified by "count() by".
    pub key: String,
    /// Array of values in detected records for the field specified inside the parentheses of
    /// count. If nothing is specified inside the parentheses, this is an array of length 0.
    pub field_values: Vec<String>,
    /// Time of the first record in the detected block.
    pub start_datetime: DateTime<Utc>,
    /// All times and EventIDs of records in the detected block.
    pub agg_record_time_info: Vec<AggRecordTimeInfo>,
}

impl AggResult {
    pub fn new(
        count_data: i64,
        key_name: String,
        field_value: Vec<String>,
        event_start_timedate: DateTime<Utc>,
        agg_record_time_info: Vec<AggRecordTimeInfo>,
    ) -> AggResult {
        AggResult {
            data: count_data,
            key: key_name,
            field_values: field_value,
            start_datetime: event_start_timedate,
            agg_record_time_info,
        }
    }
}

#[cfg(test)]
mod tests {
    use yaml_rust2::YamlLoader;

    use super::RuleNode;
    use crate::detections::{
        self,
        configs::{Action, Config, CsvOutputOption, OutputOption, STORED_EKEY_ALIAS, StoredStatic},
        rule::create_rule,
        utils,
    };

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    min_level: "informational".to_string(),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            debug: false,
        }))
    }

    pub fn parse_rule_from_str(rule_str: &str) -> RuleNode {
        let rule_yaml = YamlLoader::load_from_str(rule_str);
        assert!(rule_yaml.is_ok());
        let rule_yamls = rule_yaml.unwrap();
        let mut rule_yaml = rule_yamls.into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());
        assert!(rule_node.init(&create_dummy_stored_static()).is_ok());
        rule_node
    }

    fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
        let mut rule_node = parse_rule_from_str(rule_str);
        let dummy_stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());

        match serde_json::from_str(record_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo =
                    utils::create_rec_info(record, "testpath".to_owned(), &keys, &false, &false);
                assert_eq!(
                    rule_node.select(
                        &recinfo,
                        dummy_stored_static.verbose_flag,
                        dummy_stored_static.quiet_errors_flag,
                        dummy_stored_static.json_input_flag,
                        &dummy_stored_static.eventkey_alias
                    ),
                    expect_select
                );
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_dotkey() {
        // Verify that a key written as a dot-joined path (instead of an alias) is detected
        // correctly.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHI
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_dotkey() {
        // Verify that a record which should not be detected is not detected when the key is a
        // dot-joined path instead of an alias.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHIN
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_notdetect_differentkey() {
        // Verify that a record is not detected when the value of the rule's field (here the
        // aliased key Channel) differs from the value in the record.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: NOTDETECT
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_attribute() {
        // Test for cases where JSON is parsed in a special way when a value exists in the
        // attribute part of an XML tag.
        // The original XML looks like the following, and this is a test to detect Name or Guid
        // in the Provider tag.
        /*         - <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        - <System>
          <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
          <EventID>4672</EventID>
          <Version>0</Version>
          <Level>0</Level>
          <Task>12548</Task>
          <Opcode>0</Opcode>
          <Keywords>0x8020000000000000</Keywords>
          <TimeCreated SystemTime="2021-05-12T13:33:08.0144343Z" />
          <EventRecordID>244666</EventRecordID>
          <Correlation ActivityID="{0188dd7a-447d-000c-82dd-88017d44d701}" />
          <Execution ProcessID="1172" ThreadID="22352" />
          <Channel>Security</Channel>
          <Security />
          </System>
        - <EventData>
          <Data Name="SubjectUserName">SYSTEM</Data>
          <Data Name="SubjectDomainName">NT AUTHORITY</Data>
          <Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeSecurityPrivilege SeTakeOwnershipPrivilege SeLoadDriverPrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeAuditPrivilege SeSystemEnvironmentPrivilege SeImpersonatePrivilege SeDelegateSessionUserImpersonatePrivilege</Data>
          </EventData>
          </Event> */

        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4797
                Event.System.Provider_attributes.Guid: 54849625-5478-4994-A5BA-3E3B0328C30D
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {
              "System": {
                "Channel": "Security",
                "Correlation_attributes": {
                  "ActivityID": "0188DD7A-447D-000C-82DD-88017D44D701"
                },
                "EventID": 4797,
                "EventRecordID": 239219,
                "Execution_attributes": {
                  "ProcessID": 1172,
                  "ThreadID": 23236
                },
                "Keywords": "0x8020000000000000",
                "Level": 0,
                "Opcode": 0,
                "Provider_attributes": {
                  "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
                  "Name": "Microsoft-Windows-Security-Auditing"
                },
                "Security": null,
                "Task": 13824,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-05-12T09:39:19.828403Z"
                },
                "Version": 0
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_attribute() {
        // Verify a case where a value in an XML tag attribute should not be detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4797
                Event.System.Provider_attributes.Guid: 54849625-5478-4994-A5BA-3E3B0328C30DSS
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {
              "System": {
                "Channel": "Security",
                "Correlation_attributes": {
                  "ActivityID": "0188DD7A-447D-000C-82DD-88017D44D701"
                },
                "EventID": 4797,
                "EventRecordID": 239219,
                "Execution_attributes": {
                  "ProcessID": 1172,
                  "ThreadID": 23236
                },
                "Keywords": "0x8020000000000000",
                "Level": 0,
                "Opcode": 0,
                "Provider_attributes": {
                  "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
                  "Name": "Microsoft-Windows-Security-Auditing"
                },
                "Security": null,
                "Task": 13824,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-05-12T09:39:19.828403Z"
                },
                "Version": 0
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_eventdata() {
        // In a special XML format pattern, there is a tag called EventData, and the value that
        // acts as the field key comes in the Name= attribute.
        /* - <EventData>
        <Data Name="SubjectUserSid">S-1-5-21-2673273881-979819022-3746999991-1001</Data>
        <Data Name="SubjectUserName">takai</Data>
        <Data Name="SubjectDomainName">DESKTOP-ICHIICH</Data>
        <Data Name="SubjectLogonId">0x312cd</Data>
        <Data Name="Workstation">DESKTOP-ICHIICH</Data>
        <Data Name="TargetUserName">Administrator</Data>
        <Data Name="TargetDomainName">DESKTOP-ICHIICH</Data>
        </EventData> */

        // In that case, the JSON produced by the event parser looks like the following, so test
        // that it can be correctly detected.
        /*         {
            "Event": {
              "EventData": {
                "TargetDomainName": "TEST-DOMAIN",
                "Workstation": "TEST WorkStation"
                "TargetUserName": "ichiichi11",
              },
            }
        } */

        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Event.EventData.Workstation: 'TEST WorkStation'
                Event.EventData.TargetUserName: ichiichi11
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        "#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_eventdata2() {
        // Verify that an EventData field can be matched by its bare name: keys without an alias
        // or dots fall back to Event.EventData.<key>.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                TargetUserName: ichiichi11
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        "#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_eventdata() {
        // Patterns where EventData is not detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                TargetUserName: ichiichi12
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        "#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_special_eventdata() {
        // A further special case of EventData beyond the above test case, where there is no Name
        // key inside the Data tag as shown below.
        // For this reason, only the EventData key receives special handling in the rule file.
        // Currently, this case has only been confirmed with the downgrade_attack.yml rule.
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData|re: '[\s\S]*EngineVersion=2\.0[\s\S]*'
        details: 'command=%CommandLine%'
        ";

        let record_json_str = r#"
        {
            "Event": {
              "EventData": {
                "Binary": null,
                "Data": [
                  "Stopped",
                  "Available",
                  "\tNewEngineState=Stopped\n\tPreviousEngineState=Available\n\n\tSequenceNumber=10\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n\tHostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c\n\tEngineVersion=2.0\n\tRunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine="
                ]
              },
              "System": {
                "Channel": "Windows PowerShell",
                "Computer": "DESKTOP-ST69BPO",
                "EventID": 403,
                "EventID_attributes": {
                  "Qualifiers": 0
                },
                "EventRecordID": 730,
                "Keywords": "0x80000000000000",
                "Level": 4,
                "Provider_attributes": {
                  "Name": "PowerShell"
                },
                "Security": null,
                "Task": 4,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-01-28T10:40:54.946866Z"
                }
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }
        "#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_special_eventdata() {
        // A further special case of EventData beyond the above test case, where there is no Name
        // key inside the Data tag as shown below.
        // For this reason, only the EventData key receives special handling in the rule file.
        // Currently, this case has only been confirmed with the downgrade_attack.yml rule.
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData: '[\s\S]*EngineVersion=3.0[\s\S]*'
        details: 'command=%CommandLine%'
        ";

        let record_json_str = r#"
        {
            "Event": {
              "EventData": {
                "Binary": null,
                "Data": [
                  "Stopped",
                  "Available",
                  "\tNewEngineState=Stopped\n\tPreviousEngineState=Available\n\n\tSequenceNumber=10\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n\tHostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c\n\tEngineVersion=2.0\n\tRunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine="
                ]
              },
              "System": {
                "Channel": "Windows PowerShell",
                "Computer": "DESKTOP-ST69BPO",
                "EventID": 403,
                "EventID_attributes": {
                  "Qualifiers": 0
                },
                "EventRecordID": 730,
                "Keywords": "0x80000000000000",
                "Level": 4,
                "Provider_attributes": {
                  "Name": "PowerShell"
                },
                "Security": null,
                "Task": 4,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-01-28T10:40:54.946866Z"
                }
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }
        "#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_use_strfeature_in_or_node() {
        // Test that startswith can also be used within an OR node (a list of values).
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
                param2|startswith:
                    - "disa"
                    - "aut"
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System"
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_undefined_rule_option() {
        // Test that a warning is issued when an unknown string option is written in a rule.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel|failed: Security
                EventID: 0
        details: 'Rule parse test'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(&create_dummy_stored_static()),
            Err(vec![
                "An unknown pipe element was specified. key:detection -> selection -> Channel|failed"
                    .to_string()
            ])
        );
    }

    #[test]
    fn test_detect_not_defined_selection() {
        // Test that an error is returned when the detection node has no content.
        let rule_str = r#"
        enabled: true
        detection:
        details: 'Rule parse test'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(&create_dummy_stored_static()),
            Err(vec!["Detection node was not found.".to_string()])
        );
    }

    #[test]
    fn test_use_allfeature_() {
        // Test that when the |all modifier is given, the listed values are combined with AND.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
                param2|contains|all:
                    - "star"
                    - "aut"
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System"
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        // A record that should not match: param2 contains "aut" but not "star", so contains|all
        // fails.
        let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System"
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auts"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, true);
        check_select(rule_str, record_json_str2, false);
    }

    /// Test helper that verifies the number of records accumulated for the count aggregation.
    fn _check_count(rule_str: &str, record_str: &str, key: &str, expect_count: i32) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        let _init = rule_node.init(&create_dummy_stored_static());
        let dummy_stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());

        match serde_json::from_str(record_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo =
                    utils::create_rec_info(record, "testpath".to_owned(), &keys, &false, &false);
                let result = rule_node.select(
                    &recinfo,
                    dummy_stored_static.verbose_flag,
                    dummy_stored_static.quiet_errors_flag,
                    dummy_stored_static.json_input_flag,
                    &dummy_stored_static.eventkey_alias,
                );
                assert!(rule_node.detection.aggregation_condition.is_some());
                assert!(result);
                assert_eq!(
                    rule_node.countdata.get(key).unwrap().len() as i32,
                    expect_count
                );
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }
}

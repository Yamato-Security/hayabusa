use crate::detections::{configs::EventKeyAliasConfig, detection::EvtxRecordInfo, utils};
use downcast_rs::Downcast;
use nested::Nested;
use serde_json::Value;
use std::{sync::Arc, vec};
use yaml_rust2::Yaml;

use super::matchers::{self, DefaultMatcher};

/// Trait implemented by every node under the detection-selection section of a rule file.
pub trait SelectionNode: Downcast + Send + Sync {
    /// Determines whether the given event log record matches this node's condition.
    /// Each struct implementing this trait must provide its own matching logic.
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool;

    /// Performs initialization.
    /// Since this method can return errors, report here when the rule file is invalid and a
    /// SelectionNode cannot be constructed. AndSelectionNode and the like also implement a new()
    /// function in addition to init(), but new() is only meant to create an instance and should
    /// not contain lengthy processing. This keeps the error handling for rule file parsing
    /// consolidated in init().
    fn init(&mut self) -> Result<(), Vec<String>>;

    /// Gets the child nodes ("child" in the graph-theory sense).
    fn get_children(&self) -> Vec<&dyn SelectionNode>;

    /// Gets the descendant nodes ("descendant" in the graph-theory sense).
    fn get_descendants(&self) -> Vec<&dyn SelectionNode>;
}
// Enable downcasting so callers (e.g. get_detection_keys() in rule/mod.rs) can identify concrete
// node types such as LeafSelectionNode.
downcast_rs::impl_downcast!(SelectionNode);

/// Node representing an AND condition under detection-selection.
/// Built from a YAML hash (every key/value pair must match), from a value list whose field key
/// carries the `|all` modifier, or for `and` operators in condition expressions; matches only
/// when all child nodes match.
pub struct AndSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

impl AndSelectionNode {
    pub fn new() -> AndSelectionNode {
        AndSelectionNode {
            child_nodes: vec![],
        }
    }
}

impl SelectionNode for AndSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        self.child_nodes
            .iter()
            .all(|child_node| child_node.select(event_record, eventkey_alias))
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let err_msgs = self
            .child_nodes
            .iter_mut()
            .map(|child_node| {
                let res = child_node.init();
                if let Err(err) = res { err } else { vec![] }
            })
            .fold(
                vec![],
                |mut acc: Vec<String>, cur: Vec<String>| -> Vec<String> {
                    acc.extend(cur);
                    acc
                },
            );

        if err_msgs.is_empty() {
            Result::Ok(())
        } else {
            Result::Err(err_msgs)
        }
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_children();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// Node for the keyless `|all` modifier under detection-selection: every keyword in the value
/// list must match. Matching behaves like AndSelectionNode, but it is kept as a distinct type.
pub struct AllSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

impl AllSelectionNode {
    pub fn new() -> AllSelectionNode {
        AllSelectionNode {
            child_nodes: vec![],
        }
    }
}

impl SelectionNode for AllSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        self.child_nodes
            .iter()
            .all(|child_node| child_node.select(event_record, eventkey_alias))
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let err_msgs = self
            .child_nodes
            .iter_mut()
            .map(|child_node| {
                let res = child_node.init();
                if let Err(err) = res { err } else { vec![] }
            })
            .fold(
                vec![],
                |mut acc: Vec<String>, cur: Vec<String>| -> Vec<String> {
                    acc.extend(cur);
                    acc
                },
            );

        if err_msgs.is_empty() {
            Result::Ok(())
        } else {
            Result::Err(err_msgs)
        }
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_children();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// Node representing an OR condition under detection-selection.
/// Built from a YAML array of values, for `or` operators in condition expressions, or when the
/// correlation parser merges referenced rules; matches when any child node matches.
pub struct OrSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

impl OrSelectionNode {
    pub fn new() -> OrSelectionNode {
        OrSelectionNode {
            child_nodes: vec![],
        }
    }
}

impl SelectionNode for OrSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        self.child_nodes
            .iter()
            .any(|child_node| child_node.select(event_record, eventkey_alias))
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let err_msgs = self
            .child_nodes
            .iter_mut()
            .map(|child_node| {
                let res = child_node.init();
                if let Err(err) = res { err } else { vec![] }
            })
            .fold(
                vec![],
                |mut acc: Vec<String>, cur: Vec<String>| -> Vec<String> {
                    acc.extend(cur);
                    acc
                },
            );

        if err_msgs.is_empty() {
            Result::Ok(())
        } else {
            Result::Err(err_msgs)
        }
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_children();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// Node representing a `not` in the condition expression; inverts the result of the wrapped node.
pub struct NotSelectionNode {
    node: Box<dyn SelectionNode>,
}

impl NotSelectionNode {
    pub fn new(select_node: Box<dyn SelectionNode>) -> NotSelectionNode {
        NotSelectionNode { node: select_node }
    }
}

impl SelectionNode for NotSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        !self.node.select(event_record, eventkey_alias)
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        // Nothing to initialize: this node is created when the condition expression is compiled,
        // which happens after all named selections have already been initialized.
        Result::Ok(())
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        self.get_children()
    }
}

/// Used to reference a named selection defined under detection from the condition expression.
pub struct RefSelectionNode {
    // selection_node is owned by DetectionNode's name_to_selection map, so RefSelectionNode cannot
    // take ownership of it. Arc is used so that ownership is shared between name_to_selection and
    // this field. Arc is used instead of Rc for multi-thread support.
    selection_node: Arc<Box<dyn SelectionNode>>,
}

impl RefSelectionNode {
    pub fn new(select_node: Arc<Box<dyn SelectionNode>>) -> RefSelectionNode {
        RefSelectionNode {
            selection_node: select_node,
        }
    }
}

impl SelectionNode for RefSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        self.selection_node.select(event_record, eventkey_alias)
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        // Nothing to initialize: the referenced selection is initialized by DetectionNode before
        // the condition expression is compiled.
        Result::Ok(())
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        vec![self.selection_node.as_ref().as_ref()]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        self.get_children()
    }
}

/// Leaf node under detection-selection: a single field/value pair.
/// key_list holds the chain of YAML keys leading to the value (e.g. `["CommandLine|contains"]` or
/// `["field", "min_length"]`), key holds the field name with any pipe modifiers stripped, and the
/// actual comparison is delegated to the LeafMatcher chosen during init().
pub struct LeafSelectionNode {
    key: String,
    key_list: Nested<String>,
    select_value: Yaml,
    pub matcher: Option<Box<dyn matchers::LeafMatcher>>,
}

impl LeafSelectionNode {
    pub fn new(keys: Nested<String>, value_yaml: Yaml) -> LeafSelectionNode {
        LeafSelectionNode {
            key: String::default(),
            key_list: keys,
            select_value: value_yaml,
            matcher: Option::None,
        }
    }

    pub fn get_key(&self) -> &String {
        &self.key
    }

    /// Returns the event keys this leaf refers to: the leaf's own field key plus, for field
    /// comparison modifiers such as `equalsfield`/`fieldref`, the key of the field being compared
    /// against. Used to decide which values to extract from each record up front.
    pub fn get_keys(&self) -> Vec<&String> {
        let mut keys = vec![];
        if !self.key.is_empty() {
            keys.push(&self.key);
        }

        if let Some(matcher) = &self.matcher {
            let matcher = matcher.downcast_ref::<DefaultMatcher>();
            if let Some(matcher) = matcher
                && let Some(eq_key) = matcher.get_eqfield_key()
            {
                keys.push(eq_key);
            }
        }

        keys
    }

    /// Derives the field name from key_list: the first element with any pipe modifiers
    /// (e.g. "|contains") stripped off.
    fn _create_key(&self) -> String {
        if self.key_list.is_empty() {
            return String::default();
        }

        let first_key = &self.key_list[0];
        first_key.split('|').next().unwrap_or_default().to_string()
    }

    /// Gets the value for this leaf's key from the event record JSON.
    /// Event key aliases are also taken into account.
    fn get_event_value<'a>(&self, record: &'a EvtxRecordInfo) -> Option<&'a String> {
        // If no key is specified (a keyword-style rule), match against the whole record string.
        if self.key_list.is_empty() {
            return Option::Some(&record.data_string);
        }

        record.get_value(self.get_key())
    }

    /// Gets the list of candidate matchers::LeafMatcher implementations.
    /// They are examined in order from the top, and the first matcher whose is_target_key()
    /// returns true is applied, so the most permissive matcher (DefaultMatcher) must stay last.
    fn get_matchers(&self) -> Vec<Box<dyn matchers::LeafMatcher>> {
        vec![
            Box::new(matchers::MinlengthMatcher::new()),
            Box::new(matchers::RegexesFileMatcher::new()),
            Box::new(matchers::AllowlistFileMatcher::new()),
            Box::new(matchers::DefaultMatcher::new()),
        ]
    }
}

impl SelectionNode for LeafSelectionNode {
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool {
        // The matcher is set in init(); if init() failed, this node never matches.
        if self.matcher.is_none() {
            return false;
        }

        // EventData requires special handling because its XML has a special format.
        // The original XML looks like this:
        /*
            <EventData>
            <Data>Available</Data>
            <Data>None</Data>
            <Data>NewEngineState=Available PreviousEngineState=None SequenceNumber=9 HostName=ConsoleHost HostVersion=2.0 HostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c EngineVersion=2.0 RunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1 PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=</Data>
            </EventData>
        */
        // When the XML is parsed into JSON, it takes the following format.
        // Rules that target the case where the JSON becomes an array like this cannot currently
        // be written.
        /*     "EventData": {
                    "Binary": null,
                    "Data": [
                        "",
                        "\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=15\r\n\r\n\tUserId=DESKTOP-ST69BPO\\user01\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=64821494-0737-4ce9-ad67-3ac0e50a81b8\r\n\tHostApplication=powershell calc\r\n\tEngineVersion=5.1.18362.145\r\n\tRunspaceId=74ae21ca-7fa9-40cc-a265-7a41fdb168a6\r\n\tPipelineId=1\r\n\tScriptName=\r\n\tCommandLine=",
                        "CommandInvocation(Out-Default): \"Out-Default\"\r\n"
                    ]
                }
        */
        if self.get_key() == "EventData" || self.get_key() == "Data" {
            let values = utils::get_event_value(
                "Event.EventData.Data",
                &event_record.record,
                eventkey_alias,
            );
            if values.is_none() {
                return self
                    .matcher
                    .as_ref()
                    .unwrap()
                    .is_match(Option::None, event_record);
            }

            let event_data_value = values.unwrap();
            match event_data_value {
                // For strings or numbers (not arrays), compare normally.
                Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                    let event_value = event_record.get_value(self.get_key());
                    return self
                        .matcher
                        .as_ref()
                        .unwrap()
                        .is_match(event_value, event_record);
                }
                // For arrays, the leaf matches if any element matches.
                Value::Array(_) => {
                    return event_data_value
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|array_element| {
                            let event_value = utils::value_to_string(array_element);
                            self.matcher
                                .as_ref()
                                .unwrap()
                                .is_match(event_value.as_ref(), event_record)
                        });
                }
                _ => {
                    return self
                        .matcher
                        .as_ref()
                        .unwrap()
                        .is_match(Option::None, event_record);
                }
            }
        }

        let mut event_value = self.get_event_value(event_record);
        if self.get_key() == "EventID"
            && !self.select_value.is_null()
            && !self.key_list.is_empty()
            && !self.key_list[0].contains("|")
            && let Some(event_id) = self.select_value.as_i64()
        {
            // Regex matching is heavy, so when the rule specifies EventID as a plain integer
            // (no pipe modifiers), use exact string comparison instead.
            return event_value.unwrap_or(&String::default()) == &event_id.to_string();
        }
        // For the keyless `|all` modifier, match against the entire record JSON string.
        if !self.key_list.is_empty() && self.key_list[0].eq("|all") {
            event_value = Some(&event_record.data_string);
        }
        self.matcher
            .as_ref()
            .unwrap()
            .is_match(event_value, event_record)
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let matchers = self.get_matchers();
        self.matcher = matchers
            .into_iter()
            .find(|matcher| matcher.is_target_key(&self.key_list));

        // Error: no matcher accepted this key.
        if self.matcher.is_none() {
            return Result::Err(vec![format!(
                "Found unknown key. key:{}",
                utils::concat_selection_key(&self.key_list)
            )]);
        }

        // Error: the YAML value could not be parsed.
        if self.select_value.is_badvalue() {
            return Result::Err(vec![format!(
                "Cannot parse yml file. key:{}",
                utils::concat_selection_key(&self.key_list)
            )]);
        }

        self.key = self._create_key();
        self.matcher
            .as_mut()
            .unwrap()
            .init(&self.key_list, &self.select_value)
    }

    fn get_children(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::{
        self,
        configs::{Action, Config, CsvOutputOption, OutputOption, STORED_EKEY_ALIAS, StoredStatic},
        rule::tests::parse_rule_from_str,
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
            ..Default::default()
        }))
    }

    // Parses the rule, wraps the JSON record, and asserts that rule_node.select() returns
    // expect_select.
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
    fn test_detect_multiple_regex_and() {
        // Verify that AND conditions are correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_multiple_regex_and() {
        // Verify that if even one condition in an AND condition does not match, it is not detected.
        // In this example, the Computer value is different.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4103
                Computer: DESKTOP-ICHIICHIN
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
    fn test_detect_or() {
        // Verify that OR conditions are correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
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
    fn test_detect_or2() {
        // Verify that OR conditions are correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_notdetect_or() {
        // Verify that an OR condition does not match when none of the listed values match.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "not detect", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_event_id_wildcard() {
        // Verify that EventID wildcard matching is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 41*3
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_event_id_question() {
        // Verify that EventID single-character "?" matching is correctly detected.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 41?3
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }
}

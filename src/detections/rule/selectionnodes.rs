use crate::detections::{configs::EventKeyAliasConfig, detection::EvtxRecordInfo, utils};
use downcast_rs::Downcast;
use nested::Nested;
use serde_json::Value;
use std::{sync::Arc, vec};
use yaml_rust2::Yaml;

use super::matchers::{self, DefaultMatcher};

// Ruleファイルの detection- selection配下のノードはこのtraitを実装する。
pub trait SelectionNode: Downcast + Send + Sync {
    // 引数で指定されるイベントログのレコードが、条件に一致するかどうかを判定する
    // このトレイトを実装する構造体毎に適切な判定処理を書く必要がある。
    fn select(&self, event_record: &EvtxRecordInfo, eventkey_alias: &EventKeyAliasConfig) -> bool;

    // 初期化処理を行う
    // 戻り値としてエラーを返却できるようになっているので、Ruleファイルが間違っていて、SelectionNodeを構成出来ない時はここでエラーを出す
    // AndSelectionNode等ではinit()関数とは別にnew()関数を実装しているが、new()関数はただインスタンスを作るだけにして、あまり長い処理を書かないようにしている。
    // これはRuleファイルのパースのエラー処理をinit()関数にまとめるためにこうしている。
    fn init(&mut self) -> Result<(), Vec<String>>;

    // 子ノードを取得する(グラフ理論のchildと同じ意味)
    fn get_childs(&self) -> Vec<&dyn SelectionNode>;

    // 子孫ノードを取得する(グラフ理論のdescendantと同じ意味)
    fn get_descendants(&self) -> Vec<&dyn SelectionNode>;
}
downcast_rs::impl_downcast!(SelectionNode);

/// detection - selection配下でAND条件を表すノード
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
                if let Err(err) = res {
                    err
                } else {
                    vec![]
                }
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

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_childs();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// detection - selection配下でAll条件を表すノード
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
                if let Err(err) = res {
                    err
                } else {
                    vec![]
                }
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

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_childs();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// detection - selection配下でOr条件を表すノード
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
                if let Err(err) = res {
                    err
                } else {
                    vec![]
                }
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

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node.as_ref());
        });

        ret
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        let mut ret = self.get_childs();

        self.child_nodes
            .iter()
            .flat_map(|child_node| child_node.get_descendants())
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        ret
    }
}

/// conditionでNotを表すノード
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
        Result::Ok(())
    }

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        self.get_childs()
    }
}

/// detectionで定義した条件をconditionで参照するためのもの
pub struct RefSelectionNode {
    // selection_nodeはDetectionNodeのname_2_nodeが所有権を持っていて、RefSelectionNodeのselection_nodeに所有権を持たせることができない。
    // そこでArcを使って、DetectionNodeのname_2_nodeとRefSelectionNodeのselection_nodeで所有権を共有する。
    // RcじゃなくてArcなのはマルチスレッド対応のため
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
        Result::Ok(())
    }

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        vec![self.selection_node.as_ref().as_ref()]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        self.get_childs()
    }
}

/// detection - selection配下の末端ノード
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

    pub fn get_keys(&self) -> Vec<&String> {
        let mut keys = vec![];
        if !self.key.is_empty() {
            keys.push(&self.key);
        }

        if let Some(matcher) = &self.matcher {
            let matcher = matcher.downcast_ref::<DefaultMatcher>();
            if let Some(matcher) = matcher {
                if let Some(eq_key) = matcher.get_eqfield_key() {
                    keys.push(eq_key);
                }
            }
        }

        keys
    }

    fn _create_key(&self) -> String {
        if self.key_list.is_empty() {
            return String::default();
        }

        let topkey = &self.key_list[0];
        topkey.split('|').next().unwrap_or_default().to_string()
    }

    /// JSON形式のEventJSONから値を取得する関数 aliasも考慮されている。
    fn get_event_value<'a>(&self, record: &'a EvtxRecordInfo) -> Option<&'a String> {
        // keyが指定されていない場合はそのままのレコードのデータを取得する
        if self.key_list.is_empty() {
            return Option::Some(&record.data_string);
        }

        record.get_value(self.get_key())
    }

    /// matchers::LeafMatcherの一覧を取得する。
    /// 上から順番に調べて、一番始めに一致したMatcherが適用される
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
        if self.matcher.is_none() {
            return false;
        }

        // EventDataはXMLが特殊な形式になっているので特別対応。
        //// 元のXMLは下記のような形式
        /*
            <EventData>
            <Data>Available</Data>
            <Data>None</Data>
            <Data>NewEngineState=Available PreviousEngineState=None SequenceNumber=9 HostName=ConsoleHost HostVersion=2.0 HostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c EngineVersion=2.0 RunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1 PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=</Data>
            </EventData>
        */
        //// XMLをJSONにパースすると、下記のような形式になっていた。
        //// JSONが配列になってしまうようなルールは現状では書けない。
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

            // 配列じゃなくて、文字列や数値等の場合は普通通りに比較する。
            let eventdata_data = values.unwrap();
            match eventdata_data {
                Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                    let event_value = event_record.get_value(self.get_key());
                    return self
                        .matcher
                        .as_ref()
                        .unwrap()
                        .is_match(event_value, event_record);
                }
                Value::Array(_) => {
                    return eventdata_data
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|ary_element| {
                            let event_value = utils::value_to_string(ary_element);
                            return self
                                .matcher
                                .as_ref()
                                .unwrap()
                                .is_match(event_value.as_ref(), event_record);
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
        {
            if let Some(event_id) = self.select_value.as_i64() {
                // 正規表現は重いので、数値のEventIDのみ文字列完全一致で判定
                return event_value.unwrap_or(&String::default()) == &event_id.to_string();
            }
        }
        if !self.key_list.is_empty() && self.key_list[0].eq("|all") {
            event_value = Some(&event_record.data_string);
        }
        return self
            .matcher
            .as_ref()
            .unwrap()
            .is_match(event_value, event_record);
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let matchers = self.get_matchers();
        self.matcher = matchers
            .into_iter()
            .find(|matcher| matcher.is_target_key(&self.key_list));

        // 一致するmatcherが見つからないエラー
        if self.matcher.is_none() {
            return Result::Err(vec![format!(
                "Found unknown key. key:{}",
                utils::concat_selection_key(&self.key_list)
            )]);
        }

        if self.select_value.is_badvalue() {
            return Result::Err(vec![format!(
                "Cannot parse yml file. key:{}",
                utils::concat_selection_key(&self.key_list)
            )]);
        }

        self.key = self._create_key();
        return self
            .matcher
            .as_mut()
            .unwrap()
            .init(&self.key_list, &self.select_value);
    }

    fn get_childs(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }

    fn get_descendants(&self) -> Vec<&dyn SelectionNode> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::detections::configs::TimeFormatOptions;
    use crate::detections::{
        self,
        configs::{
            Action, CommonOptions, Config, CsvOutputOption, DetectCommonOption, InputOption,
            OutputOption, StoredStatic, STORED_EKEY_ALIAS,
        },
        rule::tests::parse_rule_from_str,
        utils,
    };

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        time_offset: None,
                    },
                    profile: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    exact_level: None,
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    time_format_options: TimeFormatOptions {
                        european_time: false,
                        iso_8601: false,
                        rfc_2822: false,
                        rfc_3339: false,
                        us_military_time: false,
                        us_time: false,
                        utc: false,
                    },
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                    common_options: CommonOptions {
                        no_color: false,
                        quiet: false,
                        help: None,
                    },
                    detect_common_options: DetectCommonOption {
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                        json_input: false,
                        include_computer: None,
                        exclude_computer: None,
                    },
                    enable_unsupported_rules: false,
                    clobber: false,
                    proven_rules: false,
                    include_tag: None,
                    exclude_tag: None,
                    include_category: None,
                    exclude_category: None,
                    include_eid: None,
                    exclude_eid: None,
                    no_field: false,
                    no_pwsh_field_extraction: false,
                    remove_duplicate_data: false,
                    remove_duplicate_detections: false,
                    no_wizard: true,
                    include_status: None,
                    sort_events: false,
                    enable_all_rules: false,
                    scan_all_evtx_files: false,
                },
                geo_ip: None,
                output: None,
                multiline: false,
            })),
            debug: false,
        }))
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
    fn test_detect_mutiple_regex_and() {
        // AND条件が正しく検知することを確認する。
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
    fn test_notdetect_mutiple_regex_and() {
        // AND条件で一つでも条件に一致しないと、検知しないことを確認
        // この例ではComputerの値が異なっている。
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
        // OR条件が正しく検知できることを確認
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
        // OR条件が正しく検知できることを確認
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
        // OR条件が正しく検知できることを確認
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
        // EventIDのワイルドカードマッチが正しく検知することを確認する。
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
        // EventIDのクエスチョン?1文字マッチが正しく検知することを確認する。
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

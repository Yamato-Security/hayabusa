extern crate regex;

use std::{fmt::Debug, sync::Arc, vec};

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use nested::Nested;
use yaml_rust::Yaml;

use super::configs::{EventKeyAliasConfig, StoredStatic};
use super::detection::EvtxRecordInfo;

use self::aggregation_parser::AggregationParseInfo;
use self::count::{AggRecordTimeInfo, TimeFrameInfo};
use self::selectionnodes::{LeafSelectionNode, SelectionNode};

mod aggregation_parser;
mod condition_parser;
pub mod correlation_parser;
mod count;
mod matchers;
mod selectionnodes;

pub fn create_rule(rulepath: String, yaml: Yaml) -> RuleNode {
    RuleNode::new(rulepath, yaml)
}

/// Ruleファイルを表すノ
/// ード
pub struct RuleNode {
    pub rulepath: String,
    pub yaml: Yaml,
    detection: DetectionNode,
    countdata: HashMap<String, Vec<AggRecordTimeInfo>>,
}

impl Debug for RuleNode {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Result::Ok(())
    }
}

impl RuleNode {
    pub fn new(rule_path: String, yaml_data: Yaml) -> RuleNode {
        RuleNode {
            rulepath: rule_path,
            yaml: yaml_data,
            detection: DetectionNode::new(),
            countdata: HashMap::new(),
        }
    }

    fn new_with_detection(
        rule_path: String,
        yaml_data: Yaml,
        detection: DetectionNode,
    ) -> RuleNode {
        RuleNode {
            rulepath: rule_path,
            yaml: yaml_data,
            detection,
            countdata: HashMap::new(),
        }
    }

    pub fn init(&mut self, stored_static: &StoredStatic) -> Result<(), Vec<String>> {
        let mut errmsgs: Vec<String> = vec![];
        if !&self.yaml["correlation"].is_badvalue() {
            return Result::Ok(());
        }

        // detection node initialization
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
                &event_record.record,
                verbose_flag,
                quiet_errors_flag,
                json_input_flag,
            );
        }
        result
    }
    /// aggregation conditionが存在するかを返す関数
    pub fn has_agg_condition(&self) -> bool {
        self.detection.aggregation_condition.is_some()
    }
    /// Aggregation Conditionの結果を配列で返却する関数
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
    pub fn check_exist_countdata(&self) -> bool {
        !self.countdata.is_empty()
    }
    /// ルール内のAggregationParseInfo(Aggregation Condition)を取得する関数
    pub fn get_agg_condition(&self) -> Option<&AggregationParseInfo> {
        if self.detection.aggregation_condition.as_ref().is_some() {
            return self.detection.aggregation_condition.as_ref();
        }
        None
    }
}

// RuleNodeのdetectionに定義されているキーの一覧を取得する。
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

/// Ruleファイルのdetectionを表すノード
struct DetectionNode {
    pub name_to_selection: HashMap<String, Arc<Box<dyn SelectionNode>>>,
    pub condition: Option<Box<dyn SelectionNode>>,
    pub aggregation_condition: Option<AggregationParseInfo>,
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

    pub fn new_with_data(
        condition: Option<Box<dyn SelectionNode>>,
        aggregation_condition: Option<AggregationParseInfo>,
        timeframe: Option<TimeFrameInfo>,
    ) -> DetectionNode {
        DetectionNode {
            name_to_selection: HashMap::new(),
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
        // selection nodeの初期化
        self.parse_name_to_selection(detection_yaml)?;

        //timeframeに指定されている値を取得
        let timeframe = &detection_yaml["timeframe"].as_str();
        if timeframe.is_some() {
            self.timeframe = Some(TimeFrameInfo::parse_tframe(
                timeframe.unwrap().to_string(),
                stored_static,
            ));
        }

        // conditionに指定されている式を取得
        let condition = &detection_yaml["condition"].as_str();
        let condition_str = if let Some(cond_str) = condition {
            *cond_str
        } else {
            // conditionが指定されていない場合、selectionが一つだけならそのselectionを採用することにする。
            let mut keys = self.name_to_selection.keys();
            if keys.len() >= 2 {
                return Result::Err(vec![
                    "There is no condition node under detection.".to_string()
                ]);
            }

            keys.next().unwrap()
        };

        // conditionをパースして、SelectionNodeに変換する
        let mut err_msgs = vec![];
        let compiler = condition_parser::ConditionCompiler::new();
        let compile_result = compiler.compile_condition(condition_str, &self.name_to_selection);
        if let Result::Err(err_msg) = compile_result {
            err_msgs.extend(vec![err_msg]);
        } else {
            self.condition = Option::Some(compile_result.unwrap());
        }

        // aggregation condition(conditionのパイプ以降の部分)をパース
        let agg_compiler = aggregation_parser::AggegationConditionCompiler::new();
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

    /// selectionノードをパースします。
    fn parse_name_to_selection(&mut self, detection_yaml: &Yaml) -> Result<(), Vec<String>> {
        let detection_hash = detection_yaml.as_hash();
        if detection_hash.is_none() {
            return Result::Err(vec!["Detection node was not found.".to_string()]);
        }

        // selectionをパースする。
        let detection_hash = detection_hash.unwrap();
        let keys = detection_hash.keys();
        let mut err_msgs = vec![];
        for key in keys {
            let name = key.as_str().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            // condition等、特殊なキーワードを無視する。
            if name == "condition" || name == "timeframe" {
                continue;
            }

            // パースして、エラーメッセージがあれば配列にためて、戻り値で返す。
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

        // selectionノードが無いのはエラー
        if self.name_to_selection.is_empty() {
            return Result::Err(vec![
                "There is no selection node under detection.".to_string()
            ]);
        }

        Result::Ok(())
    }

    /// selectionをパースします。
    fn parse_selection(&self, selection_yaml: &Yaml) -> Option<Box<dyn SelectionNode>> {
        Option::Some(Self::parse_selection_recursively(
            &Nested::<String>::new(),
            selection_yaml,
        ))
    }

    /// selectionをパースします。
    fn parse_selection_recursively(
        key_list: &Nested<String>,
        yaml: &Yaml,
    ) -> Box<dyn SelectionNode> {
        if yaml.as_hash().is_some() {
            // 連想配列はAND条件と解釈する
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
            // |all だけの場合、
            let mut or_node = selectionnodes::AllSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                or_node.child_nodes.push(child_node);
            });
            Box::new(or_node)
        } else if yaml.as_vec().is_some() && key_list.iter().any(|k: &str| k.contains("|all")) {
            //key_listにallが入っていた場合は子要素の配列はAND条件と解釈する。
            let mut and_node = selectionnodes::AndSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                and_node.child_nodes.push(child_node);
            });
            Box::new(and_node)
        } else if yaml.as_vec().is_some() {
            // 配列はOR条件と解釈する。
            let mut or_node = selectionnodes::OrSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = Self::parse_selection_recursively(key_list, child_yaml);
                or_node.child_nodes.push(child_node);
            });
            Box::new(or_node)
        } else {
            // 連想配列と配列以外は末端ノード
            Box::new(selectionnodes::LeafSelectionNode::new(
                key_list.clone(),
                yaml.to_owned(),
            ))
        }
    }
}

#[derive(Debug)]
/// countなどのaggregationの結果を出力する構造体
pub struct AggResult {
    /// countなどの値
    pub data: i64,
    /// count byで指定された条件のレコード内での値
    pub key: String,
    /// countの括弧内指定された項目の検知されたレコード内での値の配列。括弧内で指定がなかった場合は長さ0の配列となる
    pub field_values: Vec<String>,
    ///検知したブロックの最初のレコードの時間
    pub start_timedate: DateTime<Utc>,
    ///条件式の情報
    pub condition_op_num: String,
}

impl AggResult {
    pub fn new(
        count_data: i64,
        key_name: String,
        field_value: Vec<String>,
        event_start_timedate: DateTime<Utc>,
        condition_op_number: String,
    ) -> AggResult {
        AggResult {
            data: count_data,
            key: key_name,
            field_values: field_value,
            start_timedate: event_start_timedate,
            condition_op_num: condition_op_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use yaml_rust::YamlLoader;

    use crate::detections::{
        self,
        configs::{
            Action, CommonOptions, Config, CsvOutputOption, DetectCommonOption, InputOption,
            OutputOption, StoredStatic, STORED_EKEY_ALIAS,
        },
        rule::create_rule,
        utils,
    };

    use super::RuleNode;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        timeline_offset: None,
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
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Some(Path::new("./rules").to_path_buf()),
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
                    low_memory_mode: false,
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
        // aliasじゃなくて、.区切りでつなげるケースが正しく検知できる。
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
        // aliasじゃなくて、.区切りでつなげるケースで、検知しないはずのケースで検知しないことを確かめる。
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
        // aliasじゃなくて、.区切りでつなげるケースで、検知しないはずのケースで検知しないことを確かめる。
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
        // XMLのタグのattributionの部分に値がある場合、JSONが特殊な感じでパースされるのでそのテスト
        // 元のXMLは下記のような感じで、Providerタグの部分のNameとかGuidを検知するテスト
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
        // XMLのタグのattributionの検知しないケースを確認
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
        // XML形式の特殊なパターンでEventDataというタグあって、Name=の部分にキー的なものが来る。
        /* - <EventData>
        <Data Name="SubjectUserSid">S-1-5-21-2673273881-979819022-3746999991-1001</Data>
        <Data Name="SubjectUserName">takai</Data>
        <Data Name="SubjectDomainName">DESKTOP-ICHIICH</Data>
        <Data Name="SubjectLogonId">0x312cd</Data>
        <Data Name="Workstation">DESKTOP-ICHIICH</Data>
        <Data Name="TargetUserName">Administrator</Data>
        <Data Name="TargetDomainName">DESKTOP-ICHIICH</Data>
        </EventData> */

        // その場合、イベントパーサーのJSONは下記のような感じになるので、それで正しく検知出来ることをテスト。
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
        // EventDataの検知しないパターン
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
        // 上記テストケースのEventDataの更に特殊ケースで下記のようにDataタグの中にNameキーがないケースがある。
        // そのためにruleファイルでEventDataというキーだけ特別対応している。
        // 現状、downgrade_attack.ymlというルールの場合だけで確認出来ているケース
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
        // 上記テストケースのEventDataの更に特殊ケースで下記のようにDataタグの中にNameキーがないケースがある。
        // そのためにruleファイルでEventDataというキーだけ特別対応している。
        // 現状、downgrade_attack.ymlというルールの場合だけで確認出来ているケース
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
        // orNodeの中でもstartswithが使えるかのテスト
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
        // 不明な文字列オプションがルールに書かれていたら警告するテスト
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
        // 不明な文字列オプションがルールに書かれていたら警告するテスト
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
        // allがパイプで入っていた場合は以下の配下の者をAnd条件で扱うようにすできるかのテスト
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

        // case of
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

    /// countで対象の数値確認を行うためのテスト用関数
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

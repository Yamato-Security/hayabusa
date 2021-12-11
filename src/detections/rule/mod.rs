extern crate regex;
use crate::detections::print::Message;

use chrono::{DateTime, Utc};

use std::{collections::HashMap, fmt::Debug, sync::Arc, vec};

use yaml_rust::Yaml;

mod matchers;
mod selectionnodes;
use self::selectionnodes::SelectionNode;
mod aggregation_parser;
use self::aggregation_parser::AggregationParseInfo;

mod condition_parser;
mod count;
use self::count::TimeFrameInfo;

use super::detection::EvtxRecordInfo;

pub fn create_rule(rulepath: String, yaml: Yaml) -> RuleNode {
    return RuleNode::new(rulepath, yaml);
}

/// Ruleファイルを表すノード
pub struct RuleNode {
    pub rulepath: String,
    pub yaml: Yaml,
    detection: Option<DetectionNode>,
    countdata: HashMap<String, HashMap<String, Vec<DateTime<Utc>>>>,
}

impl Debug for RuleNode {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return Result::Ok(());
    }
}

unsafe impl Sync for RuleNode {}

impl RuleNode {
    pub fn new(rulepath: String, yaml: Yaml) -> RuleNode {
        return RuleNode {
            rulepath: rulepath,
            yaml: yaml,
            detection: Option::None,
            countdata: HashMap::new(),
        };
    }

    pub fn init(&mut self) -> Result<(), Vec<String>> {
        let mut errmsgs: Vec<String> = vec![];

        // SIGMAルールを受け入れるため、outputがなくてもOKにする。
        // if self.yaml["output"].as_str().unwrap_or("").is_empty() {
        //     errmsgs.push("Cannot find required key. key:output".to_string());
        // }

        // detection node initialization
        let mut detection = DetectionNode::new();
        let detection_result = detection.init(&self.yaml["detection"]);
        if detection_result.is_err() {
            errmsgs.extend(detection_result.unwrap_err());
        }
        self.detection = Option::Some(detection);

        if errmsgs.is_empty() {
            return Result::Ok(());
        } else {
            return Result::Err(errmsgs);
        }
    }

    pub fn select(&mut self, filepath: &String, event_record: &EvtxRecordInfo) -> bool {
        if self.detection.is_none() {
            return false;
        }
        let result = self.detection.as_ref().unwrap().select(event_record);
        if result {
            count::count(self, filepath, &event_record.record);
        }
        return result;
    }
    /// aggregation conditionが存在するかを返す関数
    pub fn has_agg_condition(&self) -> bool {
        return self
            .detection
            .as_ref()
            .unwrap()
            .aggregation_condition
            .is_some();
    }
    /// Aggregation Conditionの結果を配列で返却する関数
    pub fn judge_satisfy_aggcondition(&self) -> Vec<AggResult> {
        let mut ret = Vec::new();
        if !self.has_agg_condition() {
            return ret;
        }
        for filepath in self.countdata.keys() {
            ret.append(&mut count::aggregation_condition_select(&self, &filepath));
        }
        return ret;
    }
    pub fn check_exist_countdata(&self) -> bool {
        self.countdata.len() > 0
    }
}

/// Ruleファイルのdetectionを表すノード
struct DetectionNode {
    pub name_to_selection: HashMap<String, Arc<Box<dyn SelectionNode + Send + Sync>>>,
    pub condition: Option<Box<dyn SelectionNode + Send + Sync>>,
    pub aggregation_condition: Option<AggregationParseInfo>,
    pub timeframe: Option<TimeFrameInfo>,
}

impl DetectionNode {
    fn new() -> DetectionNode {
        return DetectionNode {
            name_to_selection: HashMap::new(),
            condition: Option::None,
            aggregation_condition: Option::None,
            timeframe: Option::None,
        };
    }

    fn init(&mut self, detection_yaml: &Yaml) -> Result<(), Vec<String>> {
        // selection nodeの初期化
        self.parse_name_to_selection(detection_yaml)?;

        //timeframeに指定されている値を取得
        let timeframe = &detection_yaml["timeframe"].as_str();
        if timeframe.is_some() {
            self.timeframe = Some(TimeFrameInfo::parse_tframe(timeframe.unwrap().to_string()));
        }

        // conditionに指定されている式を取得
        let condition = &detection_yaml["condition"].as_str();
        let condition_str = if let Some(cond_str) = condition {
            cond_str.to_string()
        } else {
            // conditionが指定されていない場合、selectionが一つだけならそのselectionを採用することにする。
            let mut keys = self.name_to_selection.keys().clone();
            if keys.len() >= 2 {
                return Result::Err(vec![
                    "There is no condition node under detection.".to_string()
                ]);
            }

            keys.nth(0).unwrap().to_string()
        };

        // conditionをパースして、SelectionNodeに変換する
        let mut err_msgs = vec![];
        let compiler = condition_parser::ConditionCompiler::new();
        let compile_result =
            compiler.compile_condition(condition_str.clone(), &self.name_to_selection);
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
            return Result::Ok(());
        } else {
            return Result::Err(err_msgs);
        }
    }

    pub fn select(&self, event_record: &EvtxRecordInfo) -> bool {
        if self.condition.is_none() {
            return false;
        }

        let condition = &self.condition.as_ref().unwrap();
        return condition.select(event_record);
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
            if name.len() == 0 {
                continue;
            }
            // condition等、特殊なキーワードを無視する。
            if name == "condition" || name == "timeframe" {
                continue;
            }

            // パースして、エラーメッセージがあれば配列にためて、戻り値で返す。
            let selection_node = self.parse_selection(&detection_hash[key]);
            if selection_node.is_some() {
                let mut selection_node = selection_node.unwrap();
                let init_result = selection_node.init();
                if init_result.is_err() {
                    err_msgs.extend(init_result.unwrap_err());
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
        if self.name_to_selection.len() == 0 {
            return Result::Err(vec![
                "There is no selection node under detection.".to_string()
            ]);
        }

        return Result::Ok(());
    }

    /// selectionをパースします。
    fn parse_selection(
        &self,
        selection_yaml: &Yaml,
    ) -> Option<Box<dyn SelectionNode + Send + Sync>> {
        return Option::Some(self.parse_selection_recursively(vec![], selection_yaml));
    }

    /// selectionをパースします。
    fn parse_selection_recursively(
        &self,
        key_list: Vec<String>,
        yaml: &Yaml,
    ) -> Box<dyn SelectionNode + Send + Sync> {
        if yaml.as_hash().is_some() {
            // 連想配列はAND条件と解釈する
            let yaml_hash = yaml.as_hash().unwrap();
            let mut and_node = selectionnodes::AndSelectionNode::new();

            yaml_hash.keys().for_each(|hash_key| {
                let child_yaml = yaml_hash.get(hash_key).unwrap();
                let mut child_key_list = key_list.clone();
                child_key_list.push(hash_key.as_str().unwrap().to_string());
                let child_node = self.parse_selection_recursively(child_key_list, child_yaml);
                and_node.child_nodes.push(child_node);
            });
            return Box::new(and_node);
        } else if yaml.as_vec().is_some() {
            // 配列はOR条件と解釈する。
            let mut or_node = selectionnodes::OrSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = self.parse_selection_recursively(key_list.clone(), child_yaml);
                or_node.child_nodes.push(child_node);
            });

            return Box::new(or_node);
        } else {
            // 連想配列と配列以外は末端ノード
            return Box::new(selectionnodes::LeafSelectionNode::new(
                key_list,
                yaml.clone(),
            ));
        }
    }
}

#[derive(Debug)]
/// countなどのaggregationの結果を出力する構造体
pub struct AggResult {
    /// evtx file path
    pub filepath: String,
    /// countなどの値
    pub data: i32,
    /// (countの括弧内の記載)_(count byで指定された条件)で設定されたキー
    pub key: String,
    ///検知したブロックの最初のレコードの時間
    pub start_timedate: DateTime<Utc>,
    ///条件式の情報
    pub condition_op_num: String,
}

impl AggResult {
    pub fn new(
        filepath: String,
        data: i32,
        key: String,
        start_timedate: DateTime<Utc>,
        condition_op_num: String,
    ) -> AggResult {
        return AggResult {
            filepath: filepath,
            data: data,
            key: key,
            start_timedate: start_timedate,
            condition_op_num: condition_op_num,
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::{detection::EvtxRecordInfo, rule::create_rule};
    use yaml_rust::YamlLoader;

    use super::RuleNode;

    pub fn parse_rule_from_str(rule_str: &str) -> RuleNode {
        let rule_yaml = YamlLoader::load_from_str(rule_str);
        assert_eq!(rule_yaml.is_ok(), true);
        let rule_yamls = rule_yaml.unwrap();
        let mut rule_yaml = rule_yamls.into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());
        assert_eq!(rule_node.init().is_ok(), true);
        return rule_node;
    }

    #[test]
    fn test_detect_dotkey() {
        // aliasじゃなくて、.区切りでつなげるケースが正しく検知できる。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHI
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_dotkey() {
        // aliasじゃなくて、.区切りでつなげるケースで、検知しないはずのケースで検知しないことを確かめる。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHIN
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_differentkey() {
        // aliasじゃなくて、.区切りでつなげるケースで、検知しないはずのケースで検知しないことを確かめる。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: NOTDETECT
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_eventdata2() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                TargetUserName: ichiichi11
        output: 'command=%CommandLine%'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_special_eventdata() {
        // 上記テストケースのEventDataの更に特殊ケースで下記のようにDataタグの中にNameキーがないケースがある。
        // そのためにruleファイルでEventDataというキーだけ特別対応している。
        // 現状、downgrade_attack.ymlというルールの場合だけで確認出来ているケース
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData|re: '[\s\S]*EngineVersion=2\.0[\s\S]*'
        output: 'command=%CommandLine%'
        "#;

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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_special_eventdata() {
        // 上記テストケースのEventDataの更に特殊ケースで下記のようにDataタグの中にNameキーがないケースがある。
        // そのためにruleファイルでEventDataというキーだけ特別対応している。
        // 現状、downgrade_attack.ymlというルールの場合だけで確認出来ているケース
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData: '[\s\S]*EngineVersion=3.0[\s\S]*'
        output: 'command=%CommandLine%'
        "#;

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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_rec) => {
                assert!(false, "Failed to parse json record.");
            }
        }
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
        output: 'Rule parse test'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(),
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
        output: 'Rule parse test'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(),
            Err(vec!["Detection node was not found.".to_string()])
        );
    }

    /// countで対象の数値確認を行うためのテスト用関数
    fn _check_count(rule_str: &str, record_str: &str, key: &str, expect_count: i32) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        let _init = rule_node.init();
        match serde_json::from_str(record_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo {
                    evtx_filepath: "testpath".to_owned(),
                    record: record,
                };
                let result = rule_node.select(&"testpath".to_string(), &recinfo);
                assert_eq!(
                    rule_node.detection.unwrap().aggregation_condition.is_some(),
                    true
                );
                assert_eq!(result, true);
                assert_eq!(
                    *&rule_node
                        .countdata
                        .get("testpath")
                        .unwrap()
                        .get(key)
                        .unwrap()
                        .len() as i32,
                    expect_count
                );
            }
            Err(_rec) => {
                assert!(false, "Failed to parse json record.");
            }
        }
    }
}

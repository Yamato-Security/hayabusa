use crate::detections::utils;
use mopa::mopafy;
use serde_json::Value;
use std::{sync::Arc, vec};
use yaml_rust::Yaml;

use super::matchers;

// Ruleファイルの detection- selection配下のノードはこのtraitを実装する。
pub trait SelectionNode: mopa::Any {
    // 引数で指定されるイベントログのレコードが、条件に一致するかどうかを判定する
    // このトレイトを実装する構造体毎に適切な判定処理を書く必要がある。
    fn select(&self, event_record: &Value) -> bool;

    // 初期化処理を行う
    // 戻り値としてエラーを返却できるようになっているので、Ruleファイルが間違っていて、SelectionNodeを構成出来ない時はここでエラーを出す
    // AndSelectionNode等ではinit()関数とは別にnew()関数を実装しているが、new()関数はただインスタンスを作るだけにして、あまり長い処理を書かないようにしている。
    // これはRuleファイルのパースのエラー処理をinit()関数にまとめるためにこうしている。
    fn init(&mut self) -> Result<(), Vec<String>>;

    // 子ノードを取得する(グラフ理論のchildと同じ意味)
    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>>;

    // 子孫ノードを取得する(グラフ理論のdescendantと同じ意味)
    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>>;
}
mopafy!(SelectionNode);

/// detection - selection配下でAND条件を表すノード
pub struct AndSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode + Send + Sync>>,
}

unsafe impl Send for AndSelectionNode {}
unsafe impl Sync for AndSelectionNode {}

impl AndSelectionNode {
    pub fn new() -> AndSelectionNode {
        return AndSelectionNode {
            child_nodes: vec![],
        };
    }
}

impl SelectionNode for AndSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
        return self.child_nodes.iter().all(|child_node| {
            return child_node.select(event_record);
        });
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let err_msgs = self
            .child_nodes
            .iter_mut()
            .map(|child_node| {
                let res = child_node.init();
                if res.is_err() {
                    return res.unwrap_err();
                } else {
                    return vec![];
                }
            })
            .fold(
                vec![],
                |mut acc: Vec<String>, cur: Vec<String>| -> Vec<String> {
                    acc.extend(cur.into_iter());
                    return acc;
                },
            );

        if err_msgs.is_empty() {
            return Result::Ok(());
        } else {
            return Result::Err(err_msgs);
        }
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node);
        });

        return ret;
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        let mut ret = self.get_childs();

        self.child_nodes
            .iter()
            .map(|child_node| {
                return child_node.get_descendants();
            })
            .flatten()
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        return ret;
    }
}

/// detection - selection配下でOr条件を表すノード
pub struct OrSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode + Send + Sync>>,
}

unsafe impl Send for OrSelectionNode {}
unsafe impl Sync for OrSelectionNode {}

impl OrSelectionNode {
    pub fn new() -> OrSelectionNode {
        return OrSelectionNode {
            child_nodes: vec![],
        };
    }
}

impl SelectionNode for OrSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
        return self.child_nodes.iter().any(|child_node| {
            return child_node.select(event_record);
        });
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let err_msgs = self
            .child_nodes
            .iter_mut()
            .map(|child_node| {
                let res = child_node.init();
                if res.is_err() {
                    return res.unwrap_err();
                } else {
                    return vec![];
                }
            })
            .fold(
                vec![],
                |mut acc: Vec<String>, cur: Vec<String>| -> Vec<String> {
                    acc.extend(cur.into_iter());
                    return acc;
                },
            );

        if err_msgs.is_empty() {
            return Result::Ok(());
        } else {
            return Result::Err(err_msgs);
        }
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node);
        });

        return ret;
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        let mut ret = self.get_childs();

        self.child_nodes
            .iter()
            .map(|child_node| {
                return child_node.get_descendants();
            })
            .flatten()
            .for_each(|descendant_node| {
                ret.push(descendant_node);
            });

        return ret;
    }
}

/// conditionでNotを表すノード
pub struct NotSelectionNode {
    node: Box<dyn SelectionNode + Send + Sync>,
}

unsafe impl Send for NotSelectionNode {}
unsafe impl Sync for NotSelectionNode {}

impl NotSelectionNode {
    pub fn new(node: Box<dyn SelectionNode + Send + Sync>) -> NotSelectionNode {
        return NotSelectionNode { node: node };
    }
}

impl SelectionNode for NotSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
        return !self.node.select(event_record);
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        return Result::Ok(());
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![];
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return self.get_childs();
    }
}

/// detectionで定義した条件をconditionで参照するためのもの
pub struct RefSelectionNode {
    // selection_nodeはDetectionNodeのname_2_nodeが所有権を持っていて、RefSelectionNodeのselection_nodeに所有権を持たせることができない。
    // そこでArcを使って、DetectionNodeのname_2_nodeとRefSelectionNodeのselection_nodeで所有権を共有する。
    // RcじゃなくてArcなのはマルチスレッド対応のため
    selection_node: Arc<Box<dyn SelectionNode + Send + Sync>>,
}

unsafe impl Send for RefSelectionNode {}
unsafe impl Sync for RefSelectionNode {}

impl RefSelectionNode {
    pub fn new(selection_node: Arc<Box<dyn SelectionNode + Send + Sync>>) -> RefSelectionNode {
        return RefSelectionNode {
            selection_node: selection_node,
        };
    }
}

impl SelectionNode for RefSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
        return self.selection_node.select(event_record);
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        return Result::Ok(());
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![&self.selection_node];
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return self.get_childs();
    }
}

/// detection - selection配下の末端ノード
pub struct LeafSelectionNode {
    key_list: Vec<String>,
    select_value: Yaml,
    pub matcher: Option<Box<dyn matchers::LeafMatcher>>,
}

unsafe impl Send for LeafSelectionNode {}
unsafe impl Sync for LeafSelectionNode {}

impl LeafSelectionNode {
    pub fn new(key_list: Vec<String>, value_yaml: Yaml) -> LeafSelectionNode {
        return LeafSelectionNode {
            key_list: key_list,
            select_value: value_yaml,
            matcher: Option::None,
        };
    }

    pub fn get_key(&self) -> String {
        if self.key_list.is_empty() {
            return String::default();
        }

        return self.key_list[0].to_string();
    }

    /// JSON形式のEventJSONから値を取得する関数 aliasも考慮されている。
    fn get_event_value<'a>(&self, event_value: &'a Value) -> Option<&'a Value> {
        if self.key_list.is_empty() {
            return Option::None;
        }

        return utils::get_event_value(&self.get_key(), event_value);
    }

    /// matchers::LeafMatcherの一覧を取得する。
    /// 上から順番に調べて、一番始めに一致したMatcherが適用される
    fn get_matchers(&self) -> Vec<Box<dyn matchers::LeafMatcher>> {
        return vec![
            Box::new(matchers::RegexMatcher::new()),
            Box::new(matchers::MinlengthMatcher::new()),
            Box::new(matchers::RegexesFileMatcher::new()),
            Box::new(matchers::WhitelistFileMatcher::new()),
        ];
    }
}

impl SelectionNode for LeafSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
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
        if self.key_list.len() > 0 && self.key_list[0].to_string() == "EventData" {
            let values = utils::get_event_value(&"Event.EventData.Data".to_string(), event_record);
            if values.is_none() {
                return self.matcher.as_ref().unwrap().is_match(Option::None);
            }

            // 配列じゃなくて、文字列や数値等の場合は普通通りに比較する。
            let eventdata_data = values.unwrap();

            if eventdata_data.is_boolean() || eventdata_data.is_i64() || eventdata_data.is_string()
            {
                return self
                    .matcher
                    .as_ref()
                    .unwrap()
                    .is_match(Option::Some(eventdata_data));
            }
            // 配列の場合は配列の要素のどれか一つでもルールに合致すれば条件に一致したことにする。
            if eventdata_data.is_array() {
                return eventdata_data
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|ary_element| {
                        return self
                            .matcher
                            .as_ref()
                            .unwrap()
                            .is_match(Option::Some(ary_element));
                    });
            } else {
                return self.matcher.as_ref().unwrap().is_match(Option::None);
            }
        }

        let event_value = self.get_event_value(event_record);
        return self.matcher.as_ref().unwrap().is_match(event_value);
    }

    fn init(&mut self) -> Result<(), Vec<String>> {
        let mut fixed_key_list = Vec::new(); // |xx を排除したkey_listを作成する
        for key in &self.key_list {
            if key.contains('|') {
                let v: Vec<&str> = key.split('|').collect();
                self.matcher = match v[1] {
                    "startswith" => Some(Box::new(matchers::StartsWithMatcher::new())),
                    "endswith" => Some(Box::new(matchers::EndsWithMatcher::new())),
                    "contains" => Some(Box::new(matchers::ContainsMatcher::new())),
                    _ => {
                        return Result::Err(vec![format!(
                            "Found unknown key option. option: {}",
                            v[1]
                        )])
                    }
                };
                fixed_key_list.push(v[0].to_string());
            } else {
                fixed_key_list.push(key.to_string());
            }
        }
        self.key_list = fixed_key_list;
        let mut match_key_list = self.key_list.clone();
        match_key_list.remove(0);
        if self.matcher.is_none() {
            let matchers = self.get_matchers();
            self.matcher = matchers
                .into_iter()
                .find(|matcher| matcher.is_target_key(&match_key_list));
        }

        // 一致するmatcherが見つからないエラー
        if self.matcher.is_none() {
            return Result::Err(vec![format!(
                "Found unknown key. key:{}",
                utils::concat_selection_key(&match_key_list)
            )]);
        }

        if self.select_value.is_badvalue() {
            return Result::Err(vec![format!(
                "Cannot parse yaml file. key:{}",
                utils::concat_selection_key(&match_key_list)
            )]);
        }

        return self
            .matcher
            .as_mut()
            .unwrap()
            .init(&match_key_list, &self.select_value);
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![];
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![];
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::rule::tests::parse_rule_from_str;

    #[test]
    fn test_detect_mutiple_regex_and() {
        // AND条件が正しく検知することを確認する。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4103
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "not detect", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_casesensetive() {
        // OR条件が正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }
}

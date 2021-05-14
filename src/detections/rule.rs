extern crate regex;

use mopa::mopafy;

use std::vec;

use crate::detections::utils;

use regex::Regex;
use serde_json::Value;
use yaml_rust::Yaml;

// TODO テストケースかかなきゃ...
pub fn parse_rule(yaml: Yaml) -> RuleNode {
    let detection = parse_detection(&yaml);

    return RuleNode {
        yaml: yaml,
        detection: detection,
    };
}

fn parse_detection(yaml: &Yaml) -> Option<DetectionNode> {
    if yaml["detection"].is_badvalue() {
        return Option::None;
    } else {
        let node = DetectionNode {
            selection: parse_selection(&yaml),
        };
        return Option::Some(node);
    }
}

fn concat_selection_key(key_list: &Vec<String>) -> String {
    return key_list
        .iter()
        .fold("detection -> selection".to_string(), |mut acc, cur| {
            acc = acc + " -> " + cur;
            return acc;
        });
}

fn parse_selection(yaml: &Yaml) -> Option<Box<dyn SelectionNode + Send>> {
    // TODO detection-selectionが存在しない場合のチェック
    let selection_yaml = &yaml["detection"]["selection"];
    if selection_yaml.is_badvalue() {
        return Option::None;
    }
    return Option::Some(parse_selection_recursively(vec![], &selection_yaml));
}

fn parse_selection_recursively(
    key_list: Vec<String>,
    yaml: &Yaml,
) -> Box<dyn SelectionNode + Send> {
    if yaml.as_hash().is_some() {
        // 連想配列はAND条件と解釈する
        let yaml_hash = yaml.as_hash().unwrap();
        let mut and_node = AndSelectionNode::new();

        yaml_hash.keys().for_each(|hash_key| {
            let child_yaml = yaml_hash.get(hash_key).unwrap();
            let mut child_key_list = key_list.clone();
            child_key_list.push(hash_key.as_str().unwrap().to_string());
            let child_node = parse_selection_recursively(child_key_list, child_yaml);
            and_node.child_nodes.push(child_node);
        });
        return Box::new(and_node);
    } else if yaml.as_vec().is_some() {
        // 配列はOR条件と解釈する。
        let mut or_node = OrSelectionNode::new();
        yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
            let child_node = parse_selection_recursively(key_list.clone(), child_yaml);
            or_node.child_nodes.push(child_node);
        });

        return Box::new(or_node);
    } else {
        // 連想配列と配列以外は末端ノード
        return Box::new(LeafSelectionNode::new(key_list, yaml.clone()));
    }
}

// Ruleファイルを表すノード
pub struct RuleNode {
    pub yaml: Yaml,
    detection: Option<DetectionNode>,
}

unsafe impl Sync for RuleNode {}

impl RuleNode {
    pub fn init(&mut self) -> Result<(), Vec<String>> {
        let mut errmsgs: Vec<String> = vec![];

        // field check
        if self.yaml["output"].as_str().unwrap_or("").is_empty() {
            errmsgs.push("Cannot find required key. key:output".to_string());
        }

        // detection node initialization
        self.detection.as_mut().and_then(|detection| {
            let detection_result = detection.init();
            if detection_result.is_err() {
                errmsgs.extend(detection_result.unwrap_err());
            }
            return Option::Some(detection);
        });

        if errmsgs.is_empty() {
            return Result::Ok(());
        } else {
            return Result::Err(errmsgs);
        }
    }

    pub fn select(&self, event_record: &Value) -> bool {
        let selection = self
            .detection
            .as_ref()
            .and_then(|detect_node| detect_node.selection.as_ref());
        if selection.is_none() {
            return false;
        }

        return selection.unwrap().select(event_record);
    }

    // pub fn get_event_ids(&self) -> Vec<i64> {
    //     let selection = self
    //         .detection
    //         .as_ref()
    //         .and_then(|detection| detection.selection.as_ref());
    //     if selection.is_none() {
    //         return vec![];
    //     }

    //     return selection
    //         .unwrap()
    //         .get_descendants()
    //         .iter()
    //         .filter_map(|node| return node.downcast_ref::<LeafSelectionNode>()) // mopaというライブラリを使うと簡単にダウンキャストできるらしいです。https://crates.io/crates/mopa
    //         .filter(|node| {
    //             // キーがEventIDのノードである
    //             let key = utils::get_event_id_key();
    //             if node.get_key() == key {
    //                 return true;
    //             }

    //             // EventIDのAliasに一致しているかどうか
    //             let alias = utils::get_alias(&key);
    //             if alias.is_none() {
    //                 return false;
    //             } else {
    //                 return node.get_key() == alias.unwrap();
    //             }
    //         })
    //         .filter_map(|node| {
    //             return node.select_value.as_i64();
    //         })
    //         .collect();
    // }
}

// Ruleファイルのdetectionを表すノード
struct DetectionNode {
    pub selection: Option<Box<dyn SelectionNode + Send>>,
}

impl DetectionNode {
    fn init(&mut self) -> Result<(), Vec<String>> {
        if self.selection.is_none() {
            return Result::Ok(());
        }

        return self.selection.as_mut().unwrap().init();
    }
}

// Ruleファイルの detection- selection配下のノードはこのtraitを実装する。
trait SelectionNode: mopa::Any {
    fn select(&self, event_record: &Value) -> bool;
    fn init(&mut self) -> Result<(), Vec<String>>;
    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode>>;
    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode>>;
}
mopafy!(SelectionNode);

// detection - selection配下でAND条件を表すノード
struct AndSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

unsafe impl Send for AndSelectionNode {}

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

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode>> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node);
        });

        return ret;
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode>> {
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

// detection - selection配下でOr条件を表すノード
struct OrSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

unsafe impl Send for OrSelectionNode {}

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

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode>> {
        let mut ret = vec![];
        self.child_nodes.iter().for_each(|child_node| {
            ret.push(child_node);
        });

        return ret;
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode>> {
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

// detection - selection配下の末端ノード
struct LeafSelectionNode {
    key_list: Vec<String>,
    select_value: Yaml,
    matcher: Option<Box<dyn LeafMatcher>>,
}

unsafe impl Send for LeafSelectionNode {}

impl LeafSelectionNode {
    fn new(key_list: Vec<String>, value_yaml: Yaml) -> LeafSelectionNode {
        return LeafSelectionNode {
            key_list: key_list,
            select_value: value_yaml,
            matcher: Option::None,
        };
    }

    fn get_key(&self) -> String {
        if self.key_list.is_empty() {
            return String::default();
        }

        return self.key_list[0].to_string();
    }

    // JSON形式のEventJSONから値を取得する関数 aliasも考慮されている。
    fn get_event_value<'a>(&self, event_value: &'a Value) -> Option<&'a Value> {
        if self.key_list.is_empty() {
            return Option::None;
        }

        return utils::get_event_value(&self.get_key(), event_value);
    }

    // LeafMatcherの一覧を取得する。
    fn get_matchers(&self) -> Vec<Box<dyn LeafMatcher>> {
        return vec![
            Box::new(RegexMatcher::new()),
            Box::new(MinlengthMatcher::new()),
            Box::new(RegexesFileMatcher::new()),
            Box::new(WhitelistFileMatcher::new()),
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
        let matchers = self.get_matchers();
        let mut match_key_list = self.key_list.clone();
        match_key_list.remove(0);
        self.matcher = matchers
            .into_iter()
            .find(|matcher| matcher.is_target_key(&match_key_list));
        // 一致するmatcherが見つからないエラー
        if self.matcher.is_none() {
            return Result::Err(vec![format!(
                "Found unknown key. key:{}",
                concat_selection_key(&match_key_list)
            )]);
        }

        if self.select_value.is_badvalue() {
            return Result::Err(vec![format!(
                "Cannot parse yaml file. key:{}",
                concat_selection_key(&match_key_list)
            )]);
        }

        return self
            .matcher
            .as_mut()
            .unwrap()
            .init(&match_key_list, &self.select_value);
    }

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode>> {
        return vec![];
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode>> {
        return vec![];
    }
}

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
trait LeafMatcher: mopa::Any {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool;

    fn is_match(&self, event_value: Option<&Value>) -> bool;

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>>;
}
mopafy!(LeafMatcher);

// 正規表現で比較するロジックを表すクラス
struct RegexMatcher {
    re: Option<Regex>,
}

impl RegexMatcher {
    fn new() -> RegexMatcher {
        return RegexMatcher {
            re: Option::None, // empty
        };
    }
    fn is_regex_fullmatch(&self, re: &Regex, value: String) -> bool {
        return re.find_iter(&value).any(|match_obj| {
            return match_obj.as_str().to_string() == value;
        });
    }
}

impl LeafMatcher for RegexMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        if key_list.is_empty() {
            return true;
        }

        if key_list.len() == 1 {
            return key_list.get(0).unwrap_or(&"".to_string()) == &"regex".to_string();
        } else {
            return false;
        }
    }

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        if select_value.is_null() {
            self.re = Option::None;
            return Result::Ok(());
        }

        // stringで比較する。
        let yaml_value = match select_value {
            Yaml::Boolean(b) => Option::Some(b.to_string()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_string()),
            Yaml::String(s) => Option::Some(s.to_owned()),
            _ => Option::None,
        };
        // ここには来ないはず
        if yaml_value.is_none() {
            let errmsg = format!(
                "unknown error occured. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        // 指定された正規表現が間違っていて、パースに失敗した場合
        let yaml_str = yaml_value.unwrap();
        let re_result = Regex::new(&yaml_str);
        if re_result.is_err() {
            let errmsg = format!(
                "cannot parse regex. [regex:{}, key:{}]",
                yaml_str,
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        self.re = re_result.ok();

        return Result::Ok(());
    }

    fn is_match(&self, event_value: Option<&Value>) -> bool {
        // unwrap_orの引数に""ではなく" "を指定しているのは、
        // event_valueが文字列じゃない場合にis_event_value_nullの値がfalseになるように、len() == 0とならない値を指定している。
        let is_event_value_null = event_value.is_none()
            || event_value.unwrap().is_null()
            || event_value.unwrap().as_str().unwrap_or(" ").len() == 0;

        // yamlにnullが設定されていた場合
        if self.re.is_none() {
            return is_event_value_null;
        }

        return match event_value.unwrap_or(&Value::Null) {
            Value::Bool(b) => self.is_regex_fullmatch(self.re.as_ref().unwrap(), b.to_string()),
            Value::String(s) => self.is_regex_fullmatch(self.re.as_ref().unwrap(), s.to_owned()),
            Value::Number(n) => self.is_regex_fullmatch(self.re.as_ref().unwrap(), n.to_string()),
            _ => false,
        };
    }
}

// 指定された文字数以上であることをチェックするクラス。
struct MinlengthMatcher {
    min_len: i64,
}

impl MinlengthMatcher {
    fn new() -> MinlengthMatcher {
        return MinlengthMatcher { min_len: 0 };
    }
}

impl LeafMatcher for MinlengthMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        if key_list.len() != 1 {
            return false;
        }

        return key_list.get(0).unwrap() == "min_length";
    }

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let min_length = select_value.as_i64();
        if min_length.is_none() {
            let errmsg = format!(
                "min_length value should be Integer. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        self.min_len = min_length.unwrap();
        return Result::Ok(());
    }

    fn is_match(&self, event_value: Option<&Value>) -> bool {
        return match event_value.unwrap_or(&Value::Null) {
            Value::String(s) => s.len() as i64 >= self.min_len,
            Value::Number(n) => n.to_string().len() as i64 >= self.min_len,
            _ => false,
        };
    }
}

// 正規表現のリストが記載されたファイルを読み取って、比較するロジックを表すクラス
// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
struct RegexesFileMatcher {
    regexes_csv_content: Vec<Vec<String>>,
}

impl RegexesFileMatcher {
    fn new() -> RegexesFileMatcher {
        return RegexesFileMatcher {
            regexes_csv_content: vec![],
        };
    }
}

impl LeafMatcher for RegexesFileMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        if key_list.len() != 1 {
            return false;
        }

        return key_list.get(0).unwrap() == "regexes";
    }

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Option::Some(s.to_owned()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_owned()),
            _ => Option::None,
        };
        if value.is_none() {
            let errmsg = format!(
                "regexes value should be String. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let csv_content = utils::read_csv(&value.unwrap());
        if csv_content.is_err() {
            let errmsg = format!(
                "cannot read regexes file. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        self.regexes_csv_content = csv_content.unwrap();

        return Result::Ok(());
    }

    fn is_match(&self, event_value: Option<&Value>) -> bool {
        return match event_value.unwrap_or(&Value::Null) {
            Value::String(s) => !utils::check_regex(s, 0, &self.regexes_csv_content).is_empty(),
            Value::Number(n) => {
                !utils::check_regex(&n.to_string(), 0, &self.regexes_csv_content).is_empty()
            }
            _ => false,
        };
    }
}

// ファイルに列挙された文字列に一致する場合に検知するロジックを表す
// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
struct WhitelistFileMatcher {
    whitelist_csv_content: Vec<Vec<String>>,
}

impl WhitelistFileMatcher {
    fn new() -> WhitelistFileMatcher {
        return WhitelistFileMatcher {
            whitelist_csv_content: vec![],
        };
    }
}

impl LeafMatcher for WhitelistFileMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        if key_list.len() != 1 {
            return false;
        }

        return key_list.get(0).unwrap() == "whitelist";
    }

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Option::Some(s.to_owned()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_owned()),
            _ => Option::None,
        };
        if value.is_none() {
            let errmsg = format!(
                "whitelist value should be String. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let csv_content = utils::read_csv(&value.unwrap());
        if csv_content.is_err() {
            let errmsg = format!(
                "cannot read whitelist file. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        self.whitelist_csv_content = csv_content.unwrap();

        return Result::Ok(());
    }

    fn is_match(&self, event_value: Option<&Value>) -> bool {
        return match event_value.unwrap_or(&Value::Null) {
            Value::String(s) => !utils::check_whitelist(s, &self.whitelist_csv_content),
            Value::Number(n) => {
                !utils::check_whitelist(&n.to_string(), &self.whitelist_csv_content)
            }
            Value::Bool(b) => !utils::check_whitelist(&b.to_string(), &self.whitelist_csv_content),
            _ => true,
        };
    }
}

#[cfg(test)]
mod tests {
    use yaml_rust::YamlLoader;

    use crate::detections::rule::{
        parse_rule, AndSelectionNode, LeafSelectionNode, MinlengthMatcher, OrSelectionNode,
        RegexMatcher, RegexesFileMatcher, SelectionNode, WhitelistFileMatcher,
    };

    use super::RuleNode;

    #[test]
    fn test_rule_parse() {
        // ルールファイルをYAML形式で読み込み
        let rule_str = r#"
        title: PowerShell Execution Pipeline
        description: hogehoge
        enabled: true
        author: Yea
        logsource: 
            product: windows
        detection:
            selection:
                Channel: Microsoft-Windows-PowerShell/Operational
                EventID: 4103
                ContextInfo:
                    - Host Application
                    - ホスト アプリケーション
                ImagePath:
                    min_length: 1234321
                    regexes: ./regexes.txt
                    whitelist: ./whitelist.txt
        falsepositives:
            - unknown
        level: medium
        output: 'command=%CommandLine%'
        creation_date: 2020/11/8
        updated_date: 2020/11/8
        "#;
        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        // Root
        let detection_childs = selection_node.get_childs();
        assert_eq!(detection_childs.len(), 4);

        // Channel
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[0];
            assert_eq!(child_node.is::<LeafSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "Channel");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert_eq!(matcher.is_some(), true);
            let matcher = child_node.matcher.as_ref().unwrap();
            assert_eq!(matcher.is::<RegexMatcher>(), true);
            let matcher = matcher.downcast_ref::<RegexMatcher>().unwrap();

            assert_eq!(matcher.re.is_some(), true);
            let re = matcher.re.as_ref();
            assert_eq!(
                re.unwrap().as_str(),
                "Microsoft-Windows-PowerShell/Operational"
            );
        }

        // EventID
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[1];
            assert_eq!(child_node.is::<LeafSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "EventID");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert_eq!(matcher.is_some(), true);
            let matcher = child_node.matcher.as_ref().unwrap();
            assert_eq!(matcher.is::<RegexMatcher>(), true);
            let matcher = matcher.downcast_ref::<RegexMatcher>().unwrap();

            assert_eq!(matcher.re.is_some(), true);
            let re = matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "4103");
        }

        // ContextInfo
        {
            // OrSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[2];
            assert_eq!(child_node.is::<OrSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<OrSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 2);

            // OrSelectionNodeの下にLeafSelectionNodeがあるパターンをテスト
            // LeafSelectionNodeである、Host Applicationノードが正しいことを確認
            let hostapp_en_node = ancestors[0];
            assert_eq!(hostapp_en_node.is::<LeafSelectionNode>(), true);
            let hostapp_en_node = hostapp_en_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_en_matcher = &hostapp_en_node.matcher;
            assert_eq!(hostapp_en_matcher.is_some(), true);
            let hostapp_en_matcher = hostapp_en_matcher.as_ref().unwrap();
            assert_eq!(hostapp_en_matcher.is::<RegexMatcher>(), true);
            let hostapp_en_matcher = hostapp_en_matcher.downcast_ref::<RegexMatcher>().unwrap();
            assert_eq!(hostapp_en_matcher.re.is_some(), true);
            let re = hostapp_en_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "Host Application");

            // LeafSelectionNodeである、ホスト アプリケーションノードが正しいことを確認
            let hostapp_jp_node = ancestors[1];
            assert_eq!(hostapp_jp_node.is::<LeafSelectionNode>(), true);
            let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_jp_matcher = &hostapp_jp_node.matcher;
            assert_eq!(hostapp_jp_matcher.is_some(), true);
            let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
            assert_eq!(hostapp_jp_matcher.is::<RegexMatcher>(), true);
            let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<RegexMatcher>().unwrap();
            assert_eq!(hostapp_jp_matcher.re.is_some(), true);
            let re = hostapp_jp_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "ホスト アプリケーション");
        }

        // ImagePath
        {
            // AndSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[3];
            assert_eq!(child_node.is::<AndSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<AndSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 3);

            // min-lenが正しく読み込めることを確認
            {
                let ancestor_node = ancestors[0];
                assert_eq!(ancestor_node.is::<LeafSelectionNode>(), true);
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert_eq!(ancestor_node.is_some(), true);
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert_eq!(ancestor_matcher.is::<MinlengthMatcher>(), true);
                let ancestor_matcher = ancestor_matcher.downcast_ref::<MinlengthMatcher>().unwrap();
                assert_eq!(ancestor_matcher.min_len, 1234321);
            }

            // regexesが正しく読み込めることを確認
            {
                let ancestor_node = ancestors[1];
                assert_eq!(ancestor_node.is::<LeafSelectionNode>(), true);
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert_eq!(ancestor_node.is_some(), true);
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert_eq!(ancestor_matcher.is::<RegexesFileMatcher>(), true);
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<RegexesFileMatcher>()
                    .unwrap();

                // regexes.txtの中身と一致していることを確認
                let csvcontent = &ancestor_matcher.regexes_csv_content;
                assert_eq!(csvcontent.len(), 14);

                let firstcontent = &csvcontent[0];
                assert_eq!(firstcontent.len(), 3);
                assert_eq!(firstcontent[0], "0");
                assert_eq!(
                    firstcontent[1],
                    r"^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$"
                );
                assert_eq!(
                    firstcontent[2],
                    r"Metasploit-style cmd with pipe (possible use of Meterpreter 'getsystem')"
                );

                let lastcontent = &csvcontent[13];
                assert_eq!(lastcontent.len(), 3);
                assert_eq!(lastcontent[0], "0");
                assert_eq!(
                    lastcontent[1],
                    r"\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp"
                );
                assert_eq!(lastcontent[2], r"PSAttack-style command via cvtres.exe");
            }

            // whitelist.txtが読み込めることを確認
            {
                let ancestor_node = ancestors[2];
                assert_eq!(ancestor_node.is::<LeafSelectionNode>(), true);
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert_eq!(ancestor_node.is_some(), true);
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert_eq!(ancestor_matcher.is::<WhitelistFileMatcher>(), true);
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<WhitelistFileMatcher>()
                    .unwrap();

                let csvcontent = &ancestor_matcher.whitelist_csv_content;
                assert_eq!(csvcontent.len(), 2);

                assert_eq!(
                    csvcontent[0][0],
                    r#"^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe""#.to_string()
                );
                assert_eq!(
                    csvcontent[1][0],
                    r#"^"C:\\Program Files\\Google\\Update\\GoogleUpdate\.exe""#.to_string()
                );
            }
        }
    }

    // #[test]
    // fn test_get_event_ids() {
    //     let rule_str = r#"
    //     enabled: true
    //     detection:
    //         selection:
    //             EventID: 1234
    //     output: 'command=%CommandLine%'
    //     "#;
    //     let rule_node = parse_rule_from_str(rule_str);
    //     let event_ids = rule_node.get_event_ids();
    //     assert_eq!(event_ids.len(), 1);
    //     assert_eq!(event_ids[0], 1234);
    // }

    #[test]
    fn test_notdetect_regex_eventid() {
        // 完全一致なので、前方一致で検知しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 410}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_regex_eventid2() {
        // 完全一致なので、後方一致で検知しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_regex_eventid() {
        // これはEventID=4103で検知するはず
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_regex_str() {
        // 文字列っぽいデータでも確認
        // 完全一致なので、前方一致しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Securit"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_regex_str2() {
        // 文字列っぽいデータでも確認
        // 完全一致なので、後方一致しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ecurity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }
    #[test]
    fn test_detect_regex_str() {
        // 文字列っぽいデータでも完全一致することを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_regex_emptystr() {
        // 文字列っぽいデータでも完全一致することを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"Channel": ""}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_minlen() {
        // minlenが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security9", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_minlen() {
        // minlenが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_minlen2() {
        // minlenが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security.11", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_minlen_and() {
        // minlenが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    regex: Security10
                    min_length: 10
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_minlen_and() {
        // minlenが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    regex: Security10
                    min_length: 11
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_regex() {
        // 正規表現が使えることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ^Program$
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_regexes() {
        // regexes.txtが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、whitelistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - whitelist: whitelist.txt
        output: 'command=%CommandLine%'
        "#;

        // JSONで値としてダブルクオートを使う場合、\でエスケープが必要なのに注意
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_whitelist() {
        // whitelistが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、whitelistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - whitelist: whitelist.txt
        output: 'command=%CommandLine%'
        "#;

        // JSONで値としてダブルクオートを使う場合、\でエスケープが必要なのに注意
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_whitelist2() {
        // whitelistが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、whitelistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - whitelist: whitelist.txt
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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
                EventData: '[\s\S]*EngineVersion=2.0[\s\S]*'
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
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

        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = rule_node.detection.unwrap().selection.unwrap();

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(selection_node.select(&record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    fn parse_rule_from_str(rule_str: &str) -> RuleNode {
        let rule_yaml = YamlLoader::load_from_str(rule_str);
        assert_eq!(rule_yaml.is_ok(), true);
        let rule_yamls = rule_yaml.unwrap();
        let mut rule_yaml = rule_yamls.into_iter();
        let mut rule_node = parse_rule(rule_yaml.next().unwrap());
        assert_eq!(rule_node.init().is_ok(), true);
        return rule_node;
    }
}

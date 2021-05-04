extern crate regex;

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

    pub fn get_event_ids(&self) -> Vec<i64> {
        let selection = self
            .detection
            .as_ref()
            .and_then(|detection| detection.selection.as_ref());
        if selection.is_none() {
            return vec![];
        }

        return selection
            .unwrap()
            .get_leaf_nodes()
            .iter()
            .filter(|node| {
                return node.get_key() == "EventID";
            })
            .filter(|node| {
                return node.select_value.as_i64().is_some();
            })
            .map(|node| {
                return node.select_value.as_i64().unwrap();
            })
            .collect();
    }
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
trait SelectionNode {
    fn select(&self, event_record: &Value) -> bool;
    fn init(&mut self) -> Result<(), Vec<String>>;
    fn get_leaf_nodes(&self) -> Vec<&LeafSelectionNode>;
}

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

    fn get_leaf_nodes(&self) -> Vec<&LeafSelectionNode> {
        let mut ret = vec![];

        self.child_nodes
            .iter()
            .map(|child| {
                return child.get_leaf_nodes();
            })
            .flatten()
            .for_each(|descendant| {
                ret.push(descendant);
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

    fn get_leaf_nodes(&self) -> Vec<&LeafSelectionNode> {
        let mut ret = vec![];

        self.child_nodes
            .iter()
            .map(|child| {
                return child.get_leaf_nodes();
            })
            .flatten()
            .for_each(|descendant| {
                ret.push(descendant);
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

    fn get_leaf_nodes(&self) -> Vec<&LeafSelectionNode> {
        return vec![&self];
    }
}

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
trait LeafMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool;

    fn is_match(&self, event_value: Option<&Value>) -> bool;

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>>;
}

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
            Value::String(s) => utils::check_whitelist(s, &self.whitelist_csv_content),
            Value::Number(n) => utils::check_whitelist(&n.to_string(), &self.whitelist_csv_content),
            Value::Bool(b) => utils::check_whitelist(&b.to_string(), &self.whitelist_csv_content),
            _ => false,
        };
    }
}

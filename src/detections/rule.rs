use serde_json::Value;
use yaml_rust::Yaml;
use crate::detections::configs;

pub fn parse_rule(yaml: Yaml) -> RuleNode {
    let selection = parse_selection(&yaml);
    return RuleNode {
        yaml: yaml,
        detection: DetectionNode {
            selection: selection,
        },
    };
}

fn parse_selection(yaml: &Yaml) -> Option<Box<dyn SelectionNode>> {
    let selection_yaml = &yaml["detection"]["selection"];
    return Option::Some(parse_selection_recursively(vec![], &selection_yaml));
}

fn parse_selection_recursively(mut key_list: Vec<String>, yaml: &Yaml) -> Box<dyn SelectionNode> {
    if yaml.as_hash().is_some() {
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
        let mut or_node = OrSelectionNode::new();
        yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
            let child_node = parse_selection_recursively(key_list.clone(), child_yaml);
            or_node.child_nodes.push(child_node);
        });

        return Box::new(or_node);
    } else {
        return Box::new(FieldSelectionNode::new(key_list, yaml.clone()));
    }
}

/////////////// RuleNode
pub struct RuleNode {
    pub yaml: Yaml,
    pub detection: DetectionNode,
}

//////////////// Detection Node
pub struct DetectionNode {
    selection: Option<Box<dyn SelectionNode>>,
}

impl DetectionNode {
    pub fn select(&self, event_record: &Value) -> bool {
        if self.selection.is_none() {
            return false;
        }

        return self.selection.as_ref().unwrap().select(event_record);
    }
}

//////////// Selection Node
trait SelectionNode {
    fn select(&self, event_record: &Value) -> bool;
}

///////////////// AndSelectionNode
struct AndSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

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
            return child_node.as_ref().select(event_record);
        });
    }
}

////////// OrSelectionNode
struct OrSelectionNode {
    pub child_nodes: Vec<Box<dyn SelectionNode>>,
}

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
            return child_node.as_ref().select(event_record);
        });
    }
}

////////////// Field Selection Node
struct FieldSelectionNode {
    key_list: Vec<String>,
    select_value: Yaml,
}

impl FieldSelectionNode {
    fn new(key_list: Vec<String>, value_yaml: Yaml) -> FieldSelectionNode {
        return FieldSelectionNode {
            key_list: key_list,
            select_value: value_yaml,
        };
    }

    // JSON形式のEventJSONから値を取得する関数 aliasも考慮されている。
    // TODO Messageを出力する際も利用するので、共通して使えるようにrefactoringする。
    fn get_event_value<'a>(&self, event_value: &'a Value) -> Option<&'a Value> {
        if self.key_list.is_empty() {
            return Option::None;
        }

        let key: &str = &self.key_list[0];
        if key.len() == 0 {
            return Option::None;
        }

        let event_key = match configs::singleton().event_key_alias_config.get_event_key(key.to_string()) {
            Some(alias_event_key) => { alias_event_key }
            None => { key }
        };
        
        let mut ret: &Value = event_value;
        for key in event_key.split(".") {
            if ret.is_object() == false {
                return Option::None;
            }
            ret = &ret[key];
        }

        return Option::Some(ret);
    }

    // TODO Matcherのインスタンスが都度生成されないようにする。
    fn get_matchers(&self) -> Vec<Box<dyn FieldSelectionMatcher>> {
        return vec![Box::new(ValueMatcher {})];
    }
}

impl SelectionNode for FieldSelectionNode {
    fn select(&self, event_record: &Value) -> bool {
        let matchers = self.get_matchers();
        let matcher = matchers
            .into_iter()
            .find(|matcher| matcher.is_target_key(&self.key_list));
        if matcher.is_none() {
            return false;
        }

        let event_value = self.get_event_value(event_record);
        return matcher
            .unwrap()
            .is_match(&self.key_list, &self.select_value, event_value);
    }
}

trait FieldSelectionMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool;
    fn is_match(
        &self,
        key_list: &Vec<String>,
        select_value: &Yaml,
        event_value: Option<&Value>,
    ) -> bool;
}

struct ValueMatcher {}

impl FieldSelectionMatcher for ValueMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        return key_list.is_empty();
    }

    fn is_match(
        &self,
        key_list: &Vec<String>,
        select_value: &Yaml,
        event_value: Option<&Value>,
    ) -> bool {
        return true;
    }
}
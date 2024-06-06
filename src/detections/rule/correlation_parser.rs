use std::error::Error;

use yaml_rust::Yaml;

use crate::detections::configs::StoredStatic;
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use crate::detections::rule::aggregation_parser::{
    AggregationConditionToken, AggregationParseInfo,
};
use crate::detections::rule::count::TimeFrameInfo;
use crate::detections::rule::selectionnodes::OrSelectionNode;
use crate::detections::rule::{DetectionNode, RuleNode};

fn is_related_rule(rule_node: &RuleNode, id_or_title: &str) -> bool {
    if let Some(hash) = rule_node.yaml.as_hash() {
        if let Some(id) = hash.get(&Yaml::String("id".to_string())) {
            if id.as_str() == Some(id_or_title) {
                return true;
            }
        }
        if let Some(title) = hash.get(&Yaml::String("title".to_string())) {
            if title.as_str() == Some(id_or_title) {
                return true;
            }
        }
    }
    false
}

fn parse_condition(yaml: &Yaml) -> Result<(AggregationConditionToken, i64), Box<dyn Error>> {
    if let Some(hash) = yaml.as_hash() {
        if let Some(condition) = hash.get(&Yaml::String("condition".to_string())) {
            if let Some(condition_hash) = condition.as_hash() {
                if let Some((key, value)) = condition_hash.into_iter().next() {
                    let key_str = key
                        .as_str()
                        .ok_or("Failed to convert condition key to string")?;
                    let token = match key_str {
                        "eq" => AggregationConditionToken::EQ,
                        "lte" => AggregationConditionToken::LE,
                        "gte" => AggregationConditionToken::GE,
                        "lt" => AggregationConditionToken::LT,
                        "gt" => AggregationConditionToken::GT,
                        _ => return Err(format!("Invalid condition token: {}", key_str).into()),
                    };
                    let value_num = value
                        .as_i64()
                        .ok_or("Failed to convert condition value to i64")?;
                    return Ok((token, value_num));
                }
            }
        }
    }
    Err("Failed to parse condition".into())
}

fn to_or_selection_node(related_rule_nodes: Vec<RuleNode>) -> OrSelectionNode {
    let mut or_selection_node = OrSelectionNode::new();
    for rule_node in related_rule_nodes {
        or_selection_node
            .child_nodes
            .push(rule_node.detection.condition.unwrap());
    }
    or_selection_node
}

fn get_related_rules_id(yaml: &Yaml) -> Result<Vec<String>, Box<dyn Error>> {
    let correlation = yaml["correlation"]
        .as_hash()
        .ok_or("Failed to get 'correlation'")?;
    let rules_yaml = correlation
        .get(&Yaml::String("rules".to_string()))
        .ok_or("Failed to get 'rules'")?;

    let mut rules = Vec::new();
    for rule_yaml in rules_yaml
        .as_vec()
        .ok_or("Failed to convert 'rules' to Vec")?
    {
        let rule = rule_yaml
            .as_str()
            .ok_or("Failed to convert rule to string")?
            .to_string();
        rules.push(rule);
    }

    Ok(rules)
}

fn get_group_by_from_yaml(yaml: &Yaml) -> Result<String, Box<dyn Error>> {
    let correlation = yaml["correlation"]
        .as_hash()
        .ok_or("Failed to get 'correlation'")?;
    let group_by_yaml = correlation
        .get(&Yaml::String("group-by".to_string()))
        .ok_or("Failed to get 'group-by'")?;

    let mut group_by = Vec::new();
    for group_by_yaml in group_by_yaml
        .as_vec()
        .ok_or("Failed to convert 'group-by' to Vec")?
    {
        let group = group_by_yaml
            .as_str()
            .ok_or("Failed to convert group to string")?
            .to_string();
        group_by.push(group);
    }

    Ok(group_by.join(","))
}
fn parse_tframe(value: String) -> Result<TimeFrameInfo, Box<dyn Error>> {
    let ttype;
    let mut target_val = value.as_str();
    if target_val.ends_with('s') {
        ttype = "s";
    } else if target_val.ends_with('m') {
        ttype = "m";
    } else if target_val.ends_with('h') {
        ttype = "h";
    } else if target_val.ends_with('d') {
        ttype = "d";
    } else {
        return Err("Invalid time frame".into());
    }
    if !ttype.is_empty() {
        target_val = &value[..value.len() - 1];
    }
    Ok(TimeFrameInfo {
        timetype: ttype.to_string(),
        timenum: target_val.parse::<i64>(),
    })
}

fn create_related_rule_nodes(
    related_rules_ids: Vec<String>,
    other_rules: &[RuleNode],
    stored_static: &StoredStatic,
) -> Vec<RuleNode> {
    let mut related_rule_nodes: Vec<RuleNode> = Vec::new();
    for id in related_rules_ids {
        for other_rule in other_rules {
            if is_related_rule(other_rule, &id) {
                let mut node = RuleNode::new(other_rule.rulepath.clone(), other_rule.yaml.clone());
                let _ = node.init(stored_static);
                related_rule_nodes.push(node);
            }
        }
    }
    related_rule_nodes
}

fn create_detection(
    rule_node: &RuleNode,
    related_rule_nodes: Vec<RuleNode>,
) -> Result<DetectionNode, Box<dyn Error>> {
    let condition = parse_condition(&rule_node.yaml["correlation"])?;
    let group_by = get_group_by_from_yaml(&rule_node.yaml)?;
    let timespan = rule_node.yaml["correlation"]["timespan"].as_str();
    match timespan {
        None => Err("Failed to get 'timespan'".into()),
        Some(timespan) => {
            let time_frame = parse_tframe(timespan.to_string())?;
            let nodes = to_or_selection_node(related_rule_nodes);
            let agg_info = AggregationParseInfo {
                _field_name: None,
                _by_field_name: Some(group_by),
                _cmp_op: condition.0,
                _cmp_num: condition.1,
            };
            Ok(DetectionNode::new_with_data(
                Some(Box::new(nodes)),
                Some(agg_info),
                Some(time_frame),
            ))
        }
    }
}

fn error_log(
    rule_path: &str,
    reason: &str,
    stored_static: &StoredStatic,
    parseerror_count: &mut u128,
) {
    let msg = format!(
        "Failed to parse rule. (FilePath : {}) {}",
        rule_path, reason
    );
    if stored_static.verbose_flag {
        AlertMessage::alert(msg.as_str()).ok();
    }
    if !stored_static.quiet_errors_flag {
        ERROR_LOG_STACK
            .lock()
            .unwrap()
            .push(format!("[WARN] {msg}"));
    }
    *parseerror_count += 1;
}

pub fn parse_correlation_rules(
    rule_nodes: Vec<RuleNode>,
    stored_static: &StoredStatic,
    parseerror_count: &mut u128,
) -> Vec<RuleNode> {
    let (correlation_rules, other_rules): (Vec<RuleNode>, Vec<RuleNode>) = rule_nodes
        .into_iter()
        .partition(|rule_node| !rule_node.yaml["correlation"].is_badvalue());
    let mut parsed_rules: Vec<RuleNode> = correlation_rules
        .into_iter()
        .map(|rule_node| {
            if rule_node.yaml["correlation"]["type"].as_str() != Some("event_count") {
                let m = "The type of correlations rule only supports event_count.";
                error_log(&rule_node.rulepath, m, stored_static, parseerror_count);
                return rule_node;
            }
            let related_rules_ids = get_related_rules_id(&rule_node.yaml);
            let related_rules_ids = match related_rules_ids {
                Ok(related_rules_ids) => related_rules_ids,
                Err(_) => {
                    let m = "Related rule not found.";
                    error_log(&rule_node.rulepath, m, stored_static, parseerror_count);
                    return rule_node;
                }
            };
            if related_rules_ids.is_empty() {
                let m = "Related rule not found.";
                error_log(&rule_node.rulepath, m, stored_static, parseerror_count);
                return rule_node;
            }
            let related_rules =
                create_related_rule_nodes(related_rules_ids, &other_rules, stored_static);
            let detection = create_detection(&rule_node, related_rules);
            let detection = match detection {
                Ok(detection) => detection,
                Err(e) => {
                    error_log(
                        &rule_node.rulepath,
                        e.to_string().as_str(),
                        stored_static,
                        parseerror_count,
                    );
                    return rule_node;
                }
            };
            RuleNode::new_with_detection(rule_node.rulepath, rule_node.yaml, detection)
        })
        .collect();
    parsed_rules.extend(other_rules);
    parsed_rules
}

#[cfg(test)]
mod tests {
    use yaml_rust::YamlLoader;

    use super::*;

    #[test]
    fn test_parse_condition_valid() {
        let yaml_str = r#"
        condition:
            gte: 3
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let result = parse_condition(yaml);
        assert!(result.is_ok());
        let (_, value) = result.unwrap();
        assert_eq!(value, 3);
    }

    #[test]
    fn test_parse_condition_invalid_token() {
        let yaml_str = r#"
        condition:
            invalid_token: 3
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let result = parse_condition(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_condition_invalid_value() {
        let yaml_str = r#"
        condition:
            gte: invalid_value
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let result = parse_condition(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_rules_from_yaml() {
        let yaml_str = r#"
        title: Many failed logins to the same computer
        id: 0e95725d-7320-415d-80f7-004da920fc11
        correlation:
          type: event_count
          rules:
            - e87bd730-df45-4ae9-85de-6c75369c5d29 # Logon Failure (Wrong Password)
            - 8afa97ce-a217-4f7c-aced-3e320a57756d # Logon Failure (User Does Not Exist)
          group-by:
            - Computer
          timespan: 5m
          condition:
            gte: 3
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let result = get_related_rules_id(yaml).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "e87bd730-df45-4ae9-85de-6c75369c5d29");
        assert_eq!(result[1], "8afa97ce-a217-4f7c-aced-3e320a57756d");
    }
}

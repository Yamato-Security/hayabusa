use std::error::Error;
use std::sync::Arc;

use crate::detections::configs::StoredStatic;
use crate::detections::message::{AlertMessage, ERROR_LOG_STACK};
use crate::detections::rule::aggregation_parser::{
    AggregationConditionToken, AggregationParseInfo,
};
use crate::detections::rule::count::TimeFrameInfo;
use crate::detections::rule::selectionnodes::{OrSelectionNode, SelectionNode};
use crate::detections::rule::{CorrelationType, DetectionNode, RuleNode};
use hashbrown::{HashMap, HashSet};
use uuid::Uuid;
use yaml_rust2::Yaml;
use yaml_rust2::yaml::Hash;

type Name2Selection = HashMap<String, Arc<Box<dyn SelectionNode>>>;

fn is_referenced_rule(rule_node: &RuleNode, id_or_title: &str) -> bool {
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
        if let Some(title) = hash.get(&Yaml::String("name".to_string())) {
            if title.as_str() == Some(id_or_title) {
                return true;
            }
        }
    }
    false
}
fn find_condition_field_value(
    rule_type: Option<&Yaml>,
    pair: Vec<(&Yaml, &Yaml)>,
) -> Option<String> {
    for (key, value) in pair {
        if let Some(key_str) = key.as_str() {
            if key_str == "field" && rule_type == Some(&Yaml::String("value_count".to_string())) {
                return value.as_str().map(|s| s.to_string());
            }
        }
    }
    None
}

fn process_condition_pairs(
    pair: Vec<(&Yaml, &Yaml)>,
    field: Option<String>,
) -> Result<(AggregationConditionToken, i64, Option<String>), Box<dyn Error>> {
    for (key, value) in pair {
        if let Some(key_str) = key.as_str() {
            let token = match key_str {
                "eq" => AggregationConditionToken::EQ,
                "lte" => AggregationConditionToken::LE,
                "gte" => AggregationConditionToken::GE,
                "lt" => AggregationConditionToken::LT,
                "gt" => AggregationConditionToken::GT,
                _ => continue,
            };
            let value_num = value
                .as_i64()
                .ok_or("Failed to convert condition value to i64")?;
            return Ok((token, value_num, field.clone()));
        }
    }
    Err("Failed to match any condition".into())
}

fn parse_condition(
    yaml: &Yaml,
) -> Result<(AggregationConditionToken, i64, Option<String>), Box<dyn Error>> {
    if let Some(hash) = yaml.as_hash() {
        let rule_type = hash.get(&Yaml::String("type".to_string()));
        if let Some(condition) = hash.get(&Yaml::String("condition".to_string())) {
            if let Some(condition_hash) = condition.as_hash() {
                let pair: Vec<(&Yaml, &Yaml)> = condition_hash.iter().collect();
                let field = find_condition_field_value(rule_type, pair.clone());
                return process_condition_pairs(pair, field);
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

fn get_group_by_from_yaml(yaml: &Yaml) -> Result<Option<String>, Box<dyn Error>> {
    let correlation = yaml["correlation"]
        .as_hash()
        .ok_or("Failed to get 'correlation'")?;
    let group_by_yaml = match correlation.get(&Yaml::String("group-by".to_string())) {
        Some(value) => value,
        None => return Ok(None),
    };

    let mut group_by = Vec::new();
    if let Some(group_by_vec) = group_by_yaml.as_vec() {
        for group_by_yaml in group_by_vec {
            if let Some(group) = group_by_yaml.as_str() {
                group_by.push(group.to_string());
            }
        }
    }
    Ok(Some(group_by.join(",")))
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
    related_rules_ids: &Vec<String>,
    other_rules: &[RuleNode],
    stored_static: &StoredStatic,
) -> Result<(Vec<RuleNode>, Name2Selection), Box<dyn Error>> {
    let mut related_rule_nodes: Vec<RuleNode> = Vec::new();
    let mut name_to_selection: Name2Selection = HashMap::new();
    for id in related_rules_ids {
        let mut any_referenced = false;
        for other_rule in other_rules {
            if is_referenced_rule(other_rule, id) {
                any_referenced = true;
                let mut node = RuleNode::new(other_rule.rulepath.clone(), other_rule.yaml.clone());
                let _ = node.init(stored_static);
                name_to_selection.extend(node.detection.name_to_selection.clone());
                related_rule_nodes.push(node);
            }
        }
        if !any_referenced {
            let msg = format!("The referenced rule was not found: {id}");
            return Err(msg.into());
        }
    }
    Ok((related_rule_nodes, name_to_selection))
}

fn create_detection(
    rule_node: &RuleNode,
    related_rule_nodes: Vec<RuleNode>,
    name_to_selection: HashMap<String, Arc<Box<dyn SelectionNode>>>,
) -> Result<DetectionNode, Box<dyn Error>> {
    let condition = parse_condition(&rule_node.yaml["correlation"])?;
    let group_by = get_group_by_from_yaml(&rule_node.yaml)?;
    let timespan = rule_node.yaml["correlation"]["timespan"].as_str();
    match timespan {
        None => Err("Failed to get 'timespan'".into()),
        Some(timespan) => {
            let time_frame = parse_tframe(timespan.to_string())?;
            let node = to_or_selection_node(related_rule_nodes);
            let agg_info = AggregationParseInfo {
                _field_name: condition.2,
                _by_field_name: group_by,
                _cmp_op: condition.0,
                _cmp_num: condition.1,
            };
            Ok(DetectionNode::new_with_data(
                name_to_selection,
                Some(Box::new(node)),
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
    let msg = format!("Failed to parse rule. (FilePath : {rule_path}) {reason}");
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

fn merge_referenced_rule(
    rule: RuleNode,
    other_rules: &mut Vec<RuleNode>,
    stored_static: &StoredStatic,
    parse_error_count: &mut u128,
) -> RuleNode {
    let rule_type = rule.yaml["correlation"]["type"].as_str();
    if rule_type != Some("event_count")
        && rule_type != Some("value_count")
        && rule_type != Some("temporal")
        && rule_type != Some("temporal_ordered")
    {
        let m = "The type of correlation rule only supports event_count/value_count/temporal/temporal_ordered.";
        error_log(&rule.rulepath, m, stored_static, parse_error_count);
        return rule;
    }
    let referenced_ids = match get_related_rules_id(&rule.yaml) {
        Ok(related_rules_ids) => related_rules_ids,
        Err(_) => {
            let m = "Referenced rule not found.";
            error_log(&rule.rulepath, m, stored_static, parse_error_count);
            return rule;
        }
    };
    if referenced_ids.is_empty() {
        let m = "Referenced rule not found.";
        error_log(&rule.rulepath, m, stored_static, parse_error_count);
        return rule;
    }
    if rule.yaml["correlation"]["timespan"].as_str().is_none() {
        let m = "key timespan not found.";
        error_log(&rule.rulepath, m, stored_static, parse_error_count);
        return rule;
    }
    if rule.yaml["correlation"]["group-by"].as_vec().is_none() {
        let m = "key group-by  not found.";
        error_log(&rule.rulepath, m, stored_static, parse_error_count);
        return rule;
    }
    if rule_type == Some("temporal") || rule_type == Some("temporal_ordered") {
        return rule;
    }
    let (referenced_rules, name_to_selection) =
        match create_related_rule_nodes(&referenced_ids, other_rules, stored_static) {
            Ok(result) => result,
            Err(e) => {
                error_log(
                    &rule.rulepath,
                    e.to_string().as_str(),
                    stored_static,
                    parse_error_count,
                );
                return rule;
            }
        };
    let is_not_referenced_rule = |rule_node: &RuleNode| {
        let id = rule_node.yaml["id"].as_str().unwrap_or_default();
        let title = rule_node.yaml["title"].as_str().unwrap_or_default();
        let name = rule_node.yaml["name"].as_str().unwrap_or_default();
        !referenced_ids.contains(&id.to_string())
            && !referenced_ids.contains(&title.to_string())
            && !referenced_ids.contains(&name.to_string())
    };
    if !rule.yaml["correlation"]["generate"]
        .as_bool()
        .unwrap_or_default()
    {
        other_rules.retain(is_not_referenced_rule);
    }
    let referenced_hashes: Vec<Hash> = referenced_rules
        .iter()
        .filter_map(|rule_node| rule_node.yaml.as_hash().cloned())
        .collect();
    let detection = match create_detection(&rule, referenced_rules, name_to_selection) {
        Ok(detection) => detection,
        Err(e) => {
            error_log(
                &rule.rulepath,
                e.to_string().as_str(),
                stored_static,
                parse_error_count,
            );
            return rule;
        }
    };
    let referenced_yaml: Yaml =
        Yaml::Array(referenced_hashes.into_iter().map(Yaml::Hash).collect());
    let mut merged_yaml = rule.yaml.as_hash().unwrap().clone();
    merged_yaml.insert(Yaml::String("detection".to_string()), referenced_yaml);
    RuleNode::new_with_detection(rule.rulepath, Yaml::Hash(merged_yaml), detection)
}

fn parse_temporal_rules(
    temporal_rules: Vec<RuleNode>,
    other_rules: &mut Vec<RuleNode>,
    stored_static: &StoredStatic,
) -> Vec<RuleNode> {
    let mut parsed_temporal_rules: Vec<RuleNode> = Vec::new();
    let mut temporal_ref_rules: Vec<RuleNode> = Vec::new();
    let mut referenced_del_ids: HashSet<String> = HashSet::new();
    for temporal in temporal_rules.iter() {
        let temporal_yaml = &temporal.yaml;
        let mut temporal_ref_ids: Vec<Yaml> = Vec::new();
        if let Some(ref_ids) = temporal_yaml["correlation"]["rules"].as_vec() {
            for ref_id in ref_ids {
                for other_rule in other_rules.iter_mut() {
                    let ref_id = ref_id.as_str().unwrap_or_default();
                    if is_referenced_rule(other_rule, ref_id) {
                        let generate = temporal_yaml["correlation"]["generate"]
                            .as_bool()
                            .unwrap_or_default();
                        let mut new_yaml = other_rule.yaml.clone();
                        if other_rule.correlation_type != CorrelationType::None {
                            other_rule.correlation_type =
                                CorrelationType::TemporalRef(generate, ref_id.to_string());
                            temporal_ref_ids.push(Yaml::String(ref_id.to_string()));
                            continue;
                        }
                        let new_id = Uuid::new_v4().to_string();
                        if let Some(hash) = new_yaml.as_mut_hash() {
                            hash.insert(
                                Yaml::String("id".to_string()),
                                Yaml::String(new_id.to_string()),
                            );
                        }
                        let mut node = RuleNode::new(other_rule.rulepath.clone(), new_yaml);
                        let _ = node.init(stored_static);
                        node.correlation_type =
                            CorrelationType::TemporalRef(generate, new_id.to_string());
                        let group_by = get_group_by_from_yaml(&temporal.yaml);
                        let timespan = &temporal.yaml["correlation"]["timespan"].as_str().unwrap();
                        let time_frame = parse_tframe(timespan.to_string());
                        let agg_info = AggregationParseInfo {
                            _field_name: None,
                            _by_field_name: group_by.unwrap(),
                            _cmp_op: AggregationConditionToken::GE,
                            _cmp_num: 1,
                        };
                        let mut detection = DetectionNode::new();
                        detection.name_to_selection = node.detection.name_to_selection;
                        detection.condition = node.detection.condition;
                        detection.timeframe = Some(time_frame.unwrap());
                        detection.aggregation_condition = Some(agg_info);
                        node.detection = detection;
                        temporal_ref_rules.push(node);
                        temporal_ref_ids.push(Yaml::String(new_id.to_string()));
                        if !generate {
                            referenced_del_ids.insert(ref_id.to_string());
                        }
                    }
                }
            }
            let mut new_yaml = temporal_yaml.clone();
            new_yaml["correlation"]["rules"] = Yaml::Array(temporal_ref_ids);
            let mut node = RuleNode::new(temporal.rulepath.clone(), new_yaml);
            let group_by = get_group_by_from_yaml(&temporal.yaml);
            let timespan = &temporal.yaml["correlation"]["timespan"].as_str().unwrap();
            let time_frame = parse_tframe(timespan.to_string());
            node.detection.aggregation_condition = Some(AggregationParseInfo {
                _field_name: None,
                _by_field_name: group_by.unwrap(),
                _cmp_op: AggregationConditionToken::GE,
                _cmp_num: 1,
            });
            node.detection.timeframe = Some(time_frame.unwrap());
            parsed_temporal_rules.push(node);
        }
    }
    other_rules.retain(|rule| {
        let id = rule.yaml["id"].as_str().unwrap_or_default();
        let title = rule.yaml["title"].as_str().unwrap_or_default();
        let name = rule.yaml["name"].as_str().unwrap_or_default();
        !referenced_del_ids.contains(id)
            && !referenced_del_ids.contains(title)
            && !referenced_del_ids.contains(name)
    });
    other_rules.extend(temporal_ref_rules);
    parsed_temporal_rules
}

pub fn parse_correlation_rules(
    rule_nodes: Vec<RuleNode>,
    stored_static: &StoredStatic,
    parse_error_count: &mut u128,
) -> Vec<RuleNode> {
    let (correlation_rules, mut not_correlation_rules): (Vec<RuleNode>, Vec<RuleNode>) = rule_nodes
        .into_iter()
        .partition(|rule_node| !rule_node.yaml["correlation"].is_badvalue());
    let (temporal_rules, not_temporal_rules): (Vec<RuleNode>, Vec<RuleNode>) =
        correlation_rules.into_iter().partition(|rule_node| {
            rule_node.yaml["correlation"]["type"].as_str() == Some("temporal")
                || rule_node.yaml["correlation"]["type"].as_str() == Some("temporal_ordered")
        });
    let mut parsed_rules: Vec<RuleNode> = not_temporal_rules
        .into_iter()
        .map(|correlation_rule_node| {
            merge_referenced_rule(
                correlation_rule_node,
                &mut not_correlation_rules,
                stored_static,
                parse_error_count,
            )
        })
        .collect();
    parsed_rules.extend(not_correlation_rules);
    let parsed_temporal_rules =
        parse_temporal_rules(temporal_rules, &mut parsed_rules, stored_static);
    parsed_rules.extend(parsed_temporal_rules);
    parsed_rules
}

#[cfg(test)]
mod tests {
    use yaml_rust2::YamlLoader;

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
        let (_, value, _) = result.unwrap();
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

    #[test]
    fn test_find_field_value() {
        let yaml_str = r#"
        field: "test_field"
        other_key: "other_value"
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let pair: Vec<(&Yaml, &Yaml)> = yaml.as_hash().unwrap().iter().collect();
        let result =
            find_condition_field_value(Some(&Yaml::String("value_count".to_string())), pair);
        assert_eq!(result, Some("test_field".to_string()));
    }

    #[test]
    fn test_find_field_value_no_field() {
        let yaml_str = r#"
        other_key: "other_value"
        another_key: "another_value"
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let pair: Vec<(&Yaml, &Yaml)> = yaml.as_hash().unwrap().iter().collect();
        let result =
            find_condition_field_value(Some(&Yaml::String("value_count".to_string())), pair);
        assert_eq!(result, None);
    }

    #[test]
    fn test_process_condition_pairs_valid() {
        let yaml_str = r#"
        eq: 3
        other_key: "other_value"
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let pair: Vec<(&Yaml, &Yaml)> = yaml.as_hash().unwrap().iter().collect();
        let result = process_condition_pairs(pair, Some("test_field".to_string()));
        assert!(result.is_ok());
        let (_, value, field) = result.unwrap();
        assert_eq!(value, 3);
        assert_eq!(field, Some("test_field".to_string()));
    }

    #[test]
    fn test_process_condition_pairs_invalid_token() {
        let yaml_str = r#"
        invalid_token: 3
        other_key: "other_value"
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let pair: Vec<(&Yaml, &Yaml)> = yaml.as_hash().unwrap().iter().collect();
        let result = process_condition_pairs(pair, Some("test_field".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_process_condition_pairs_invalid_value() {
        let yaml_str = r#"
        eq: invalid_value
        other_key: "other_value"
        "#;
        let yaml = &YamlLoader::load_from_str(yaml_str).unwrap()[0];
        let pair: Vec<(&Yaml, &Yaml)> = yaml.as_hash().unwrap().iter().collect();
        let result = process_condition_pairs(pair, Some("test_field".to_string()));
        assert!(result.is_err());
    }
}

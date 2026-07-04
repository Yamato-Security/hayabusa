use lazy_static::lazy_static;
use regex::Regex;

use self::selectionnodes::{
    AndSelectionNode, NotSelectionNode, OrSelectionNode, RefSelectionNode, SelectionNode,
};
use super::selectionnodes;
use hashbrown::HashMap;
use itertools::Itertools;
use std::{sync::Arc, vec::IntoIter};

lazy_static! {
    // Token patterns tried in order during lexing: "(", ")", a space, and a selection name or
    // keyword (and/or/not).
    pub static ref CONDITION_REGEXMAP: Vec<Regex> = vec![
        Regex::new(r"^\(").unwrap(),
        Regex::new(r"^\)").unwrap(),
        Regex::new(r"^ ").unwrap(),
        Regex::new(r"^[\w+]+").unwrap(),
    ];
    // Matches the pipe character and everything after it (the aggregation part of a condition).
    pub static ref RE_PIPE: Regex = Regex::new(r"\|.*").unwrap();
    // Regular expression matching "all of selection*" and "1 of selection*".
    pub static ref OF_SELECTION: Regex = Regex::new(r"(all|1) of ([^*]+)\*").unwrap();
}

#[derive(Debug, Clone)]
/// Tokens appearing during lexical analysis of a condition expression.
pub enum ConditionToken {
    LeftParenthesis,
    RightParenthesis,
    Space,
    Not,
    And,
    Or,
    SelectionReference(String),

    // Pseudo tokens created to facilitate processing during parsing.
    ParenthesisContainer(Box<ConditionToken>), // Token representing a parenthesized subexpression.
    AndContainer(IntoIter<ConditionToken>),    // Token to group conditions connected by AND.
    OrContainer(IntoIter<ConditionToken>),     // Token to group conditions connected by OR.
    NotContainer(Box<ConditionToken>), // Token grouping a NOT and the expression it negates.
}

impl ConditionToken {
    /// Converts this ConditionToken into a SelectionNode. `name_to_node` maps the selection names
    /// defined in the rule's detection section to their parsed selection nodes.
    pub fn into_selection_node(
        self,
        name_to_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        match self {
            ConditionToken::SelectionReference(selection_name) => {
                let selection_node = name_to_node.get(&selection_name);
                if let Some(select_node) = selection_node {
                    let selection_node = select_node;
                    let selection_node = Arc::clone(selection_node);
                    let ref_node = RefSelectionNode::new(selection_node);
                    Result::Ok(Box::new(ref_node))
                } else {
                    let err_msg = format!("{selection_name} is not defined.");
                    Result::Err(err_msg)
                }
            }
            ConditionToken::ParenthesisContainer(sub_token) => {
                Result::Ok((*sub_token).into_selection_node(name_to_node)?)
            }
            ConditionToken::AndContainer(sub_tokens) => {
                let mut select_and_node = AndSelectionNode::new();
                for sub_token in sub_tokens {
                    let sub_node = sub_token.into_selection_node(name_to_node)?;
                    select_and_node.child_nodes.push(sub_node);
                }
                Result::Ok(Box::new(select_and_node))
            }
            ConditionToken::OrContainer(sub_tokens) => {
                let mut select_or_node = OrSelectionNode::new();
                for sub_token in sub_tokens {
                    let sub_node = sub_token.into_selection_node(name_to_node)?;
                    select_or_node.child_nodes.push(sub_node);
                }
                Result::Ok(Box::new(select_or_node))
            }
            ConditionToken::NotContainer(sub_token) => {
                let select_sub_node = sub_token.into_selection_node(name_to_node)?;
                let select_not_node = NotSelectionNode::new(select_sub_node);
                Result::Ok(Box::new(select_not_node))
            }
            // The raw lexer tokens below should all have been consumed while parsing, so reaching
            // them here is an internal error.
            ConditionToken::LeftParenthesis => Result::Err("Unknown error".to_string()),
            ConditionToken::RightParenthesis => Result::Err("Unknown error".to_string()),
            ConditionToken::Space => Result::Err("Unknown error".to_string()),
            ConditionToken::Not => Result::Err("Unknown error".to_string()),
            ConditionToken::And => Result::Err("Unknown error".to_string()),
            ConditionToken::Or => Result::Err("Unknown error".to_string()),
        }
    }

    /// Converts a lexed string into its ConditionToken. Anything that is not an operator,
    /// a parenthesis or a space is treated as a selection name reference.
    pub fn to_condition_token(token: &str) -> ConditionToken {
        if token == "(" {
            ConditionToken::LeftParenthesis
        } else if token == ")" {
            ConditionToken::RightParenthesis
        } else if token == " " {
            ConditionToken::Space
        } else if token == "not" {
            ConditionToken::Not
        } else if token == "and" {
            ConditionToken::And
        } else if token == "or" {
            ConditionToken::Or
        } else {
            ConditionToken::SelectionReference(token.to_string())
        }
    }
}

/// Compiles the condition expression of a rule's detection section into a SelectionNode tree.
#[derive(Debug)]
pub struct ConditionCompiler {}

impl ConditionCompiler {
    pub fn new() -> Self {
        ConditionCompiler {}
    }

    /// Compiles a condition string into a SelectionNode tree. `name_to_node` maps the selection
    /// names defined in the rule's detection section to their parsed selection nodes.
    pub fn compile_condition(
        &self,
        condition_str: &str,
        name_to_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        let node_keys: Vec<String> = name_to_node.keys().cloned().collect();
        let condition_str = Self::convert_condition(condition_str, &node_keys);
        // The aggregation part after a pipe (e.g. "| count() >= 1") is parsed elsewhere
        // (see aggregation_parser.rs), so strip it here.
        let captured = self::RE_PIPE.captures(condition_str.as_str());
        let replaced_condition = if let Some(cap) = captured {
            let captured = cap.get(0).unwrap().as_str();
            condition_str.replace(captured, "")
        } else {
            condition_str.to_string()
        };

        let result = self.compile_condition_body(&replaced_condition, name_to_node);
        if let Result::Err(msg) = result {
            Result::Err(format!("A condition parse error has occurred. {msg}"))
        } else {
            result
        }
    }

    /// Expands the Sigma "all of selection*" and "1 of selection*" syntax into plain and/or
    /// expressions over every selection name starting with the given prefix, e.g.
    /// "all of selection*" becomes "(selection1 and selection2 and ...)".
    pub fn convert_condition(condition_str: &str, node_keys: &[String]) -> String {
        let mut converted_str = condition_str.to_string();
        for matched in OF_SELECTION.find_iter(condition_str) {
            let match_str: &str = matched.as_str();
            let sep = if match_str.starts_with("all") {
                " and "
            } else {
                " or "
            };
            let target_node_key_prefix = match_str
                .replace('*', "")
                .replace("all of ", "")
                .replace("1 of ", "");
            let replaced_condition = node_keys
                .iter()
                .filter(|x| x.starts_with(target_node_key_prefix.as_str()))
                .join(sep);
            converted_str =
                converted_str.replace(match_str, format!("({replaced_condition})").as_str())
        }
        converted_str
    }

    /// Creates a SelectionNode from the given Condition.
    fn compile_condition_body(
        &self,
        condition_str: &str,
        name_to_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        let tokens = self.tokenize(condition_str)?;

        let parsed = self.parse(tokens.into_iter())?;

        parsed.into_selection_node(name_to_node)
    }

    /// Executes syntactic analysis.
    fn parse(&self, tokens: IntoIter<ConditionToken>) -> Result<ConditionToken, String> {
        // Analyze sections enclosed in parentheses.
        let tokens = self.parse_parenthesis(tokens)?;

        // Parse And and Or.
        self.parse_and_or_operator(tokens)
    }

    /// Performs lexical analysis.
    fn tokenize(&self, condition_str: &str) -> Result<Vec<ConditionToken>, String> {
        let mut cur_condition_str = condition_str;

        let mut tokens = Vec::new();
        while !cur_condition_str.is_empty() {
            let captured = self::CONDITION_REGEXMAP
                .iter()
                .find_map(|regex| regex.captures(cur_condition_str));
            if captured.is_none() {
                // Every character of a valid condition must match one of the token regexes, so
                // failing to match means the condition contains an unusable character.
                return Result::Err("An unusable character was found.".to_string());
            }

            let matched_str = captured.unwrap().get(0).unwrap().as_str();
            let token = ConditionToken::to_condition_token(matched_str);
            if let ConditionToken::Space = token {
                // Whitespace has no special meaning, so skip it.
                cur_condition_str = &cur_condition_str[matched_str.len()..];
                continue;
            }

            tokens.push(token);
            cur_condition_str = &cur_condition_str[matched_str.len()..];
        }

        Result::Ok(tokens)
    }

    /// Parses only the parentheses. The returned array contains no LeftParenthesis or
    /// RightParenthesis tokens; each parenthesized section is recursively parsed and replaced
    /// with a single ParenthesisContainer token.
    fn parse_parenthesis(
        &self,
        mut tokens: IntoIter<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        while let Some(token) = tokens.next() {
            // First, look for a left parenthesis.
            let is_left = matches!(token, ConditionToken::LeftParenthesis);
            if !is_left {
                ret.push(token);
                continue;
            }

            // If a left parenthesis is found, find the corresponding right parenthesis.
            let mut left_cnt = 1;
            let mut right_cnt = 0;
            let mut sub_tokens = vec![];
            for token in tokens.by_ref() {
                if let ConditionToken::LeftParenthesis = token {
                    left_cnt += 1;
                } else if let ConditionToken::RightParenthesis = token {
                    right_cnt += 1;
                }
                if left_cnt == right_cnt {
                    break;
                }
                sub_tokens.push(token);
            }
            // Reaching the end without finding a matching right parenthesis.
            if left_cnt != right_cnt {
                return Result::Err("')' was expected but not found.".to_string());
            }

            // Recursively parse the tokens inside the parentheses.
            let parsed_sub_token = self.parse(sub_tokens.into_iter())?;
            let parenthesis_token =
                ConditionToken::ParenthesisContainer(Box::new(parsed_sub_token));
            ret.push(parenthesis_token);
        }

        // If right parentheses remain at this point, there are more right parentheses than left.
        let is_right_left = ret
            .iter()
            .any(|token| matches!(token, ConditionToken::RightParenthesis));
        if is_right_left {
            return Result::Err("'(' was expected but not found.".to_string());
        }

        Result::Ok(ret)
    }

    /// Parses AND and OR operators. AND binds tighter than OR: runs of AND-connected operands
    /// are grouped into AndContainers first, and the resulting groups are then combined with an
    /// OrContainer.
    fn parse_and_or_operator(&self, tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        if tokens.is_empty() {
            // Must not be called with length 0.
            return Result::Err("Unknown error.".to_string());
        }

        // First, collapse each operand between the logical operators into a single token; e.g. in
        // "selection1 and not selection2", both "selection1" and "not selection2" become one
        // token each.
        let tokens = self.to_operand_container(tokens)?;

        // AND/OR at the beginning or end is invalid.
        if self.is_logical(&tokens[0]) || self.is_logical(&tokens[tokens.len() - 1]) {
            return Result::Err("An illegal logical operator(and, or) was found.".to_string());
        }

        // Operands and logical operators (And/Or) must alternate, so split them into their
        // respective lists while verifying the alternation.
        let mut operand_list = vec![];
        let mut operator_list = vec![];
        for (i, token) in tokens.into_iter().enumerate() {
            if (i % 2 == 1) != self.is_logical(&token) {
                // Operands must sit at even indices and logical operators at odd indices.
                return Result::Err(
                    "The use of a logical operator(and, or) was wrong.".to_string(),
                );
            }

            if i % 2 == 0 {
                operand_list.push(token);
            } else {
                operator_list.push(token);
            }
        }

        // First, group all parts connected by AND.
        let mut operand_ite = operand_list.into_iter();
        let mut operands = vec![];
        let mut and_groups = vec![];
        operator_list.push(ConditionToken::Or); // sentinel Or to flush the final AND group
        for token in operator_list.iter() {
            if let ConditionToken::Or = token {
                if and_groups.is_empty() {
                    operands.push(operand_ite.next().unwrap());
                } else {
                    and_groups.push(operand_ite.next().unwrap());
                    operands.push(ConditionToken::AndContainer(and_groups.into_iter()));
                }
                and_groups = vec![];
            } else {
                and_groups.push(operand_ite.next().unwrap());
            }
        }

        if operands.len() == 1 {
            return Result::Ok(operands.into_iter().next().unwrap());
        }
        // Next, group parts connected by OR.
        Result::Ok(ConditionToken::OrContainer(operands.into_iter()))
    }

    /// Parses one operand group (the tokens between two logical operators). Currently this only
    /// needs to handle an optional leading Not.
    fn parse_operand_container(sub_tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        // Currently, in the NOT case, there should be two items: "not" and "the name of the
        // selection node negated by not".
        // If there is no NOT, there should be only one item: "the name of the selection node".

        // As stated above, there should never be three or more items.
        if sub_tokens.len() >= 3 {
            return Result::Err(
                "Unknown error. Maybe it is because there are multiple names of selection nodes."
                    .to_string(),
            );
        }

        // An empty group should be impossible.
        if sub_tokens.is_empty() {
            return Result::Err("Unknown error.".to_string());
        }

        // With only one token, it must not be a Not (a lone "not" has nothing to negate).
        if sub_tokens.len() == 1 {
            let operand_subtoken = sub_tokens.into_iter().next().unwrap();
            if let ConditionToken::Not = operand_subtoken {
                return Result::Err("An illegal not was found.".to_string());
            }

            return Result::Ok(operand_subtoken);
        }

        // If there are two items, the first should be Not and the next should be something that
        // is not Not.
        let mut sub_ite = sub_tokens.into_iter();
        let first_token = sub_ite.next().unwrap();
        let second_token = sub_ite.next().unwrap();
        if let ConditionToken::Not = first_token {
            if let ConditionToken::Not = second_token {
                Result::Err("Not is continuous.".to_string())
            } else {
                let not_container = ConditionToken::NotContainer(Box::new(second_token));
                Result::Ok(not_container)
            }
        } else {
            Result::Err(
                "Unknown error. Maybe it is because there are multiple names of selection nodes."
                    .to_string(),
            )
        }
    }

    /// Returns true if the ConditionToken is an And or Or token.
    fn is_logical(&self, token: &ConditionToken) -> bool {
        matches!(token, ConditionToken::And | ConditionToken::Or)
    }

    /// Collapses each run of consecutive non-operator tokens into a single operand token, so the
    /// result alternates between operands and logical operators (And/Or).
    fn to_operand_container(
        &self,
        tokens: Vec<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        // Tokens between two logical operators, i.e. one operand when And/Or are viewed as
        // operators.
        let mut grouped_operands = vec![];
        for token in tokens.into_iter() {
            if self.is_logical(&token) {
                // A logical operator with no preceding operand is really an error, but
                // parse_and_or_operator reports it later, so just pass the token through here.
                if grouped_operands.is_empty() {
                    ret.push(token);
                    continue;
                }

                ret.push(ConditionCompiler::parse_operand_container(
                    grouped_operands,
                )?);
                ret.push(token);
                grouped_operands = vec![];
                continue;
            }

            grouped_operands.push(token);
        }
        if !grouped_operands.is_empty() {
            ret.push(ConditionCompiler::parse_operand_container(
                grouped_operands,
            )?);
        }

        Result::Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::configs::{
        Action, Config, CsvOutputOption, OutputOption, STORED_EKEY_ALIAS, StoredStatic,
    };
    use crate::detections::rule::condition_parser::ConditionCompiler;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::tests::parse_rule_from_str;
    use crate::detections::{self, utils};
    use yaml_rust2::YamlLoader;

    // Minimal event record shared by most of the tests in this module.
    const SIMPLE_RECORD_STR: &str = r#"
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

    fn check_rule_parse_error(rule_str: &str, errmsgs: Vec<String>) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(rule_node.init(&create_dummy_stored_static()), Err(errmsgs));
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
    fn test_no_condition() {
        // Verify that parsing succeeds when there is only one selection even without a condition expression.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
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
    fn test_no_condition_notdetect() {
        // Verify that parsing succeeds when there is only one selection even without a condition expression.
        // This is a non-detection pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7041
                param1: 'Windows Event Log'
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

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_condition_and_detect() {
        // Test for patterns using and in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_and_notdetect() {
        // Test for patterns using and in condition.
        // This is a non-hit pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_and_notdetect2() {
        // Test for patterns using and in condition.
        // This is a non-hit pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_and_detect3() {
        // Test for patterns using and in condition.
        // This is a non-hit pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_and_notdetect4() {
        // Test for patterns using and in condition.
        // This is a non-hit pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_and_notdetect5() {
        // Test for patterns using and in condition.
        // This is a non-hit pattern.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_or_detect() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect2() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect3() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect4() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect5() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect6() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_detect7() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_or_notdetect() {
        // Test for patterns using or in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_not_detect() {
        // Test for patterns using not in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            condition: not selection1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_not_notdetect() {
        // Test for patterns using not in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: not selection1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_parenthesis_detect() {
        // Test using parentheses in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (selection2 or selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_parenthesis_not_detect() {
        // Test using parentheses in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (selection2 and selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_many_parenthesis_detect() {
        // Test using many parentheses in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (((selection2 or selection3)))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_manyparenthesis_not_detect() {
        // Test using many parentheses in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and ((((selection2 and selection3))))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_notparenthesis_detect() {
        // Test combining parentheses and not in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and not ((selection2 and selection3))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_notparenthesis_notdetect() {
        // Test combining parentheses and not in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and not (not(selection2 and selection3))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_manyparenthesis_detect2() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and (selection2 or selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_manyparenthesis_notdetect2() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and (selection2 and selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_manyparenthesis_detect3() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 and selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_manyparenthesis_notdetect3() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 and selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_manyparenthesis_detect4() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 or selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_manyparenthesis_notdetect4() {
        // Cases using various parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto startn'
            condition: (selection1 and (selection2 and ( selection3 or selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_rule_parseerror_no_condition() {
        // Having multiple selections without a condition is an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(&create_dummy_stored_static()),
            Err(vec![
                "There is no condition node under detection.".to_string()
            ])
        );
    }

    #[test]
    fn test_condition_err_condition_forbid_character() {
        // The condition contains a character that cannot be tokenized (the hyphen in
        // "selection-1").
        let rule_str = r#"
        enabled: true
        detection:
            selection-1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection-1 and selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. An unusable character was found."
                    .to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_leftparenthesis_over() {
        // Too many left parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and ((selection2)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. ')' was expected but not found.".to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_rightparenthesis_over() {
        // Too many right parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and (selection2))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. '(' was expected but not found.".to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_parenthesis_direction_wrong() {
        // Wrong direction of parentheses.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and )selection2(
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. ')' was expected but not found.".to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_no_logical() {
        // Using two selection names not connected by AND or OR is an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(rule_str,vec!["A condition parse error has occurred. Unknown error. Maybe it is because there are multiple names of selection nodes.".to_string()]);
    }

    #[test]
    fn test_condition_err_first_logical() {
        // A logical operator at the beginning of the condition is an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: and selection1 or selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. An illegal logical operator(and, or) was found."
                    .to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_last_logical() {
        // A logical operator at the end of the condition is an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "A condition parse error has occurred. An illegal logical operator(and, or) was found."
                    .to_string(),
            ],
        );
    }

    #[test]
    fn test_condition_err_consecutive_logical() {
        // Consecutive logical operators are an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or or selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(rule_str,vec!["A condition parse error has occurred. The use of a logical operator(and, or) was wrong.".to_string()]);
    }

    #[test]
    fn test_condition_err_only_not() {
        // A not without an operand is an error.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or ( not )
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["A condition parse error has occurred. An illegal not was found.".to_string()],
        );
    }

    #[test]
    fn test_condition_err_not_not() {
        // Consecutive nots are not allowed.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or ( not not )
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["A condition parse error has occurred. Not is continuous.".to_string()],
        );
    }

    #[test]
    fn test_convert_condition_all_of_selection() {
        let condition = "all of selection*";

        let keys = vec!["selection1".to_string(), "selection2".to_string()];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 and selection2)".to_string();
        assert_eq!(result, expected);

        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "selection3".to_string(),
        ];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 and selection2 and selection3)".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_condition_multiple_all_of_selection() {
        let condition = "all of selection* and all of filter*";

        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "filter1".to_string(),
            "filter2".to_string(),
        ];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 and selection2) and (filter1 and filter2)".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_condition_one_of_selection() {
        let condition = "1 of selection*";

        let keys = vec!["selection1".to_string(), "selection2".to_string()];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 or selection2)".to_string();
        assert_eq!(result, expected);

        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "selection3".to_string(),
        ];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 or selection2 or selection3)".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_condition_multiple_one_of_selection() {
        let condition = "1 of selection* and 1 of filter*";
        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "filter1".to_string(),
            "filter2".to_string(),
        ];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected = "(selection1 or selection2) and (filter1 or filter2)".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_condition_convert_complex_condition() {
        let condition = "all of selection* and test1 or test2 or 1 of filter*";
        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "test".to_string(),
            "filter1".to_string(),
            "filter2".to_string(),
        ];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        let expected =
            "(selection1 and selection2) and test1 or test2 or (filter1 or filter2)".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_condition_not_convert() {
        let condition = "selection1 and selection2";
        let keys = vec!["selection1".to_string(), "selection2".to_string()];
        let result = ConditionCompiler::convert_condition(condition, &keys);
        assert_eq!(result, condition);
    }

    #[test]
    fn test_condition_1_of_select_detect() {
        // Test for patterns using "1 of selection*" in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: 1 of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_1_of_select_not_detect() {
        // Test for patterns using "1 of selection*" in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'NODETECT'
            selection2:
                EventID: 9999
            selection3:
                param1: 'NODETECT'
            condition: 1 of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_all_of_select_detect() {
        // Test for patterns using "all of selection*" in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: all of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, true);
    }

    #[test]
    fn test_condition_all_of_select_not_detect() {
        // Test for patterns using "all of selection*" in condition.
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'NOTDETECT'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: all of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_select(rule_str, SIMPLE_RECORD_STR, false);
    }

    #[test]
    fn test_condition_complex_of_selection() {
        let rule_str = |condition: &str| {
            format!(
                r#"
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7045
            suspicious1:
                ImagePath|contains:
                    - 'A'
                    - 'B'
            suspicious2a:
                ImagePath|contains: 'C'
            suspicious2b:
                ImagePath|contains:
                    - 'D'
                    - 'E'
            filter_thor_remote:
                ImagePath|startswith: 'F'
            filter_defender_def_updates:
                ImagePath|startswith: 'G'
            condition:
                {condition}
        "#
            )
        };

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7045,
              "Channel": "System"
            },
            "EventData": {
              "ImagePath": "A B C D E F G"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let case0 = "selection and all of suspicious2* and not 1 of filter_*";
        let case1 = "selection and ( suspicious1 or all of suspicious2* ) and not 1 of filter_*";
        let case2 = "selection and ( suspicious1 or all of suspicious2* ) and 1 of filter_*";
        let case3 =
            "selection and not ( suspicious1 or all of suspicious2* ) and not 1 of filter_*";
        let case4 = "selection and not ( suspicious1 or all of suspicious2* ) and 1 of filter_*";
        let case5 = "selection and ( suspicious1 and not all of suspicious2* ) and 1 of filter_*";

        check_select(rule_str(case0).as_str(), record_json_str, true);
        check_select(rule_str(case1).as_str(), record_json_str, true);
        check_select(rule_str(case2).as_str(), record_json_str, false);
        check_select(rule_str(case3).as_str(), record_json_str, false);
        check_select(rule_str(case4).as_str(), record_json_str, false);
        check_select(rule_str(case5).as_str(), record_json_str, false);
    }
}

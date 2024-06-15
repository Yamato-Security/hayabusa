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
    pub static ref CONDITION_REGEXMAP: Vec<Regex> = vec![
        Regex::new(r"^\(").unwrap(),
        Regex::new(r"^\)").unwrap(),
        Regex::new(r"^ ").unwrap(),
        Regex::new(r"^\w+").unwrap(),
    ];
    pub static ref RE_PIPE: Regex = Regex::new(r"\|.*").unwrap();
    // all of selection* と 1 of selection* にマッチする正規表現
    pub static ref OF_SELECTION: Regex = Regex::new(r"(all|1) of ([^*]+)\*").unwrap();
}

#[derive(Debug, Clone)]
/// 字句解析で出てくるトークン
pub enum ConditionToken {
    LeftParenthesis,
    RightParenthesis,
    Space,
    Not,
    And,
    Or,
    SelectionReference(String),

    // パースの時に上手く処理するために作った疑似的なトークン
    ParenthesisContainer(Box<ConditionToken>), // 括弧を表すトークン
    AndContainer(IntoIter<ConditionToken>),    // ANDでつながった条件をまとめるためのトークン
    OrContainer(IntoIter<ConditionToken>),     // ORでつながった条件をまとめるためのトークン
    NotContainer(Box<ConditionToken>), // 「NOT」と「NOTで否定される式」をまとめるためのトークン この配列には要素が一つしか入らないが、他のContainerと同じように扱えるようにするためにVecにしている。あんまり良くない。
}

impl ConditionToken {
    /// convert from ConditionToken into SelectionNode
    pub fn into_selection_node(
        self,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        return match self {
            ConditionToken::SelectionReference(selection_name) => {
                let selection_node = name_2_node.get(&selection_name);
                if let Some(select_node) = selection_node {
                    let selection_node = select_node;
                    let selection_node = Arc::clone(selection_node);
                    let ref_node = RefSelectionNode::new(selection_node);
                    return Result::Ok(Box::new(ref_node));
                } else {
                    let err_msg = format!("{selection_name} is not defined.");
                    return Result::Err(err_msg);
                }
            }
            ConditionToken::ParenthesisContainer(sub_token) => {
                Result::Ok((*sub_token).into_selection_node(name_2_node)?)
            }
            ConditionToken::AndContainer(sub_tokens) => {
                let mut select_and_node = AndSelectionNode::new();
                for sub_token in sub_tokens {
                    let sub_node = sub_token.into_selection_node(name_2_node)?;
                    select_and_node.child_nodes.push(sub_node);
                }
                return Result::Ok(Box::new(select_and_node));
            }
            ConditionToken::OrContainer(sub_tokens) => {
                let mut select_or_node = OrSelectionNode::new();
                for sub_token in sub_tokens {
                    let sub_node = sub_token.into_selection_node(name_2_node)?;
                    select_or_node.child_nodes.push(sub_node);
                }
                return Result::Ok(Box::new(select_or_node));
            }
            ConditionToken::NotContainer(sub_token) => {
                let select_sub_node = sub_token.into_selection_node(name_2_node)?;
                let select_not_node = NotSelectionNode::new(select_sub_node);
                return Result::Ok(Box::new(select_not_node));
            }
            ConditionToken::LeftParenthesis => Result::Err("Unknown error".to_string()),
            ConditionToken::RightParenthesis => Result::Err("Unknown error".to_string()),
            ConditionToken::Space => Result::Err("Unknown error".to_string()),
            ConditionToken::Not => Result::Err("Unknown error".to_string()),
            ConditionToken::And => Result::Err("Unknown error".to_string()),
            ConditionToken::Or => Result::Err("Unknown error".to_string()),
        };
    }

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

#[derive(Debug)]
pub struct ConditionCompiler {}

// conditionの式を読み取るクラス。
impl ConditionCompiler {
    pub fn new() -> Self {
        ConditionCompiler {}
    }

    pub fn compile_condition(
        &self,
        condition_str: &str,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        let node_keys: Vec<String> = name_2_node.keys().cloned().collect();
        let condition_str = Self::convert_condition(condition_str, &node_keys);
        // パイプはここでは処理しない
        let captured = self::RE_PIPE.captures(condition_str.as_str());
        let replaced_condition = if let Some(cap) = captured {
            let captured = cap.get(0).unwrap().as_str();
            condition_str.replace(captured, "")
        } else {
            condition_str.to_string()
        };

        let result = self.compile_condition_body(&replaced_condition, name_2_node);
        if let Result::Err(msg) = result {
            Result::Err(format!("A condition parse error has occurred. {msg}"))
        } else {
            result
        }
    }

    // all of selection* と 1 of selection* を通常のand/orに変換する
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
                converted_str.replace(match_str, format!("({})", replaced_condition).as_str())
        }
        converted_str
    }

    /// 与えたConditionからSelectionNodeを作る
    fn compile_condition_body(
        &self,
        condition_str: &str,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode>>>,
    ) -> Result<Box<dyn SelectionNode>, String> {
        let tokens = self.tokenize(condition_str)?;

        let parsed = self.parse(tokens.into_iter())?;

        parsed.into_selection_node(name_2_node)
    }

    /// 構文解析を実行する。
    fn parse(&self, tokens: IntoIter<ConditionToken>) -> Result<ConditionToken, String> {
        // 括弧で囲まれた部分を解析します。
        let tokens = self.parse_parenthesis(tokens)?;

        // AndとOrをパースする。
        self.parse_and_or_operator(tokens)
    }

    /// 字句解析を行う
    fn tokenize(&self, condition_str: &str) -> Result<Vec<ConditionToken>, String> {
        let mut cur_condition_str = condition_str;

        let mut tokens = Vec::new();
        while !cur_condition_str.is_empty() {
            let captured = self::CONDITION_REGEXMAP.iter().find_map(|regex| {
                return regex.captures(cur_condition_str);
            });
            if captured.is_none() {
                // トークンにマッチしないのはありえないという方針でパースしています。
                return Result::Err("An unusable character was found.".to_string());
            }

            let matched_str = captured.unwrap().get(0).unwrap().as_str();
            let token = ConditionToken::to_condition_token(matched_str);
            if let ConditionToken::Space = token {
                // 空白は特に意味ないので、読み飛ばす。
                cur_condition_str = &cur_condition_str[matched_str.len()..];
                continue;
            }

            tokens.push(token);
            cur_condition_str = &cur_condition_str[matched_str.len()..];
        }

        Result::Ok(tokens)
    }

    /// 右括弧と左括弧をだけをパースする。戻り値の配列にはLeftParenthesisとRightParenthesisが含まれず、代わりにTokenContainerに変換される。TokenContainerが括弧で囲まれた部分を表現している。
    fn parse_parenthesis(
        &self,
        mut tokens: IntoIter<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        while let Some(token) = tokens.next() {
            // まず、左括弧を探す。
            let is_left = matches!(token, ConditionToken::LeftParenthesis);
            if !is_left {
                ret.push(token);
                continue;
            }

            // 左括弧が見つかったら、対応する右括弧を見つける。
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
            // 最後までついても対応する右括弧が見つからないことを表している
            if left_cnt != right_cnt {
                return Result::Err("')' was expected but not found.".to_string());
            }

            // ここで再帰的に呼び出す。
            let parsed_sub_token = self.parse(sub_tokens.into_iter())?;
            let parenthesis_token =
                ConditionToken::ParenthesisContainer(Box::new(parsed_sub_token));
            ret.push(parenthesis_token);
        }

        // この時点で右括弧が残っている場合は右括弧の数が左括弧よりも多いことを表している。
        let is_right_left = ret
            .iter()
            .any(|token| matches!(token, ConditionToken::RightParenthesis));
        if is_right_left {
            return Result::Err("'(' was expected but not found.".to_string());
        }

        Result::Ok(ret)
    }

    /// AND, ORをパースする。
    fn parse_and_or_operator(&self, tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        if tokens.is_empty() {
            // 長さ0は呼び出してはいけない
            return Result::Err("Unknown error.".to_string());
        }

        // まず、selection1 and not selection2みたいな式のselection1やnot selection2のように、ANDやORでつながるトークンをまとめる。
        let tokens = self.to_operand_container(tokens)?;

        // 先頭又は末尾がAND/ORなのはだめ
        if self.is_logical(&tokens[0]) || self.is_logical(&tokens[tokens.len() - 1]) {
            return Result::Err("An illegal logical operator(and, or) was found.".to_string());
        }

        // OperandContainerとLogicalOperator(AndとOR)が交互に並んでいるので、それぞれリストに投入
        let mut operand_list = vec![];
        let mut operator_list = vec![];
        for (i, token) in tokens.into_iter().enumerate() {
            if (i % 2 == 1) != self.is_logical(&token) {
                // インデックスが奇数の時はLogicalOperatorで、インデックスが偶数のときはOperandContainerになる
                return Result::Err(
                    "The use of a logical operator(and, or) was wrong.".to_string(),
                );
            }

            if i % 2 == 0 {
                // ここで再帰的にAND,ORをパースする関数を呼び出す
                operand_list.push(token);
            } else {
                operator_list.push(token);
            }
        }

        // 先にANDでつながっている部分を全部まとめる
        let mut operand_ite = operand_list.into_iter();
        let mut operands = vec![];
        let mut and_grops = vec![];
        operator_list.push(ConditionToken::Or); // add "or token" as a sentinel
        for token in operator_list.iter() {
            if let ConditionToken::Or = token {
                if and_grops.is_empty() {
                    operands.push(operand_ite.next().unwrap());
                } else {
                    and_grops.push(operand_ite.next().unwrap());
                    operands.push(ConditionToken::AndContainer(and_grops.into_iter()));
                }
                and_grops = vec![];
            } else {
                and_grops.push(operand_ite.next().unwrap());
            }
        }

        if operands.len() == 1 {
            return Result::Ok(operands.into_iter().next().unwrap());
        }
        // 次にOrでつながっている部分をまとめる
        Result::Ok(ConditionToken::OrContainer(operands.into_iter()))
    }

    /// OperandContainerの中身をパースする。現状はNotをパースするためだけに存在している。
    fn parse_operand_container(sub_tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        // 現状ではNOTの場合は、「not」と「notで修飾されるselectionノードの名前」の2つ入っているはず
        // NOTが無い場合、「selectionノードの名前」の一つしか入っていないはず。

        // 上記の通り、3つ以上入っていることはないはず。
        if sub_tokens.len() >= 3 {
            return Result::Err(
                "Unknown error. Maybe it is because there are multiple names of selection nodes."
                    .to_string(),
            );
        }

        // 0はありえないはず
        if sub_tokens.is_empty() {
            return Result::Err("Unknown error.".to_string());
        }

        // 1つだけ入っている場合、NOTはありえない。
        if sub_tokens.len() == 1 {
            let operand_subtoken = sub_tokens.into_iter().next().unwrap();
            if let ConditionToken::Not = operand_subtoken {
                return Result::Err("An illegal not was found.".to_string());
            }

            return Result::Ok(operand_subtoken);
        }

        // ２つ入っている場合、先頭がNotで次はNotじゃない何かのはず
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

    /// ConditionTokenがAndまたはOrTokenならばTrue
    fn is_logical(&self, token: &ConditionToken) -> bool {
        matches!(token, ConditionToken::And | ConditionToken::Or)
    }

    /// ConditionToken::OperandContainerに変換できる部分があれば変換する。
    fn to_operand_container(
        &self,
        tokens: Vec<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        let mut grouped_operands = vec![]; // ANDとORの間にあるトークンを表す。ANDとORをOperatorとしたときのOperand
        for token in tokens.into_iter() {
            if self.is_logical(&token) {
                // ここに来るのはエラーのはずだが、後でエラー出力するので、ここではエラー出さない。
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
        Action, CommonOptions, Config, CsvOutputOption, DetectCommonOption, InputOption,
        OutputOption, StoredStatic, STORED_EKEY_ALIAS,
    };
    use crate::detections::rule::condition_parser::ConditionCompiler;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::tests::parse_rule_from_str;
    use crate::detections::{self, utils};
    use std::path::Path;
    use yaml_rust::YamlLoader;

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
        // condition式が無くても、selectionが一つだけなら、正しくパースできることを確認
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
        // condition式が無くても、selectionが一つだけなら、正しくパースできることを確認
        // これは検知しないパターン
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
        // conditionにandを使ったパターンのテスト
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
        // conditionにandを使ったパターンのテスト
        // これはHitしないパターン
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
        // conditionにandを使ったパターンのテスト
        // これはHitしないパターン
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
        // conditionにandを使ったパターンのテスト
        // これはHitしないパターン
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
        // conditionにandを使ったパターンのテスト
        // これはHitしないパターン
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
        // conditionにandを使ったパターンのテスト
        // これはHitしないパターン
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにorを使ったパターンのテスト
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
        // conditionにnotを使ったパターンのテスト
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
        // conditionにnotを使ったパターンのテスト
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
        // conditionに括弧を使ったテスト
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
        // conditionに括弧を使ったテスト
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
        // conditionに括弧を沢山使ったテスト
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
        // conditionに括弧を沢山使ったテスト
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
        // conditionに括弧を沢山使ったテスト
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
        // conditionに括弧とnotを組み合わせたテスト
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
        // 括弧を色々使ったケース
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
        // 括弧を色々使ったケース
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
        // 括弧を色々使ったケース
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
        // 括弧を色々使ったケース
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
        // 括弧を色々使ったケース
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
        // 括弧を色々使ったケース
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
        // selectionが複数あるのにconditionが無いのはエラー
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
    fn test_condition_err_condition_forbit_character() {
        // conditionに読み込めない文字が指定されている。
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
        // 左括弧が多い
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
        // 右括弧が多い
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
        // 括弧の向きが違う
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
        // ANDとかORで結合してない
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
        //
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
        //
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
        //
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
        //
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
        // notが続くのはだめ
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
        // conditionに 1 of selection* を使ったパターンのテスト
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
        // conditionに 1 of selection* を使ったパターンのテスト
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
        // conditionに all of selection* を使ったパターンのテスト
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
        // conditionに all of selection* を使ったパターンのテスト
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

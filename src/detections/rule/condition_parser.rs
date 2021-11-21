use regex::Regex;

use self::selectionnodes::{
    AndSelectionNode, NotSelectionNode, OrSelectionNode, RefSelectionNode, SelectionNode,
};
use super::selectionnodes;
use std::{collections::HashMap, sync::Arc};

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
    ParenthesisContainer(Vec<ConditionToken>), // 括弧を表すトークン
    AndContainer(Vec<ConditionToken>),         // ANDでつながった条件をまとめるためのトークン
    OrContainer(Vec<ConditionToken>),          // ORでつながった条件をまとめるためのトークン
    NotContainer(Vec<ConditionToken>), // 「NOT」と「NOTで否定される式」をまとめるためのトークン この配列には要素が一つしか入らないが、他のContainerと同じように扱えるようにするためにVecにしている。あんまり良くない。
    OperandContainer(Vec<ConditionToken>), // ANDやORやNOT等の演算子に対して、非演算子を表す
}

// ここを参考にしました。https://qiita.com/yasuo-ozu/items/7ce2f8ff846ba00dd244
impl IntoIterator for ConditionToken {
    type Item = ConditionToken;
    type IntoIter = std::vec::IntoIter<ConditionToken>;

    fn into_iter(self) -> Self::IntoIter {
        let v = match self {
            ConditionToken::ParenthesisContainer(sub_tokens) => sub_tokens,
            ConditionToken::AndContainer(sub_tokens) => sub_tokens,
            ConditionToken::OrContainer(sub_tokens) => sub_tokens,
            ConditionToken::NotContainer(sub_tokens) => sub_tokens,
            ConditionToken::OperandContainer(sub_tokens) => sub_tokens,
            _ => vec![],
        };
        v.into_iter()
    }
}

impl ConditionToken {
    fn replace_subtoken(&self, sub_tokens: Vec<ConditionToken>) -> ConditionToken {
        return match self {
            ConditionToken::ParenthesisContainer(_) => {
                ConditionToken::ParenthesisContainer(sub_tokens)
            }
            ConditionToken::AndContainer(_) => ConditionToken::AndContainer(sub_tokens),
            ConditionToken::OrContainer(_) => ConditionToken::OrContainer(sub_tokens),
            ConditionToken::NotContainer(_) => ConditionToken::NotContainer(sub_tokens),
            ConditionToken::OperandContainer(_) => ConditionToken::OperandContainer(sub_tokens),
            ConditionToken::LeftParenthesis => ConditionToken::LeftParenthesis,
            ConditionToken::RightParenthesis => ConditionToken::RightParenthesis,
            ConditionToken::Space => ConditionToken::Space,
            ConditionToken::Not => ConditionToken::Not,
            ConditionToken::And => ConditionToken::And,
            ConditionToken::Or => ConditionToken::Or,
            ConditionToken::SelectionReference(name) => {
                ConditionToken::SelectionReference(name.clone())
            }
        };
    }

    pub fn sub_tokens<'a>(&'a self) -> Vec<ConditionToken> {
        // TODO ここでcloneを使わずに実装できるようにしたい。
        return match self {
            ConditionToken::ParenthesisContainer(sub_tokens) => sub_tokens.clone(),
            ConditionToken::AndContainer(sub_tokens) => sub_tokens.clone(),
            ConditionToken::OrContainer(sub_tokens) => sub_tokens.clone(),
            ConditionToken::NotContainer(sub_tokens) => sub_tokens.clone(),
            ConditionToken::OperandContainer(sub_tokens) => sub_tokens.clone(),
            ConditionToken::LeftParenthesis => vec![],
            ConditionToken::RightParenthesis => vec![],
            ConditionToken::Space => vec![],
            ConditionToken::Not => vec![],
            ConditionToken::And => vec![],
            ConditionToken::Or => vec![],
            ConditionToken::SelectionReference(_) => vec![],
        };
    }

    pub fn sub_tokens_without_parenthesis<'a>(&'a self) -> Vec<ConditionToken> {
        return match self {
            ConditionToken::ParenthesisContainer(_) => vec![],
            _ => self.sub_tokens(),
        };
    }
}

#[derive(Debug)]
pub struct ConditionCompiler {
    regex_patterns: Vec<Regex>,
}

// conditionの式を読み取るクラス。
impl ConditionCompiler {
    pub fn new() -> Self {
        // ここで字句解析するときに使う正規表現の一覧を定義する。
        let mut regex_patterns = vec![];
        regex_patterns.push(Regex::new(r"^\(").unwrap());
        regex_patterns.push(Regex::new(r"^\)").unwrap());
        regex_patterns.push(Regex::new(r"^ ").unwrap());
        // ^\w+については、sigmaのソースのsigma/tools/sigma/parser/condition.pyのSigmaConditionTokenizerを参考にしている。
        // 上記ソースの(SigmaConditionToken.TOKEN_ID,     re.compile("[\\w*]+")),を参考。
        regex_patterns.push(Regex::new(r"^\w+").unwrap());

        return ConditionCompiler {
            regex_patterns: regex_patterns,
        };
    }

    pub fn compile_condition(
        &self,
        condition_str: String,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode + Send + Sync>>>,
    ) -> Result<Box<dyn SelectionNode + Send + Sync>, String> {
        // パイプはここでは処理しない
        let re_pipe = Regex::new(r"\|.*").unwrap();
        let captured = re_pipe.captures(&condition_str);
        let condition_str = if captured.is_some() {
            let captured = captured.unwrap().get(0).unwrap().as_str().to_string();
            condition_str.replacen(&captured, "", 1)
        } else {
            condition_str
        };

        let result = self.compile_condition_body(condition_str, name_2_node);
        if let Result::Err(msg) = result {
            return Result::Err(format!("condition parse error has occured. {}", msg));
        } else {
            return result;
        }
    }

    /// 与えたConditionからSelectionNodeを作る
    fn compile_condition_body(
        &self,
        condition_str: String,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode + Send + Sync>>>,
    ) -> Result<Box<dyn SelectionNode + Send + Sync>, String> {
        let tokens = self.tokenize(&condition_str)?;

        let parsed = self.parse(tokens)?;

        return self.to_selectnode(parsed, name_2_node);
    }

    /// 構文解析を実行する。
    fn parse(&self, tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        // 括弧で囲まれた部分を解析します。
        // (括弧で囲まれた部分は後で解析するため、ここでは一時的にConditionToken::ParenthesisContainerに変換しておく)
        // 括弧の中身を解析するのはparse_rest_parenthesis()で行う。
        let tokens = self.parse_parenthesis(tokens)?;

        // AndとOrをパースする。
        let tokens = self.parse_and_or_operator(tokens)?;

        // OperandContainerトークンの中身をパースする。(現状、Notを解析するためだけにある。将来的に修飾するキーワードが増えたらここを変える。)
        let token = self.parse_operand_container(tokens)?;

        // 括弧で囲まれている部分を探して、もしあればその部分を再帰的に構文解析します。
        return self.parse_rest_parenthesis(token);
    }

    /// 括弧で囲まれている部分を探して、もしあればその部分を再帰的に構文解析します。
    fn parse_rest_parenthesis(&self, token: ConditionToken) -> Result<ConditionToken, String> {
        if let ConditionToken::ParenthesisContainer(sub_token) = token {
            let new_token = self.parse(sub_token)?;
            return Result::Ok(new_token);
        }

        let sub_tokens = token.sub_tokens();
        if sub_tokens.len() == 0 {
            return Result::Ok(token);
        }

        let mut new_sub_tokens = vec![];
        for sub_token in sub_tokens {
            let new_token = self.parse_rest_parenthesis(sub_token)?;
            new_sub_tokens.push(new_token);
        }
        return Result::Ok(token.replace_subtoken(new_sub_tokens));
    }

    /// 字句解析を行う
    fn tokenize(&self, condition_str: &String) -> Result<Vec<ConditionToken>, String> {
        let mut cur_condition_str = condition_str.clone();

        let mut tokens = Vec::new();
        while cur_condition_str.len() != 0 {
            let captured = self.regex_patterns.iter().find_map(|regex| {
                return regex.captures(cur_condition_str.as_str());
            });
            if captured.is_none() {
                // トークンにマッチしないのはありえないという方針でパースしています。
                return Result::Err("An unusable character was found.".to_string());
            }

            let mached_str = captured.unwrap().get(0).unwrap().as_str();
            let token = self.to_enum(mached_str.to_string());
            if let ConditionToken::Space = token {
                // 空白は特に意味ないので、読み飛ばす。
                cur_condition_str = cur_condition_str.replacen(mached_str, "", 1);
                continue;
            }

            tokens.push(token);
            cur_condition_str = cur_condition_str.replacen(mached_str, "", 1);
        }

        return Result::Ok(tokens);
    }

    /// 文字列をConditionTokenに変換する。
    fn to_enum(&self, token: String) -> ConditionToken {
        if token == "(" {
            return ConditionToken::LeftParenthesis;
        } else if token == ")" {
            return ConditionToken::RightParenthesis;
        } else if token == " " {
            return ConditionToken::Space;
        } else if token == "not" {
            return ConditionToken::Not;
        } else if token == "and" {
            return ConditionToken::And;
        } else if token == "or" {
            return ConditionToken::Or;
        } else {
            return ConditionToken::SelectionReference(token.clone());
        }
    }

    /// 右括弧と左括弧をだけをパースする。戻り値の配列にはLeftParenthesisとRightParenthesisが含まれず、代わりにTokenContainerに変換される。TokenContainerが括弧で囲まれた部分を表現している。
    fn parse_parenthesis(
        &self,
        tokens: Vec<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        let mut token_ite = tokens.into_iter();
        while let Some(token) = token_ite.next() {
            // まず、左括弧を探す。
            let is_left = match token {
                ConditionToken::LeftParenthesis => true,
                _ => false,
            };
            if !is_left {
                ret.push(token);
                continue;
            }

            // 左括弧が見つかったら、対応する右括弧を見つける。
            let mut left_cnt = 1;
            let mut right_cnt = 0;
            let mut sub_tokens = vec![];
            while let Some(token) = token_ite.next() {
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
                return Result::Err("expected ')'. but not found.".to_string());
            }

            // ここで再帰的に呼び出す。
            ret.push(ConditionToken::ParenthesisContainer(sub_tokens));
        }

        // この時点で右括弧が残っている場合は右括弧の数が左括弧よりも多いことを表している。
        let is_right_left = ret.iter().any(|token| {
            return match token {
                ConditionToken::RightParenthesis => true,
                _ => false,
            };
        });
        if is_right_left {
            return Result::Err("expected '('. but not found.".to_string());
        }

        return Result::Ok(ret);
    }

    /// AND, ORをパースする。
    fn parse_and_or_operator(&self, tokens: Vec<ConditionToken>) -> Result<ConditionToken, String> {
        if tokens.len() == 0 {
            // 長さ0は呼び出してはいけない
            return Result::Err("unknown error.".to_string());
        }

        // まず、selection1 and not selection2みたいな式のselection1やnot selection2のように、ANDやORでつながるトークンをまとめる。
        let tokens = self.to_operand_container(tokens)?;

        // 先頭又は末尾がAND/ORなのはだめ
        if self.is_logical(&tokens[0]) || self.is_logical(&tokens[tokens.len() - 1]) {
            return Result::Err("illegal Logical Operator(and, or) was found.".to_string());
        }

        // OperandContainerとLogicalOperator(AndとOR)が交互に並んでいるので、それぞれリストに投入
        let mut operand_list = vec![];
        let mut operator_list = vec![];
        for (i, token) in tokens.into_iter().enumerate() {
            if (i % 2 == 1) != self.is_logical(&token) {
                // インデックスが奇数の時はLogicalOperatorで、インデックスが偶数のときはOperandContainerになる
                return Result::Err("The use of logical operator(and, or) was wrong.".to_string());
            }

            if i % 2 == 0 {
                // ここで再帰的にAND,ORをパースする関数を呼び出す
                operand_list.push(token);
            } else {
                operator_list.push(token);
            }
        }

        // 先にANDでつながっている部分を全部まとめる
        let mut operant_ite = operand_list.into_iter();
        let mut operands = vec![operant_ite.next().unwrap()];
        for token in operator_list.iter() {
            if let ConditionToken::Or = token {
                // Orの場合はそのままリストに追加
                operands.push(operant_ite.next().unwrap());
            } else {
                // Andの場合はANDでつなげる
                let and_operands = vec![operands.pop().unwrap(), operant_ite.next().unwrap()];
                let and_container = ConditionToken::AndContainer(and_operands);
                operands.push(and_container);
            }
        }

        // 次にOrでつながっている部分をまとめる
        let or_contaienr = ConditionToken::OrContainer(operands);
        return Result::Ok(or_contaienr);
    }

    /// OperandContainerの中身をパースする。現状はNotをパースするためだけに存在している。
    fn parse_operand_container(
        &self,
        parent_token: ConditionToken,
    ) -> Result<ConditionToken, String> {
        if let ConditionToken::OperandContainer(sub_tokens) = parent_token {
            // 現状ではNOTの場合は、「not」と「notで修飾されるselectionノードの名前」の2つ入っているはず
            // NOTが無い場合、「selectionノードの名前」の一つしか入っていないはず。

            // 上記の通り、3つ以上入っていることはないはず。
            if sub_tokens.len() >= 3 {
                return Result::Err(
                    "unknown error. maybe it's because there are multiple name of selection node."
                        .to_string(),
                );
            }

            // 0はありえないはず
            if sub_tokens.len() == 0 {
                return Result::Err("unknown error.".to_string());
            }

            // 1つだけ入っている場合、NOTはありえない。
            if sub_tokens.len() == 1 {
                let operand_subtoken = sub_tokens.into_iter().next().unwrap();
                if let ConditionToken::Not = operand_subtoken {
                    return Result::Err("illegal not was found.".to_string());
                }

                return Result::Ok(operand_subtoken);
            }

            // ２つ入っている場合、先頭がNotで次はNotじゃない何かのはず
            let mut sub_tokens_ite = sub_tokens.into_iter();
            let first_token = sub_tokens_ite.next().unwrap();
            let second_token = sub_tokens_ite.next().unwrap();
            if let ConditionToken::Not = first_token {
                if let ConditionToken::Not = second_token {
                    return Result::Err("not is continuous.".to_string());
                } else {
                    let not_container = ConditionToken::NotContainer(vec![second_token]);
                    return Result::Ok(not_container);
                }
            } else {
                return Result::Err(
                    "unknown error. maybe it's because there are multiple name of selection node."
                        .to_string(),
                );
            }
        } else {
            let sub_tokens = parent_token.sub_tokens_without_parenthesis();
            if sub_tokens.len() == 0 {
                return Result::Ok(parent_token);
            }

            let mut new_sub_tokens = vec![];
            for sub_token in sub_tokens {
                let new_sub_token = self.parse_operand_container(sub_token)?;
                new_sub_tokens.push(new_sub_token);
            }

            return Result::Ok(parent_token.replace_subtoken(new_sub_tokens));
        }
    }

    /// ConditionTokenからSelectionNodeトレイトを実装した構造体に変換します。
    fn to_selectnode(
        &self,
        token: ConditionToken,
        name_2_node: &HashMap<String, Arc<Box<dyn SelectionNode + Send + Sync>>>,
    ) -> Result<Box<dyn SelectionNode + Send + Sync>, String> {
        // RefSelectionNodeに変換
        if let ConditionToken::SelectionReference(selection_name) = token {
            let selection_node = name_2_node.get(&selection_name);
            if selection_node.is_none() {
                let err_msg = format!("{} is not defined.", selection_name);
                return Result::Err(err_msg);
            } else {
                let selection_node = selection_node.unwrap();
                let selection_node = Arc::clone(selection_node);
                let ref_node = RefSelectionNode::new(selection_node);
                return Result::Ok(Box::new(ref_node));
            }
        }

        // AndSelectionNodeに変換
        if let ConditionToken::AndContainer(sub_tokens) = token {
            let mut select_and_node = AndSelectionNode::new();
            for sub_token in sub_tokens.into_iter() {
                let sub_node = self.to_selectnode(sub_token, name_2_node)?;
                select_and_node.child_nodes.push(sub_node);
            }
            return Result::Ok(Box::new(select_and_node));
        }

        // OrSelectionNodeに変換
        if let ConditionToken::OrContainer(sub_tokens) = token {
            let mut select_or_node = OrSelectionNode::new();
            for sub_token in sub_tokens.into_iter() {
                let sub_node = self.to_selectnode(sub_token, name_2_node)?;
                select_or_node.child_nodes.push(sub_node);
            }
            return Result::Ok(Box::new(select_or_node));
        }

        // NotSelectionNodeに変換
        if let ConditionToken::NotContainer(sub_tokens) = token {
            if sub_tokens.len() > 1 {
                return Result::Err("unknown error".to_string());
            }

            let select_sub_node =
                self.to_selectnode(sub_tokens.into_iter().next().unwrap(), name_2_node)?;
            let select_not_node = NotSelectionNode::new(select_sub_node);
            return Result::Ok(Box::new(select_not_node));
        }

        return Result::Err("unknown error".to_string());
    }

    /// ConditionTokenがAndまたはOrTokenならばTrue
    fn is_logical(&self, token: &ConditionToken) -> bool {
        return match token {
            ConditionToken::And => true,
            ConditionToken::Or => true,
            _ => false,
        };
    }

    /// ConditionToken::OperandContainerに変換できる部分があれば変換する。
    fn to_operand_container(
        &self,
        tokens: Vec<ConditionToken>,
    ) -> Result<Vec<ConditionToken>, String> {
        let mut ret = vec![];
        let mut grouped_operands = vec![]; // ANDとORの間にあるトークンを表す。ANDとORをOperatorとしたときのOperand
        let mut token_ite = tokens.into_iter();
        while let Some(token) = token_ite.next() {
            if self.is_logical(&token) {
                // ここに来るのはエラーのはずだが、後でエラー出力するので、ここではエラー出さない。
                if grouped_operands.is_empty() {
                    ret.push(token);
                    continue;
                }
                ret.push(ConditionToken::OperandContainer(grouped_operands));
                ret.push(token);
                grouped_operands = vec![];
                continue;
            }

            grouped_operands.push(token);
        }
        if !grouped_operands.is_empty() {
            ret.push(ConditionToken::OperandContainer(grouped_operands));
        }

        return Result::Ok(ret);
    }
}

#[cfg(test)]
mod tests {
    use yaml_rust::YamlLoader;

    use crate::detections::detection::EvtxRecordInfo;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::tests::parse_rule_from_str;

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

    fn check_rule_parse_error(rule_str: &str, errmsgs: Vec<String>) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(rule_node.init(), Err(errmsgs));
    }

    fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_str) {
            Ok(record) => {
                let recinfo = EvtxRecordInfo{ evtx_filepath: "testpath".to_owned(), record: record };
                assert_eq!(
                    rule_node.select(&"testpath".to_owned(), &recinfo),
                    expect_select
                );
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
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
                let recinfo = EvtxRecordInfo{ evtx_filepath: "testpath".to_owned(), record: record };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), true);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
                let recinfo = EvtxRecordInfo{ evtx_filepath: "testpath".to_owned(), record: record };
                assert_eq!(rule_node.select(&"testpath".to_owned(), &recinfo), false);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule("testpath".to_string(), rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(),
            Err(vec![
                "There are no condition node under detection.".to_string()
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. An unusable character was found.".to_string()],
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. expected ')'. but not found.".to_string()],
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. expected '('. but not found.".to_string()],
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. expected ')'. but not found.".to_string()],
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(rule_str,vec!["condition parse error has occured. unknown error. maybe it\'s because there are multiple name of selection node.".to_string()]);
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "condition parse error has occured. illegal Logical Operator(and, or) was found."
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec![
                "condition parse error has occured. illegal Logical Operator(and, or) was found."
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(rule_str,vec!["condition parse error has occured. The use of logical operator(and, or) was wrong.".to_string()]);
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. illegal not was found.".to_string()],
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
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        check_rule_parse_error(
            rule_str,
            vec!["condition parse error has occured. not is continuous.".to_string()],
        );
    }
}

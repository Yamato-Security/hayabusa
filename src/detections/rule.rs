extern crate regex;

use crate::detections::print::AlertMessage;
use chrono::{DateTime, TimeZone, Utc};
use mopa::mopafy;
use std::collections::VecDeque;
use std::num::ParseIntError;

use std::{collections::HashMap, sync::Arc, vec};

use crate::detections::print::Message;
use crate::detections::utils;

use regex::Regex;
use serde_json::Value;
use yaml_rust::Yaml;

pub fn create_rule(yaml: Yaml) -> RuleNode {
    return RuleNode::new(yaml);
}

fn concat_selection_key(key_list: &Vec<String>) -> String {
    return key_list
        .iter()
        .fold("detection -> selection".to_string(), |mut acc, cur| {
            acc = acc + " -> " + cur;
            return acc;
        });
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

    fn compile_condition(
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

#[derive(Debug)]
/// パイプ(|)以降のconditionでの字句解析、構文解析の結果を保存する構造体
pub struct AggregationParseInfo {
    _field_name: Option<String>,        // countの括弧に囲まれた部分の文字
    _by_field_name: Option<String>,     // count() by の後に指定される文字列
    _cmp_op: AggregationConditionToken, // (必須)<とか>とか何が指定されたのか
    _cmp_num: i32,                      // (必須)<とか>とかの後にある数値
}

#[derive(Debug)]
pub enum AggregationConditionToken {
    COUNT(String),   // count
    SPACE,           // 空白
    BY,              // by
    EQ,              // ..と等しい
    LE,              // ..以下
    LT,              // ..未満
    GE,              // ..以上
    GT,              // .よりおおきい
    KEYWORD(String), // BYのフィールド名
}

/// SIGMAルールでいうAggregationConditionを解析する。
/// AggregationConditionはconditionに指定された式のパイプ以降の部分を指してます。
#[derive(Debug)]
pub struct AggegationConditionCompiler {
    regex_patterns: Vec<Regex>,
}

impl AggegationConditionCompiler {
    pub fn new() -> Self {
        // ここで字句解析するときに使う正規表現の一覧を定義する。
        // ここはSigmaのGithubレポジトリにある、toos/sigma/parser/condition.pyのSigmaConditionTokenizerのtokendefsを参考にしています。
        let mut regex_patterns = vec![];
        regex_patterns.push(Regex::new(r"^count\( *\w* *\)").unwrap()); // countの式
        regex_patterns.push(Regex::new(r"^ ").unwrap());
        regex_patterns.push(Regex::new(r"^by").unwrap());
        regex_patterns.push(Regex::new(r"^==").unwrap());
        regex_patterns.push(Regex::new(r"^<=").unwrap());
        regex_patterns.push(Regex::new(r"^>=").unwrap());
        regex_patterns.push(Regex::new(r"^<").unwrap());
        regex_patterns.push(Regex::new(r"^>").unwrap());
        regex_patterns.push(Regex::new(r"^\w+").unwrap());

        return AggegationConditionCompiler {
            regex_patterns: regex_patterns,
        };
    }

    pub fn compile(&self, condition_str: String) -> Result<Option<AggregationParseInfo>, String> {
        let result = self.compile_body(condition_str);
        if let Result::Err(msg) = result {
            return Result::Err(format!(
                "aggregation condition parse error has occurred. {}",
                msg
            ));
        } else {
            return result;
        }
    }

    pub fn compile_body(
        &self,
        condition_str: String,
    ) -> Result<Option<AggregationParseInfo>, String> {
        // パイプの部分だけを取り出す
        let re_pipe = Regex::new(r"\|.*").unwrap();
        let captured = re_pipe.captures(&condition_str);
        if captured.is_none() {
            // パイプが無いので終了
            return Result::Ok(Option::None);
        }
        // ハイプ自体は削除してからパースする。
        let aggregation_str = captured
            .unwrap()
            .get(0)
            .unwrap()
            .as_str()
            .to_string()
            .replacen("|", "", 1);

        let tokens = self.tokenize(aggregation_str)?;
        return self.parse(tokens);
    }

    /// 字句解析します。
    pub fn tokenize(
        &self,
        condition_str: String,
    ) -> Result<Vec<AggregationConditionToken>, String> {
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

            if let AggregationConditionToken::SPACE = token {
                // 空白は特に意味ないので、読み飛ばす。
                cur_condition_str = cur_condition_str.replacen(mached_str, "", 1);
                continue;
            }

            tokens.push(token);
            cur_condition_str = cur_condition_str.replacen(mached_str, "", 1);
        }

        return Result::Ok(tokens);
    }

    /// 比較演算子かどうか判定します。
    fn is_cmp_op(&self, token: &AggregationConditionToken) -> bool {
        return match token {
            AggregationConditionToken::EQ => true,
            AggregationConditionToken::LE => true,
            AggregationConditionToken::LT => true,
            AggregationConditionToken::GE => true,
            AggregationConditionToken::GT => true,
            _ => false,
        };
    }

    /// 構文解析します。
    fn parse(
        &self,
        tokens: Vec<AggregationConditionToken>,
    ) -> Result<Option<AggregationParseInfo>, String> {
        if tokens.is_empty() {
            // パイプしか無いのはおかしいのでエラー
            return Result::Err("There are no strings after pipe(|).".to_string());
        }

        let mut token_ite = tokens.into_iter();
        let token = token_ite.next().unwrap();

        let mut count_field_name: Option<String> = Option::None;
        if let AggregationConditionToken::COUNT(field_name) = token {
            if !field_name.is_empty() {
                count_field_name = Option::Some(field_name);
            }
        } else {
            // いろんなパターンがあるので難しいが、countというキーワードしか使えないことを説明しておく。
            return Result::Err("aggregation condition can use count only.".to_string());
        }

        let token = token_ite.next();
        if token.is_none() {
            // 論理演算子がないのはだめ
            return Result::Err(
                "count keyword needs compare operator and number like '> 3'".to_string(),
            );
        }

        // BYはオプションでつけなくても良い
        let mut by_field_name = Option::None;
        let token = token.unwrap();
        let token = if let AggregationConditionToken::BY = token {
            let after_by = token_ite.next();
            if after_by.is_none() {
                // BYの後に何もないのはだめ
                return Result::Err("by keyword needs field name like 'by EventID'".to_string());
            }

            if let AggregationConditionToken::KEYWORD(keyword) = after_by.unwrap() {
                by_field_name = Option::Some(keyword);
                token_ite.next()
            } else {
                return Result::Err("by keyword needs field name like 'by EventID'".to_string());
            }
        } else {
            Option::Some(token)
        };

        // 比較演算子と数値をパース
        if token.is_none() {
            // 論理演算子がないのはだめ
            return Result::Err(
                "count keyword needs compare operator and number like '> 3'".to_string(),
            );
        }

        let cmp_token = token.unwrap();
        if !self.is_cmp_op(&cmp_token) {
            return Result::Err(
                "count keyword needs compare operator and number like '> 3'".to_string(),
            );
        }

        let token = token_ite.next().unwrap_or(AggregationConditionToken::SPACE);
        let cmp_number = if let AggregationConditionToken::KEYWORD(number) = token {
            let number: Result<i32, _> = number.parse();
            if number.is_err() {
                // 比較演算子の後に数値が無い。
                return Result::Err("compare operator needs a number like '> 3'.".to_string());
            } else {
                number.unwrap()
            }
        } else {
            // 比較演算子の後に数値が無い。
            return Result::Err("compare operator needs a number like '> 3'.".to_string());
        };

        if token_ite.next().is_some() {
            return Result::Err("unnecessary word was found.".to_string());
        }

        let info = AggregationParseInfo {
            _field_name: count_field_name,
            _by_field_name: by_field_name,
            _cmp_op: cmp_token,
            _cmp_num: cmp_number,
        };
        return Result::Ok(Option::Some(info));
    }

    /// 文字列をConditionTokenに変換する。
    fn to_enum(&self, token: String) -> AggregationConditionToken {
        if token.starts_with("count(") {
            let count_field = token
                .replacen("count(", "", 1)
                .replacen(")", "", 1)
                .replace(" ", "");
            return AggregationConditionToken::COUNT(count_field);
        } else if token == " " {
            return AggregationConditionToken::SPACE;
        } else if token == "by" {
            return AggregationConditionToken::BY;
        } else if token == "==" {
            return AggregationConditionToken::EQ;
        } else if token == "<=" {
            return AggregationConditionToken::LE;
        } else if token == ">=" {
            return AggregationConditionToken::GE;
        } else if token == "<" {
            return AggregationConditionToken::LT;
        } else if token == ">" {
            return AggregationConditionToken::GT;
        } else {
            return AggregationConditionToken::KEYWORD(token);
        }
    }
}

#[derive(Debug)]
/// countなどのaggregationの結果を出力する構造体
pub struct AggResult {
    /// evtx file path
    pub filepath: String,
    /// result of aggregation condition select
    pub result: bool,
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
        result: bool,
        data: i32,
        key: String,
        start_timedate: DateTime<Utc>,
        condition_op_num: String,
    ) -> AggResult {
        return AggResult {
            filepath: filepath,
            result: result,
            data: data,
            key: key,
            start_timedate: start_timedate,
            condition_op_num: condition_op_num,
        };
    }
}

/// Ruleファイルを表すノード
pub struct RuleNode {
    pub yaml: Yaml,
    detection: Option<DetectionNode>,
    countdata: HashMap<String, HashMap<String, Vec<DateTime<Utc>>>>,
    timeframe: Option<TimeFrameInfo>,
}

unsafe impl Sync for RuleNode {}

impl RuleNode {
    pub fn new(yaml: Yaml) -> RuleNode {
        return RuleNode {
            yaml: yaml,
            detection: Option::None,
            countdata: HashMap::new(),
            timeframe: Option::None,
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

    pub fn select(&mut self, filepath: &String, event_record: &Value) -> bool {
        if self.detection.is_none() {
            return false;
        }

        let result = self.detection.as_ref().unwrap().select(event_record);
        if result {
            self.count(filepath, event_record);
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
    /// countでgroupbyなどの情報を区分するためのハッシュマップのキーを作成する関数
    fn create_count_key(&self, record: &Value) -> String {
        if self
            .detection
            .as_ref()
            .unwrap()
            .aggregation_condition
            .as_ref()
            .is_none()
        {
            return "_".to_string();
        }
        let aggcondition = self
            .detection
            .as_ref()
            .unwrap()
            .aggregation_condition
            .as_ref()
            .unwrap();
        // recordでaliasが登録されている前提とする
        let mut key = "".to_string();
        if aggcondition._field_name.is_some() {
            let field_value = aggcondition._field_name.as_ref().unwrap();
            match utils::get_event_value(field_value, record) {
                Some(value) => {
                    key.push_str(&value.to_string().replace("\"", ""));
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    AlertMessage::alert(
                        &mut stdout,
                        format!("field_value alias not found.value:{}", field_value),
                    );
                }
            };
        }
        key.push_str("_");
        if aggcondition._by_field_name.is_some() {
            let by_field_value = aggcondition._by_field_name.as_ref().unwrap();
            match utils::get_event_value(by_field_value, record) {
                Some(value) => {
                    key.push_str(&value[by_field_value].to_string());
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    AlertMessage::alert(
                        &mut stdout,
                        format!("by_field_value alias not found.value:{}", by_field_value),
                    );
                }
            }
        }
        return key;
    }

    /// Aggregation Conditionの結果を配列で返却する関数
    pub fn judge_satisfy_aggcondition(&self) -> Vec<AggResult> {
        let mut ret = Vec::new();
        if !self.has_agg_condition() {
            return ret;
        }
        for filepath in self.countdata.keys() {
            ret.append(&mut self.aggregation_condition_select(&filepath));
        }
        return ret;
    }

    /// aggregation condition内での条件式を文字として返す関数
    pub fn get_str_agg_eq(&self) -> String {
        //この関数はaggregation ruleのパースが正常終了した後に呼ばれる想定のためOptionの判定は行わない
        let agg_condition = self
            .detection
            .as_ref()
            .unwrap()
            .aggregation_condition
            .as_ref()
            .unwrap();
        let mut ret: String = "".to_owned();
        match agg_condition._cmp_op {
            AggregationConditionToken::EQ => {
                ret.push_str("== ");
            }
            AggregationConditionToken::GE => {
                ret.push_str(">= ");
            }
            AggregationConditionToken::LE => {
                ret.push_str("<= ");
            }
            AggregationConditionToken::GT => {
                ret.push_str("> ");
            }
            AggregationConditionToken::LT => {
                ret.push_str("< ");
            }
            _ => {
                //想定しない演算子のため、空白文字で対応するものがない
                return "".to_string();
            }
        }
        ret.push_str(&agg_condition._cmp_num.to_string());
        return ret;
    }

    /// 検知された際にカウント情報を投入する関数
    fn count(&mut self, filepath: &String, record: &Value) {
        let key = self.create_count_key(record);
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        self.countup(
            filepath,
            &key,
            Message::get_event_time(record).unwrap_or(default_time),
        );
    }

    ///count byの条件に合致する検知済みレコードの数を増やすための関数
    pub fn countup(&mut self, filepath: &String, key: &str, record_time_value: DateTime<Utc>) {
        self.countdata
            .entry(filepath.to_string())
            .or_insert(HashMap::new());
        let value_map = self.countdata.get_mut(filepath).unwrap();
        value_map.entry(key.to_string()).or_insert(Vec::new());
        let mut prev_value = value_map[key].clone();
        prev_value.push(record_time_value);
        value_map.insert(key.to_string(), prev_value);
    }

    /// count済みデータ内でタイムフレーム内に存在するselectの条件を満たすレコードがcount条件を満たしているかを判定する関数
    fn judge_timeframe(
        &self,
        filepath: &String,
        time_data: &Vec<DateTime<Utc>>,
        key: &String,
    ) -> Vec<AggResult> {
        let mut ret = Vec::new();
        let aggcondition = self
            .detection
            .as_ref()
            .unwrap()
            .aggregation_condition
            .as_ref()
            .unwrap();
        let mut start_point = 0;
        let mut check_point = start_point + aggcondition._cmp_num - 1;
        let judge_sec_frame = self.get_sec_timeframe();
        loop {
            if start_point as usize >= time_data.len() || check_point as usize >= time_data.len() {
                let count_set_cnt = time_data.len() - (start_point as usize);
                let judge = self.select_aggcon(count_set_cnt as i32, &aggcondition);
                if judge {
                    ret.push(AggResult::new(
                        filepath.to_string(),
                        self.select_aggcon(count_set_cnt as i32, &aggcondition),
                        count_set_cnt as i32,
                        key.to_string(),
                        time_data[start_point as usize],
                        self.get_str_agg_eq(),
                    ));
                }
                break;
            }
            let check_point_date = time_data[check_point as usize];
            let diff = check_point_date.timestamp() - time_data[start_point as usize].timestamp();
            if diff > judge_sec_frame.unwrap_or(0) {
                let count_set_cnt = check_point - start_point + 1;
                let judge = self.select_aggcon(count_set_cnt, &aggcondition);
                if !judge {
                    start_point += 1;
                    check_point = start_point + aggcondition._cmp_num - 1;
                    continue;
                }
                ret.push(AggResult::new(
                    filepath.to_string(),
                    judge,
                    count_set_cnt,
                    key.to_string(),
                    time_data[start_point as usize],
                    self.get_str_agg_eq(),
                ));
                start_point = check_point + 1;
                check_point = start_point + aggcondition._cmp_num - 1;
            } else {
                check_point += 1;
            }
        }
        return ret;
    }

    /// TimeFrameInfoで格納されたtimeframeの値を秒数に変換した結果を返す関数
    fn get_sec_timeframe(&self) -> Option<i64> {
        let tframe = self.timeframe.as_ref();
        if tframe.is_none() {
            return Option::None;
        }
        let tfi = tframe.unwrap();
        match &tfi.timenum {
            Ok(n) => {
                if tfi.timetype == "d" {
                    return Some(n * 86400);
                } else if tfi.timetype == "h" {
                    return Some(n * 3600);
                } else if tfi.timetype == "m" {
                    return Some(n * 60);
                } else {
                    return Some(*n);
                }
            }
            Err(err) => {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                AlertMessage::alert(
                    &mut stdout,
                    format!("timeframe num is invalid. timeframe.{}", err),
                );
                return Option::None;
            }
        }
    }

    /// conditionのパイプ以降の処理をAggregationParseInfoを参照し、conditionの条件を満たすか判定するための関数
    pub fn select_aggcon(&self, cnt: i32, aggcondition: &AggregationParseInfo) -> bool {
        match aggcondition._cmp_op {
            AggregationConditionToken::EQ => {
                if cnt == aggcondition._cmp_num {
                    return true;
                } else {
                    return false;
                }
            }
            AggregationConditionToken::GE => {
                if cnt >= aggcondition._cmp_num {
                    return true;
                } else {
                    return false;
                }
            }
            AggregationConditionToken::GT => {
                if cnt > aggcondition._cmp_num {
                    return true;
                } else {
                    return false;
                }
            }
            AggregationConditionToken::LE => {
                if cnt <= aggcondition._cmp_num {
                    return true;
                } else {
                    return false;
                }
            }
            AggregationConditionToken::LT => {
                if cnt < aggcondition._cmp_num {
                    return true;
                } else {
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
    }
    ///現状のレコードの状態から条件式に一致しているかを判定する関数
    fn aggregation_condition_select(&self, filepath: &String) -> Vec<AggResult> {
        // recordでaliasが登録されている前提とする
        let value_map = self.countdata.get(filepath).unwrap();
        let mut ret = Vec::new();
        for (key, value) in value_map {
            ret.append(&mut self.judge_timeframe(&filepath.to_string(), value, &key.to_string()));
        }
        return ret;
    }
}

/// timeframeに設定された情報。SIGMAルール上timeframeで複数の単位(日、時、分、秒)が複合で記載されているルールがなかったためタイプと数値のみを格納する構造体
struct TimeFrameInfo {
    pub timetype: String,
    pub timenum: Result<i64, ParseIntError>,
}

impl TimeFrameInfo {
    /// timeframeの文字列をパースし、構造体を返す関数
    pub fn parse_tframe(value: String) -> TimeFrameInfo {
        let mut ttype: String = "".to_string();
        let mut tnum = value.clone();
        if value == "s" {
            ttype = "s".to_string();
            tnum.retain(|c| c != 's');
        } else if value == "m" {
            ttype = "m".to_string();
            tnum.retain(|c| c != 'm');
        } else if value == "h" {
            ttype = "h".to_string();
            tnum.retain(|c| c != 'h');
        } else if value == "d" {
            ttype = "d".to_string();
            tnum.retain(|c| c != 'd');
        } else {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            AlertMessage::alert(
                &mut stdout,
                format!("timeframe is invalid.input value:{}", value),
            );
        }
        return TimeFrameInfo {
            timetype: ttype,
            timenum: tnum.parse::<i64>(),
        };
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
                    "There are no condition node under detection.".to_string()
                ]);
            }

            keys.nth(0).unwrap().to_string()
        };

        // conditionをパースして、SelectionNodeに変換する
        let mut err_msgs = vec![];
        let compiler = ConditionCompiler::new();
        let compile_result =
            compiler.compile_condition(condition_str.clone(), &self.name_to_selection);
        if let Result::Err(err_msg) = compile_result {
            err_msgs.extend(vec![err_msg]);
        } else {
            self.condition = Option::Some(compile_result.unwrap());
        }

        // aggregation condition(conditionのパイプ以降の部分)をパース
        let agg_compiler = AggegationConditionCompiler::new();
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

    pub fn select(&self, event_record: &Value) -> bool {
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
            return Result::Err(vec!["not found detection node".to_string()]);
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
            if name == "condition" {
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
                "There are no selection node under detection.".to_string()
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
            let mut and_node = AndSelectionNode::new();

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
            let mut or_node = OrSelectionNode::new();
            yaml.as_vec().unwrap().iter().for_each(|child_yaml| {
                let child_node = self.parse_selection_recursively(key_list.clone(), child_yaml);
                or_node.child_nodes.push(child_node);
            });

            return Box::new(or_node);
        } else {
            // 連想配列と配列以外は末端ノード
            return Box::new(LeafSelectionNode::new(key_list, yaml.clone()));
        }
    }
}

// Ruleファイルの detection- selection配下のノードはこのtraitを実装する。
trait SelectionNode: mopa::Any {
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
struct AndSelectionNode {
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
struct OrSelectionNode {
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
struct NotSelectionNode {
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
struct RefSelectionNode {
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
struct LeafSelectionNode {
    key_list: Vec<String>,
    select_value: Yaml,
    matcher: Option<Box<dyn LeafMatcher>>,
}

unsafe impl Send for LeafSelectionNode {}
unsafe impl Sync for LeafSelectionNode {}

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

        let topkey = self.key_list[0].to_string();
        let values: Vec<&str> = topkey.split("|").collect();
        return values[0].to_string();
    }

    /// JSON形式のEventJSONから値を取得する関数 aliasも考慮されている。
    fn get_event_value<'a>(&self, event_value: &'a Value) -> Option<&'a Value> {
        if self.key_list.is_empty() {
            return Option::None;
        }

        return utils::get_event_value(&self.get_key(), event_value);
    }

    /// LeafMatcherの一覧を取得する。
    /// 上から順番に調べて、一番始めに一致したMatcherが適用される
    fn get_matchers(&self) -> Vec<Box<dyn LeafMatcher>> {
        return vec![
            Box::new(MinlengthMatcher::new()),
            Box::new(RegexesFileMatcher::new()),
            Box::new(WhitelistFileMatcher::new()),
            Box::new(DefaultMatcher::new()),
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
        if self.get_key() == "EventData" {
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
        let match_key_list = self.key_list.clone();
        let matchers = self.get_matchers();
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

    fn get_childs(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![];
    }

    fn get_descendants(&self) -> Vec<&Box<dyn SelectionNode + Send + Sync>> {
        return vec![];
    }
}

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
trait LeafMatcher: mopa::Any {
    /// 指定されたkey_listにマッチするLeafMatcherであるかどうか判定する。
    fn is_target_key(&self, key_list: &Vec<String>) -> bool;

    /// 引数に指定されたJSON形式のデータがマッチするかどうか判定する。
    /// main.rsでWindows Event LogをJSON形式に変換していて、そのJSON形式のWindowsのイベントログデータがここには来る
    /// 例えば正規表現でマッチするロジックなら、ここに正規表現でマッチさせる処理を書く。
    fn is_match(&self, event_value: Option<&Value>) -> bool;

    /// 初期化ロジックをここに記載します。
    /// ルールファイルの書き方が間違っている等の原因により、正しくルールファイルからパースできない場合、戻り値のResult型でエラーを返してください。
    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>>;
}
mopafy!(LeafMatcher);

/// 指定された文字数以上であることをチェックするクラス。
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
        if key_list.len() != 2 {
            return false;
        }

        return key_list.get(1).unwrap() == "min_length";
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

/// 正規表現のリストが記載されたファイルを読み取って、比較するロジックを表すクラス
/// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
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
        if key_list.len() != 2 {
            return false;
        }

        return key_list.get(1).unwrap() == "regexes";
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
        //TODO Wildcardの場合、CaseInsensitiveなので、ToLowerする。
        return match event_value.unwrap_or(&Value::Null) {
            Value::String(s) => !utils::check_regex(s, 0, &self.regexes_csv_content).is_empty(),
            Value::Number(n) => {
                !utils::check_regex(&n.to_string(), 0, &self.regexes_csv_content).is_empty()
            }
            _ => false,
        };
    }
}

/// ファイルに列挙された文字列に一致する場合に検知するロジックを表す
/// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
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
        if key_list.len() != 2 {
            return false;
        }

        return key_list.get(1).unwrap() == "whitelist";
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

/// デフォルトのマッチクラス
/// ワイルドカードの処理やパイプ
struct DefaultMatcher {
    re: Option<Regex>,
    pipes: Vec<PipeElement>,
}

impl DefaultMatcher {
    fn new() -> DefaultMatcher {
        return DefaultMatcher {
            re: Option::None,
            pipes: Vec::new(),
        };
    }

    /// このmatcherの正規表現とマッチするかどうか判定します。
    /// 判定対象の文字列とこのmatcherが保持する正規表現が完全にマッチした場合のTRUEを返します。
    /// 例えば、判定対象文字列が"abc"で、正規表現が"ab"の場合、正規表現は判定対象文字列の一部分にしか一致していないので、この関数はfalseを返します。
    fn is_regex_fullmatch(&self, value: String) -> bool {
        return self
            .re
            .as_ref()
            .unwrap()
            .find_iter(&value)
            .any(|match_obj| {
                return match_obj.as_str().to_string() == value;
            });
    }

    /// YEAのルールファイルのフィールド名とそれに続いて指定されるパイプを、正規表現形式の文字列に変換します。
    /// ワイルドカードの文字列を正規表現にする処理もこのメソッドに実装されています。patternにワイルドカードの文字列を指定して、pipesにPipeElement::Wildcardを指定すればOK!!
    fn from_pattern_to_regex_str(pattern: String, pipes: &Vec<PipeElement>) -> String {
        // パターンをPipeで処理する。
        return pipes.iter().fold(pattern, |acc, pipe| {
            return pipe.pipe_pattern(acc);
        });
    }
}

impl LeafMatcher for DefaultMatcher {
    fn is_target_key(&self, key_list: &Vec<String>) -> bool {
        return key_list.len() == 1;
    }

    fn init(&mut self, key_list: &Vec<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        if select_value.is_null() {
            return Result::Ok(());
        }

        // patternをパースする
        let yaml_value = match select_value {
            Yaml::Boolean(b) => Option::Some(b.to_string()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_string()),
            Yaml::String(s) => Option::Some(s.to_owned()),
            _ => Option::None,
        };
        if yaml_value.is_none() {
            let errmsg = format!(
                "unknown error occured. [key:{}]",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        let pattern = yaml_value.unwrap();

        // Pipeが指定されていればパースする
        let mut keys: VecDeque<&str> = key_list.get(0).unwrap().split("|").collect(); // key_listが空はあり得ない
        keys.pop_front();
        while !keys.is_empty() {
            let key = keys.pop_front().unwrap();
            let pipe_element = match key {
                "startswith" => Option::Some(PipeElement::Startswith),
                "endswith" => Option::Some(PipeElement::Endswith),
                "contains" => Option::Some(PipeElement::Contains),
                "re" => Option::Some(PipeElement::Re),
                _ => Option::None,
            };
            if pipe_element.is_none() {
                let errmsg = format!(
                    "unknown pipe element was specified. key:{}",
                    concat_selection_key(key_list)
                );
                return Result::Err(vec![errmsg]);
            }

            self.pipes.push(pipe_element.unwrap());
        }
        if self.pipes.len() >= 2 {
            // 現状では複数のパイプは対応していない
            let errmsg = format!(
                "multiple pipe element can't be used. key:{}",
                concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        let is_re = &self.pipes.iter().any(|pipe_element| {
            return match pipe_element {
                PipeElement::Re => true,
                _ => false,
            };
        });
        // 正規表現ではない場合、ワイルドカードであることを表す。
        // ワイルドカードは正規表現でマッチングするので、ワイルドカードを正規表現に変換するPipeを内部的に追加することにする。
        if !is_re {
            self.pipes.push(PipeElement::Wildcard);
        }

        // パターンをPipeで処理する。
        let pattern = DefaultMatcher::from_pattern_to_regex_str(pattern, &self.pipes);
        // Pipeで処理されたパターンを正規表現に変換
        let re_result = Regex::new(&pattern);
        if re_result.is_err() {
            let errmsg = format!(
                "cannot parse regex. [regex:{}, key:{}]",
                pattern,
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

        // JSON形式のEventLogデータをstringに変換
        let event_value_str = match event_value.unwrap_or(&Value::Null) {
            Value::Bool(b) => Option::Some(b.to_string()),
            Value::String(s) => Option::Some(s.to_owned()),
            Value::Number(n) => Option::Some(n.to_string()),
            _ => Option::None,
        };
        if event_value_str.is_none() {
            return false;
        }

        // 変換したデータに対してパイプ処理を実行する。
        let event_value_str = (&self.pipes)
            .iter()
            .fold(event_value_str.unwrap(), |acc, pipe| {
                return pipe.pipe_eventlog_data(acc);
            });

        return self.is_regex_fullmatch(event_value_str);
    }
}

/// パイプ(|)で指定される要素を表すクラス。
enum PipeElement {
    Startswith,
    Endswith,
    Contains,
    Re,
    Wildcard,
}

impl PipeElement {
    /// WindowsEventLogのJSONデータに対してパイプ処理します。
    fn pipe_eventlog_data(&self, pattern: String) -> String {
        return match self {
            // wildcardはcase sensetiveなので、全て小文字にして比較する。
            PipeElement::Wildcard => pattern.to_lowercase(),
            _ => pattern,
        };
    }

    /// patternをパイプ処理します
    fn pipe_pattern(&self, pattern: String) -> String {
        // enumでポリモーフィズムを実装すると、一つのメソッドに全部の型の実装をする感じになる。Java使い的にはキモイ感じがする。
        let fn_add_asterisk_end = |patt: String| {
            if patt.ends_with("//*") {
                return patt;
            } else if patt.ends_with("/*") {
                return patt + "*";
            } else if patt.ends_with("*") {
                return patt;
            } else {
                return patt + "*";
            }
        };
        let fn_add_asterisk_begin = |patt: String| {
            if patt.starts_with("//*") {
                return patt;
            } else if patt.starts_with("/*") {
                return "*".to_string() + &patt;
            } else if patt.starts_with("*") {
                return patt;
            } else {
                return "*".to_string() + &patt;
            }
        };

        let val: String = match self {
            // startswithの場合はpatternの最後にwildcardを足すことで対応する
            PipeElement::Startswith => fn_add_asterisk_end(pattern),
            // endswithの場合はpatternの最初にwildcardを足すことで対応する
            PipeElement::Endswith => fn_add_asterisk_begin(pattern),
            // containsの場合はpatternの前後にwildcardを足すことで対応する
            PipeElement::Contains => fn_add_asterisk_end(fn_add_asterisk_begin(pattern)),
            // 正規表現の場合は特に処理する必要無い
            PipeElement::Re => pattern,
            // WildCardは正規表現に変換する。
            PipeElement::Wildcard => PipeElement::pipe_pattern_wildcard(pattern),
        };
        return val;
    }

    /// PipeElement::Wildcardのパイプ処理です。
    /// pipe_pattern()に含めて良い処理ですが、複雑な処理になってしまったので別関数にしました。
    fn pipe_pattern_wildcard(pattern: String) -> String {
        // wildcardはcase sensetiveなので、全て小文字にして比較する。
        let pattern = pattern.to_lowercase();
        let wildcards = vec!["*".to_string(), "?".to_string()];

        // patternをwildcardでsplitした結果をpattern_splitsに入れる
        // 以下のアルゴリズムの場合、pattern_splitsの偶数indexの要素はwildcardじゃない文字列となり、奇数indexの要素はwildcardが入る。
        let mut idx = 0;
        let mut pattern_splits = vec![];
        let mut cur_str = String::default();
        while idx < pattern.len() {
            let prev_idx = idx;
            for wildcard in &wildcards {
                let cur_pattern: String = pattern.chars().skip(idx).collect::<String>();
                if cur_pattern.starts_with(&format!(r"\\{}", wildcard)) {
                    // wildcardの前にエスケープ文字が2つある場合
                    cur_str = format!("{}{}", cur_str, r"\");
                    pattern_splits.push(cur_str);
                    pattern_splits.push(wildcard.to_string());

                    cur_str = String::default();
                    idx += 3;
                    break;
                } else if cur_pattern.starts_with(&format!(r"\{}", wildcard)) {
                    // wildcardの前にエスケープ文字が1つある場合
                    cur_str = format!("{}{}", cur_str, wildcard);
                    idx += 2;
                    break;
                } else if cur_pattern.starts_with(wildcard) {
                    // wildcardの場合
                    pattern_splits.push(cur_str);
                    pattern_splits.push(wildcard.to_string());

                    cur_str = String::default();
                    idx += 1;
                    break;
                }
            }
            // 上記のFor文でHitした場合はcontinue
            if prev_idx != idx {
                continue;
            }

            cur_str = format!(
                "{}{}",
                cur_str,
                pattern.chars().skip(idx).take(1).collect::<String>()
            );
            idx += 1;
        }
        // 最後の文字がwildcardじゃない場合は、cur_strに文字が入っているので、それをpattern_splitsに入れておく
        if !cur_str.is_empty() {
            pattern_splits.push(cur_str);
        }

        // SIGMAルールのwildcard表記から正規表現の表記に変換します。
        return pattern_splits.iter().enumerate().fold(
            String::default(),
            |acc: String, (idx, pattern)| {
                let regex_value = if idx % 2 == 0 {
                    // wildcardじゃない場合はescapeした文字列を返す
                    regex::escape(pattern)
                } else {
                    // wildcardの場合、"*"は".*"という正規表現に変換し、"?"は"."に変換する。
                    let wildcard_regex_value = if pattern.to_string() == "*" {
                        ".*"
                    } else {
                        "."
                    };
                    wildcard_regex_value.to_string()
                };

                return format!("{}{}", acc, regex_value);
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::rule::{
        create_rule, AggregationConditionToken, AndSelectionNode, DefaultMatcher,
        LeafSelectionNode, MinlengthMatcher, OrSelectionNode, PipeElement, RegexesFileMatcher,
        SelectionNode, WhitelistFileMatcher,
    };
    use chrono::{TimeZone, Utc};
    use yaml_rust::YamlLoader;

    use super::{AggegationConditionCompiler, RuleNode};

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
        let selection_node = &rule_node.detection.unwrap().name_to_selection["selection"];

        // Root
        let detection_childs = selection_node.get_childs();
        assert_eq!(detection_childs.len(), 4);

        // Channel
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[0].as_ref() as &dyn SelectionNode; //  TODO キャストしないとエラーでるけど、このキャストよく分からん。
            assert_eq!(child_node.is::<LeafSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "Channel");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert_eq!(matcher.is_some(), true);
            let matcher = child_node.matcher.as_ref().unwrap();
            assert_eq!(matcher.is::<DefaultMatcher>(), true);
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

            assert_eq!(matcher.re.is_some(), true);
            let re = matcher.re.as_ref();
            assert_eq!(
                re.unwrap().as_str(),
                r"Microsoft\-Windows\-PowerShell/Operational".to_lowercase()
            );
        }

        // EventID
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[1].as_ref() as &dyn SelectionNode;
            assert_eq!(child_node.is::<LeafSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "EventID");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert_eq!(matcher.is_some(), true);
            let matcher = child_node.matcher.as_ref().unwrap();
            assert_eq!(matcher.is::<DefaultMatcher>(), true);
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

            assert_eq!(matcher.re.is_some(), true);
            let re = matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "4103");
        }

        // ContextInfo
        {
            // OrSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[2].as_ref() as &dyn SelectionNode;
            assert_eq!(child_node.is::<OrSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<OrSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 2);

            // OrSelectionNodeの下にLeafSelectionNodeがあるパターンをテスト
            // LeafSelectionNodeである、Host Applicationノードが正しいことを確認
            let hostapp_en_node = ancestors[0].as_ref() as &dyn SelectionNode;
            assert_eq!(hostapp_en_node.is::<LeafSelectionNode>(), true);
            let hostapp_en_node = hostapp_en_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_en_matcher = &hostapp_en_node.matcher;
            assert_eq!(hostapp_en_matcher.is_some(), true);
            let hostapp_en_matcher = hostapp_en_matcher.as_ref().unwrap();
            assert_eq!(hostapp_en_matcher.is::<DefaultMatcher>(), true);
            let hostapp_en_matcher = hostapp_en_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert_eq!(hostapp_en_matcher.re.is_some(), true);
            let re = hostapp_en_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "Host Application".to_lowercase());

            // LeafSelectionNodeである、ホスト アプリケーションノードが正しいことを確認
            let hostapp_jp_node = ancestors[1].as_ref() as &dyn SelectionNode;
            assert_eq!(hostapp_jp_node.is::<LeafSelectionNode>(), true);
            let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_jp_matcher = &hostapp_jp_node.matcher;
            assert_eq!(hostapp_jp_matcher.is_some(), true);
            let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
            assert_eq!(hostapp_jp_matcher.is::<DefaultMatcher>(), true);
            let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert_eq!(hostapp_jp_matcher.re.is_some(), true);
            let re = hostapp_jp_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "ホスト アプリケーション");
        }

        // ImagePath
        {
            // AndSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[3].as_ref() as &dyn SelectionNode;
            assert_eq!(child_node.is::<AndSelectionNode>(), true);
            let child_node = child_node.downcast_ref::<AndSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 3);

            // min-lenが正しく読み込めることを確認
            {
                let ancestor_node = ancestors[0].as_ref() as &dyn SelectionNode;
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
                let ancestor_node = ancestors[1].as_ref() as &dyn SelectionNode;
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
                let ancestor_node = ancestors[2].as_ref() as &dyn SelectionNode;
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

        let mut rule_node = parse_rule_from_str(rule_str);

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_wildcard_multibyte() {
        // multi byteの確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホストアプリケーション
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_wildcard_multibyte_notdetect() {
        // multi byteの確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホスとアプリケーション
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        // wildcardは大文字小文字関係なくマッチする。
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                    min_length: 10
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                    min_length: 11
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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
                Channel|re: ^Program$
        output: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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
        let mut rule_node = create_rule(rule_yaml.next().unwrap());
        assert_eq!(rule_node.init().is_ok(), true);
        return rule_node;
    }

    #[test]
    fn test_detect_startswith1() {
        // startswithが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_startswith2() {
        // startswithが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_endswith1() {
        // endswithが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_endswith2() {
        // endswithが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_contains1() {
        // containsが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_contains2() {
        // containsが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        output: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
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
        let mut rule_node = create_rule(rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(),
            Err(vec![
                "unknown pipe element was specified. key:detection -> selection -> Channel|failed"
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
        let mut rule_node = create_rule(rule_yaml.next().unwrap());

        assert_eq!(
            rule_node.init(),
            Err(vec!["not found detection node".to_string()])
        );
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_string(), &record), false);
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
        let mut rule_node = create_rule(rule_yaml.next().unwrap());

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

    #[test]
    /// conditionのパイプ(|)が存在しないときに字句解析、構文解析が完了し、パイプ以降の中身がないという結果が得られるかのテスト
    fn test_aggegation_condition_compiler_no_count() {
        // countが無いパターン
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 and select2".to_string());
        assert_eq!(true, result.is_ok());
        let result = result.unwrap();
        assert_eq!(true, result.is_none());
    }

    #[test]
    /// countの後のオペレータの字句解析ができるかのテスト
    fn test_aggegation_condition_compiler_count_ope() {
        // 正常系 countの中身にフィールドが無い 各種演算子を試す
        let token =
            check_aggregation_condition_ope("select1 and select2|count() > 32".to_string(), 32);
        let is_gt = match token {
            AggregationConditionToken::GT => true,
            _ => false,
        };
        assert_eq!(is_gt, true);

        let token =
            check_aggregation_condition_ope("select1 and select2|count() >= 43".to_string(), 43);
        let is_gt = match token {
            AggregationConditionToken::GE => true,
            _ => false,
        };
        assert_eq!(is_gt, true);

        let token =
            check_aggregation_condition_ope("select1 and select2|count() < 59".to_string(), 59);
        let is_gt = match token {
            AggregationConditionToken::LT => true,
            _ => false,
        };
        assert_eq!(is_gt, true);

        let token =
            check_aggregation_condition_ope("select1 and select2|count() <= 12".to_string(), 12);
        let is_gt = match token {
            AggregationConditionToken::LE => true,
            _ => false,
        };
        assert_eq!(is_gt, true);

        let token =
            check_aggregation_condition_ope("select1 and select2|count() == 28".to_string(), 28);
        let is_gt = match token {
            AggregationConditionToken::EQ => true,
            _ => false,
        };
        assert_eq!(is_gt, true);
    }

    #[test]
    /// count() byの字句解析、構文解析ができるかのテスト
    fn test_aggegation_condition_compiler_count_by() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count() by iiibbb > 27".to_string());

        assert_eq!(true, result.is_ok());
        let result = result.unwrap();
        assert_eq!(true, result.is_some());

        let result = result.unwrap();
        assert_eq!("iiibbb".to_string(), result._by_field_name.unwrap());
        assert_eq!(true, result._field_name.is_none());
        assert_eq!(27, result._cmp_num);
        let is_ok = match result._cmp_op {
            AggregationConditionToken::GT => true,
            _ => false,
        };
        assert_eq!(true, is_ok);
    }

    #[test]
    /// conditionのcount,count内の括弧内の変数、オペレータの字句解析、構文解析ができるかのテスト
    fn test_aggegation_condition_compiler_count_field() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge    ) > 3".to_string());

        assert_eq!(true, result.is_ok());
        let result = result.unwrap();
        assert_eq!(true, result.is_some());

        let result = result.unwrap();
        assert_eq!(true, result._by_field_name.is_none());
        assert_eq!("hogehoge", result._field_name.unwrap());
        assert_eq!(3, result._cmp_num);
        let is_ok = match result._cmp_op {
            AggregationConditionToken::GT => true,
            _ => false,
        };
        assert_eq!(true, is_ok);
    }

    #[test]
    /// conditionのcount,count内の括弧内の変数、 count by、count by後のオペレータの字句解析、構文解析ができるかのテスト
    fn test_aggegation_condition_compiler_count_all_field() {
        let compiler = AggegationConditionCompiler::new();
        let result =
            compiler.compile("select1 or select2 | count( hogehoge) by snsn > 3".to_string());

        assert_eq!(true, result.is_ok());
        let result = result.unwrap();
        assert_eq!(true, result.is_some());

        let result = result.unwrap();
        assert_eq!("snsn".to_string(), result._by_field_name.unwrap());
        assert_eq!("hogehoge", result._field_name.unwrap());
        assert_eq!(3, result._cmp_num);
        let is_ok = match result._cmp_op {
            AggregationConditionToken::GT => true,
            _ => false,
        };
        assert_eq!(true, is_ok);
    }

    #[test]
    /// conditionでパイプ以降に何の文字列もない場合にエラーが発生することの確認
    fn test_aggegation_condition_compiler_only_pipe() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 |".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!(
            "aggregation condition parse error has occurred. There are no strings after pipe(|)."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    /// conditionでパイプ以降の構文に登録されていない変数が存在した場合にエラーが出力されるかのテスト
    fn test_aggegation_condition_compiler_unused_character() {
        let compiler = AggegationConditionCompiler::new();
        let result =
            compiler.compile("select1 or select2 | count( hogeess ) by ii-i > 33".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!(
            "aggregation condition parse error has occurred. An unusable character was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    /// パイプの直後に正常な文ではあり得ないbyが先頭に来ている場合に構文解析としてエラーが出力されることを確認するテスト
    fn test_aggegation_condition_compiler_not_count() {
        // countじゃないものが先頭に来ている。
        let compiler = AggegationConditionCompiler::new();
        let result =
            compiler.compile("select1 or select2 | by count( hogehoge) by snsn > 3".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!("aggregation condition parse error has occurred. aggregation condition can use count only.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_no_ope() {
        // 比較演算子がない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) 3".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!("aggregation condition parse error has occurred. count keyword needs compare operator and number like '> 3'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_by() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) by".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!("aggregation condition parse error has occurred. by keyword needs field name like 'by EventID'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_no_ope_afterby() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result =
            compiler.compile("select1 or select2 | count( hogehoge ) by hoe >".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!("aggregation condition parse error has occurred. compare operator needs a number like '> 3'.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_unneccesary_word() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result =
            compiler.compile("select1 or select2 | count( hogehoge ) by hoe > 3 33".to_string());

        assert_eq!(true, result.is_err());
        assert_eq!(
            "aggregation condition parse error has occurred. unnecessary word was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    /// countupでハッシュマップの情報がカウントアップされているかの確認
    fn test_countup() {
        let record_str: &str = r#"
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
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count() >= 1
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        check_count(rule_str, record_str, "_", 1);
    }

    #[test]
    /// countupでハッシュマップの情報がカウントアップされているかの確認
    fn test_countup_field() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count(Channel) >= 1
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        check_count(rule_str, SIMPLE_RECORD_STR, "System_", 1);
    }

    #[test]
    /// count内の引数に有効な条件が指定されている場合
    fn test_count_include_arg() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count(EventID) >= 1
        output: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule(test);
        let init_result = rule_node.init();
        assert_eq!(init_result.is_ok(), true);
        match serde_json::from_str(SIMPLE_RECORD_STR) {
            Ok(record) => {
                let _result = rule_node.select(&"testpath".to_string(), &record);
                let judge_result = rule_node.judge_satisfy_aggcondition();

                assert_eq!(1, judge_result.len());
                assert_eq!("testpath".to_string(), judge_result[0].filepath);
                assert_eq!("7040_".to_string(), judge_result[0].key);
                assert_eq!(true, judge_result[0].result);
                assert_eq!(
                    Utc.ymd(1977, 1, 1).and_hms(0, 0, 0),
                    judge_result[0].start_timedate
                );
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }
    fn test_pipe_pattern_wildcard_asterisk() {
        let value = PipeElement::pipe_pattern_wildcard(r"*ho*ge*".to_string());
        assert_eq!(".*ho.*ge.*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\*ho\*\*ge\*".to_string());
        // wildcardの「\*」は文字列としての「*」を表す。
        // 正規表現で「*」はエスケープする必要があるので、\*が正解
        assert_eq!(r"\*ho\*\*ge\*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk3() {
        // wildcardの「\\*」は文字列としての「\」と正規表現の「.*」を表す。
        // 文字列としての「\」はエスケープされるので、「\\.*」が正解
        let value = PipeElement::pipe_pattern_wildcard(r"\\*ho\\*ge\\*".to_string());
        assert_eq!(r"\\.*ho\\.*ge\\.*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question() {
        let value = PipeElement::pipe_pattern_wildcard(r"?ho?ge?".to_string());
        assert_eq!(r".ho.ge.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\?ho\?ge\?".to_string());
        assert_eq!(r"\?ho\?ge\?", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question3() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\?ho\\?ge\\?".to_string());
        assert_eq!(r"\\.ho\\.ge\\.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_backshash() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\ho\\ge\\".to_string());
        assert_eq!(r"\\\\ho\\\\ge\\\\", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_mixed() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\*\****\*\\*".to_string());
        assert_eq!(r"\\.*\*.*.*.*\*\\.*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_many_backshashs() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\\*ho\\\*ge\\\".to_string());
        assert_eq!(r"\\\\.*ho\\\\.*ge\\\\\\", value);
    }

    //TODO add count test

    fn check_aggregation_condition_ope(expr: String, cmp_num: i32) -> AggregationConditionToken {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile(expr);

        assert_eq!(true, result.is_ok());
        let result = result.unwrap();
        assert_eq!(true, result.is_some());

        let result = result.unwrap();
        assert_eq!(true, result._by_field_name.is_none());
        assert_eq!(true, result._field_name.is_none());
        assert_eq!(cmp_num, result._cmp_num);
        return result._cmp_op;
    }

    fn check_rule_parse_error(rule_str: &str, errmsgs: Vec<String>) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let mut rule_node = create_rule(rule_yaml.next().unwrap());

        assert_eq!(rule_node.init(), Err(errmsgs));
    }
    fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_str) {
            Ok(record) => {
                assert_eq!(
                    rule_node.select(&"testpath".to_string(), &record),
                    expect_select
                );
            }
            Err(_rec) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }
    /// countで対象の数値確認を行うためのテスト用関数
    fn check_count(rule_str: &str, record_str: &str, key: &str, expect_count: i32) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule(test);
        let _init = rule_node.init();
        match serde_json::from_str(record_str) {
            Ok(record) => {
                let result = rule_node.select(&"testpath".to_string(), &record);
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
                assert!(false, "failed to parse json record.");
            }
        }
    }
}

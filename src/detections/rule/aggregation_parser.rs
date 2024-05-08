use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // ここで字句解析するときに使う正規表現の一覧を定義する。
    // ここはSigmaのGithubレポジトリにある、toos/sigma/parser/condition.pyのSigmaConditionTokenizerのtokendefsを参考にしています。
    pub static ref AGGREGATION_REGEXMAP: Vec<Regex> = vec![
        Regex::new(r"^count\( *\w* *\)").unwrap(), // countの式
        Regex::new(r"^ ").unwrap(),
        Regex::new(r"^by").unwrap(),
        Regex::new(r"^==").unwrap(),
        Regex::new(r"^<=").unwrap(),
        Regex::new(r"^>=").unwrap(),
        Regex::new(r"^<").unwrap(),
        Regex::new(r"^>").unwrap(),
        Regex::new(r"^(\s*\w+\s*,)+\s*\w+|^\w+").unwrap(),
    ];
    pub static ref RE_PIPE: Regex = Regex::new(r"\|.*").unwrap();
}

#[derive(Debug)]
pub struct AggregationParseInfo {
    pub _field_name: Option<String>,    // countの括弧に囲まれた部分の文字
    pub _by_field_name: Option<String>, // count() by の後に指定される文字列
    pub _cmp_op: AggregationConditionToken, // (必須)<とか>とか何が指定されたのか
    pub _cmp_num: i64,                  // (必須)<とか>とかの後にある数値
}

#[derive(Debug)]
pub enum AggregationConditionToken {
    Count(String),   // count
    Space,           // 空白
    BY,              // by
    EQ,              // ..と等しい
    LE,              // ..以下
    LT,              // ..未満
    GE,              // ..以上
    GT,              // .よりおおきい
    Keyword(String), // BYのフィールド名
}

/// SIGMAルールでいうAggregationConditionを解析する。
/// AggregationConditionはconditionに指定された式のパイプ以降の部分を指してます。
#[derive(Debug)]
pub struct AggegationConditionCompiler {}

impl AggegationConditionCompiler {
    pub fn new() -> Self {
        AggegationConditionCompiler {}
    }

    pub fn compile(&self, condition_str: &str) -> Result<Option<AggregationParseInfo>, String> {
        let result = self.compile_body(condition_str);
        if let Result::Err(msg) = result {
            Result::Err(format!(
                "An aggregation condition parse error has occurred. {msg}"
            ))
        } else {
            result
        }
    }

    pub fn compile_body(
        &self,
        condition_str: &str,
    ) -> Result<Option<AggregationParseInfo>, String> {
        // パイプの部分だけを取り出す
        let captured = self::RE_PIPE.captures(condition_str);
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
            .replacen('|', "", 1);

        let tokens = self.tokenize(aggregation_str)?;

        self.parse(tokens)
    }

    /// 字句解析します。
    pub fn tokenize(
        &self,
        condition_str: String,
    ) -> Result<Vec<AggregationConditionToken>, String> {
        let mut cur_condition_str = condition_str.as_str();

        let mut tokens = Vec::new();
        while !cur_condition_str.is_empty() {
            let captured = self::AGGREGATION_REGEXMAP.iter().find_map(|regex| {
                return regex.captures(cur_condition_str);
            });
            if captured.is_none() {
                // トークンにマッチしないのはありえないという方針でパースしています。
                return Result::Err("An unusable character was found.".to_string());
            }

            let matched_str = captured.unwrap().get(0).unwrap().as_str();
            let token = self.to_enum(matched_str);

            if let AggregationConditionToken::Space = token {
                // 空白は特に意味ないので、読み飛ばす。
                cur_condition_str = &cur_condition_str[matched_str.len()..];
                continue;
            }

            tokens.push(token);
            cur_condition_str = &cur_condition_str[matched_str.len()..];
        }

        Result::Ok(tokens)
    }

    /// 比較演算子かどうか判定します。
    fn is_cmp_op(&self, token: &AggregationConditionToken) -> bool {
        matches!(
            token,
            AggregationConditionToken::EQ
                | AggregationConditionToken::LE
                | AggregationConditionToken::LT
                | AggregationConditionToken::GE
                | AggregationConditionToken::GT
        )
    }

    /// 構文解析します。
    fn parse(
        &self,
        tokens: Vec<AggregationConditionToken>,
    ) -> Result<Option<AggregationParseInfo>, String> {
        if tokens.is_empty() {
            // パイプしか無いのはおかしいのでエラー
            return Result::Err("There are no strings after the pipe(|).".to_string());
        }

        let mut token_ite = tokens.into_iter();
        let token = token_ite.next().unwrap();

        let mut count_field_name: Option<String> = Option::None;
        if let AggregationConditionToken::Count(field_name) = token {
            if !field_name.is_empty() {
                count_field_name = Option::Some(field_name);
            }
        } else {
            // いろんなパターンがあるので難しいが、countというキーワードしか使えないことを説明しておく。
            return Result::Err("The aggregation condition can only use count.".to_string());
        }

        let token = token_ite.next();
        if token.is_none() {
            // 論理演算子がないのはだめ
            return Result::Err(
                "The count keyword needs a compare operator and number like '> 3'".to_string(),
            );
        }

        // BYはオプションでつけなくても良い
        let mut by_field_name = Option::None;
        let token = token.unwrap();
        let token = if let AggregationConditionToken::BY = token {
            let after_by = token_ite.next();
            if after_by.is_none() {
                // BYの後に何もないのはだめ
                return Result::Err(
                    "The by keyword needs a field name like 'by EventID'".to_string(),
                );
            }

            if let AggregationConditionToken::Keyword(keyword) = after_by.unwrap() {
                by_field_name = Option::Some(keyword);
                token_ite.next()
            } else {
                return Result::Err(
                    "The by keyword needs a field name like 'by EventID'".to_string(),
                );
            }
        } else {
            Option::Some(token)
        };

        // 比較演算子と数値をパース
        if token.is_none() {
            // 論理演算子がないのはだめ
            return Result::Err(
                "The count keyword needs a compare operator and number like '> 3'".to_string(),
            );
        }

        let cmp_token = token.unwrap();
        if !self.is_cmp_op(&cmp_token) {
            return Result::Err(
                "The count keyword needs a compare operator and number like '> 3'".to_string(),
            );
        }

        let token = token_ite.next().unwrap_or(AggregationConditionToken::Space);
        let cmp_number = if let AggregationConditionToken::Keyword(number) = token {
            let number: Result<i64, _> = number.parse();
            if let Ok(num) = number {
                num
            } else {
                // 比較演算子の後に数値が無い。
                return Result::Err("The compare operator needs a number like '> 3'.".to_string());
            }
        } else {
            // 比較演算子の後に数値が無い。
            return Result::Err("The compare operator needs a number like '> 3'.".to_string());
        };

        if token_ite.next().is_some() {
            return Result::Err("An unnecessary word was found.".to_string());
        }

        let info = AggregationParseInfo {
            _field_name: count_field_name,
            _by_field_name: by_field_name,
            _cmp_op: cmp_token,
            _cmp_num: cmp_number,
        };
        Result::Ok(Option::Some(info))
    }

    /// 文字列をConditionTokenに変換する。
    fn to_enum(&self, token: &str) -> AggregationConditionToken {
        if token.starts_with("count(") {
            let count_field = token
                .replacen("count(", "", 1)
                .replacen(')', "", 1)
                .replace(' ', "");
            AggregationConditionToken::Count(count_field)
        } else if token == " " {
            AggregationConditionToken::Space
        } else if token == "by" {
            AggregationConditionToken::BY
        } else if token == "==" {
            AggregationConditionToken::EQ
        } else if token == "<=" {
            AggregationConditionToken::LE
        } else if token == ">=" {
            AggregationConditionToken::GE
        } else if token == "<" {
            AggregationConditionToken::LT
        } else if token == ">" {
            AggregationConditionToken::GT
        } else {
            AggregationConditionToken::Keyword(token.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::aggregation_parser::{
        AggegationConditionCompiler, AggregationConditionToken,
    };

    #[test]
    fn test_aggegation_condition_compiler_no_count() {
        // countが無いパターン
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 and select2");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_aggegation_condition_compiler_count_ope() {
        // 正常系 countの中身にフィールドが無い 各種演算子を試す
        let token =
            check_aggregation_condition_ope("select1 and select2|count() > 32".to_string(), 32);
        assert!(matches!(token, AggregationConditionToken::GT));

        let token =
            check_aggregation_condition_ope("select1 and select2|count() >= 43".to_string(), 43);
        assert!(matches!(token, AggregationConditionToken::GE));

        let token =
            check_aggregation_condition_ope("select1 and select2|count() < 59".to_string(), 59);
        assert!(matches!(token, AggregationConditionToken::LT));

        let token =
            check_aggregation_condition_ope("select1 and select2|count() <= 12".to_string(), 12);
        assert!(matches!(token, AggregationConditionToken::LE));

        let token =
            check_aggregation_condition_ope("select1 and select2|count() == 28".to_string(), 28);
        assert!(matches!(token, AggregationConditionToken::EQ));
    }

    #[test]
    fn test_aggegation_condition_compiler_count_by() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count() by iiibbb > 27");

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!("iiibbb".to_string(), result._by_field_name.unwrap());
        assert!(result._field_name.is_none());
        assert_eq!(27, result._cmp_num);
        assert!(matches!(result._cmp_op, AggregationConditionToken::GT));
    }

    #[test]
    fn test_aggegation_condition_compiler_count_by_multiple_fieilds() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count() by iiibbb,aaabbb > 27");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!("iiibbb,aaabbb".to_string(), result._by_field_name.unwrap());
        assert!(result._field_name.is_none());
        assert_eq!(27, result._cmp_num);
        assert!(matches!(result._cmp_op, AggregationConditionToken::GT));
    }

    #[test]
    fn test_aggegation_condition_compiler_count_by_multiple_fieilds_with_space() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count() by iiibbb, aaabbb > 27");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!("iiibbb, aaabbb".to_string(), result._by_field_name.unwrap());
        assert!(result._field_name.is_none());
        assert_eq!(27, result._cmp_num);
        assert!(matches!(result._cmp_op, AggregationConditionToken::GT));
    }

    #[test]
    fn test_aggegation_condition_compiler_count_field() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge    ) > 3");

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(result._by_field_name.is_none());
        assert_eq!("hogehoge", result._field_name.unwrap());
        assert_eq!(3, result._cmp_num);
        assert!(matches!(result._cmp_op, AggregationConditionToken::GT));
    }

    #[test]
    fn test_aggegation_condition_compiler_count_all_field() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) by snsn > 3");

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!("snsn".to_string(), result._by_field_name.unwrap());
        assert_eq!("hogehoge", result._field_name.unwrap());
        assert_eq!(3, result._cmp_num);
        assert!(matches!(result._cmp_op, AggregationConditionToken::GT));
    }

    #[test]
    fn test_aggegation_condition_compiler_only_pipe() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 |");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. There are no strings after the pipe(|)."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    fn test_aggegation_condition_compiler_unused_character() {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogeess ) by ii-i > 33");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. An unusable character was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    fn test_aggegation_condition_compiler_not_count() {
        // countじゃないものが先頭に来ている。
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | by count( hogehoge) by snsn > 3");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The aggregation condition can only use count.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_no_ope() {
        // 比較演算子がない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) 3");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The count keyword needs a compare operator and number like '> 3'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_by() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) by");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The by keyword needs a field name like 'by EventID'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_no_ope_afterby() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge ) by hoe >");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The compare operator needs a number like '> 3'.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggegation_condition_compiler_unneccesary_word() {
        // byの後に何もない
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge ) by hoe > 3 33");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. An unnecessary word was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    fn check_aggregation_condition_ope(expr: String, cmp_num: i64) -> AggregationConditionToken {
        let compiler = AggegationConditionCompiler::new();
        let result = compiler.compile(&expr);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(result._by_field_name.is_none());
        assert!(result._field_name.is_none());
        assert_eq!(cmp_num, result._cmp_num);
        result._cmp_op
    }
}

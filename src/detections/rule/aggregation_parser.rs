use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Define the list of regular expressions used for lexical analysis here.
    // This is based on the tokendefs of SigmaConditionTokenizer in tools/sigma/parser/condition.py
    // in the Sigma GitHub repository.
    pub static ref AGGREGATION_REGEXMAP: Vec<Regex> = vec![
        Regex::new(r"^count\( *\w* *\)").unwrap(), // count expression
        Regex::new(r"^ ").unwrap(),
        Regex::new(r"^by").unwrap(),
        Regex::new(r"^==").unwrap(),
        Regex::new(r"^<=").unwrap(),
        Regex::new(r"^>=").unwrap(),
        Regex::new(r"^<").unwrap(),
        Regex::new(r"^>").unwrap(),
        Regex::new(r"^(\s*\w+\s*,)+\s*\w+|^\w+").unwrap(),
    ];
    // Matches the aggregation part of a condition: everything from the pipe character to the end.
    pub static ref RE_PIPE: Regex = Regex::new(r"\|.*").unwrap();
}

/// Parsed form of an aggregation condition such as "count(SubjectUserName) by Computer >= 10".
#[derive(Debug)]
pub struct AggregationParseInfo {
    pub _field_name: Option<String>, // Field name inside the parentheses of count(); None for a plain count().
    pub _by_field_name: Option<String>, // Field name(s) after the "by" keyword; comma-separated when multiple.
    pub _cmp_op: AggregationConditionToken, // (Required) The comparison operator, e.g. < or >.
    pub _cmp_num: i64,                  // (Required) The number to compare the count against.
}

/// A lexical token of an aggregation condition.
#[derive(Debug)]
pub enum AggregationConditionToken {
    Count(String), // count(...); the String is the field name in the parentheses (may be empty)
    Space,         // Whitespace
    BY,            // by
    EQ,            // Equal to (==)
    LE,            // Less than or equal to (<=)
    LT,            // Less than (<)
    GE,            // Greater than or equal to (>=)
    GT,            // Greater than (>)
    Keyword(String), // Bare word: the field name(s) after "by" or the number after a comparison operator
}

/// Parses the AggregationCondition as defined in SIGMA rules.
/// AggregationCondition refers to the part after the pipe in the expression specified in condition.
#[derive(Debug)]
pub struct AggregationConditionCompiler {}

impl AggregationConditionCompiler {
    pub fn new() -> Self {
        AggregationConditionCompiler {}
    }

    /// Compiles the aggregation part (everything after the pipe) of a condition string.
    /// Returns Ok(None) when the condition contains no pipe, i.e. has no aggregation condition.
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
        // Extract only the pipe portion.
        let captured = self::RE_PIPE.captures(condition_str);
        if captured.is_none() {
            // No pipe found, so terminate.
            return Result::Ok(Option::None);
        }
        // Remove the pipe itself before parsing.
        let aggregation_str = captured
            .unwrap()
            .get(0)
            .unwrap()
            .as_str()
            .replacen('|', "", 1);

        let tokens = self.tokenize(aggregation_str)?;

        self.parse(tokens)
    }

    /// Performs lexical analysis.
    pub fn tokenize(
        &self,
        condition_str: String,
    ) -> Result<Vec<AggregationConditionToken>, String> {
        let mut cur_condition_str = condition_str.as_str();

        let mut tokens = Vec::new();
        while !cur_condition_str.is_empty() {
            let captured = self::AGGREGATION_REGEXMAP
                .iter()
                .find_map(|regex| regex.captures(cur_condition_str));
            if captured.is_none() {
                // The token definitions are meant to cover every valid input, so any character
                // sequence that matches no token is treated as an error.
                return Result::Err("An unusable character was found.".to_string());
            }

            let matched_str = captured.unwrap().get(0).unwrap().as_str();
            let token = self.to_enum(matched_str);

            if let AggregationConditionToken::Space = token {
                // Whitespace has no special meaning, so skip it.
                cur_condition_str = &cur_condition_str[matched_str.len()..];
                continue;
            }

            tokens.push(token);
            cur_condition_str = &cur_condition_str[matched_str.len()..];
        }

        Result::Ok(tokens)
    }

    /// Determines whether it is a comparison operator.
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

    /// Performs syntactic analysis.
    fn parse(
        &self,
        tokens: Vec<AggregationConditionToken>,
    ) -> Result<Option<AggregationParseInfo>, String> {
        if tokens.is_empty() {
            // Having only a pipe is invalid, so return an error.
            return Result::Err("There are no strings after the pipe(|).".to_string());
        }

        let mut token_iter = tokens.into_iter();
        let token = token_iter.next().unwrap();

        let mut count_field_name: Option<String> = Option::None;
        if let AggregationConditionToken::Count(field_name) = token {
            if !field_name.is_empty() {
                count_field_name = Option::Some(field_name);
            }
        } else {
            // The Sigma spec defines other aggregation functions besides count, but supporting
            // the many possible patterns would get complex, so only the count keyword is
            // accepted here.
            return Result::Err("The aggregation condition can only use count.".to_string());
        }

        let token = token_iter.next();
        if token.is_none() {
            // Missing comparison operator is invalid.
            return Result::Err(
                "The count keyword needs a compare operator and number like '> 3'".to_string(),
            );
        }

        // BY is optional and may be omitted.
        let mut by_field_name = Option::None;
        let token = token.unwrap();
        let token = if let AggregationConditionToken::BY = token {
            let after_by = token_iter.next();
            if after_by.is_none() {
                // Nothing after BY is invalid.
                return Result::Err(
                    "The by keyword needs a field name like 'by EventID'".to_string(),
                );
            }

            if let AggregationConditionToken::Keyword(keyword) = after_by.unwrap() {
                by_field_name = Option::Some(keyword);
                token_iter.next()
            } else {
                return Result::Err(
                    "The by keyword needs a field name like 'by EventID'".to_string(),
                );
            }
        } else {
            Option::Some(token)
        };

        // Parse comparison operator and number.
        if token.is_none() {
            // Missing comparison operator is invalid.
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

        // Space serves as a dummy token here: if the input ends right after the comparison
        // operator, the if-let below falls through to the "needs a number" error.
        let token = token_iter
            .next()
            .unwrap_or(AggregationConditionToken::Space);
        let cmp_number = if let AggregationConditionToken::Keyword(number) = token {
            let number: Result<i64, _> = number.parse();
            if let Ok(num) = number {
                num
            } else {
                // No number after comparison operator.
                return Result::Err("The compare operator needs a number like '> 3'.".to_string());
            }
        } else {
            // No number after comparison operator.
            return Result::Err("The compare operator needs a number like '> 3'.".to_string());
        };

        if token_iter.next().is_some() {
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

    /// Converts a matched token string into an AggregationConditionToken.
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
        AggregationConditionCompiler, AggregationConditionToken,
    };

    #[test]
    fn test_aggregation_condition_compiler_no_count() {
        // Pattern without count.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 and select2");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_aggregation_condition_compiler_count_ope() {
        // Normal case: no field inside count, try various operators.
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
    fn test_aggregation_condition_compiler_count_by() {
        let compiler = AggregationConditionCompiler::new();
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
    fn test_aggregation_condition_compiler_count_by_multiple_fields() {
        let compiler = AggregationConditionCompiler::new();
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
    fn test_aggregation_condition_compiler_count_by_multiple_fields_with_space() {
        let compiler = AggregationConditionCompiler::new();
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
    fn test_aggregation_condition_compiler_count_field() {
        let compiler = AggregationConditionCompiler::new();
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
    fn test_aggregation_condition_compiler_count_all_field() {
        let compiler = AggregationConditionCompiler::new();
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
    fn test_aggregation_condition_compiler_only_pipe() {
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 |");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. There are no strings after the pipe(|)."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    fn test_aggregation_condition_compiler_unused_character() {
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogeess ) by ii-i > 33");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. An unusable character was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    #[test]
    fn test_aggregation_condition_compiler_not_count() {
        // Something other than count is at the beginning.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | by count( hogehoge) by snsn > 3");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The aggregation condition can only use count.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggregation_condition_compiler_no_ope() {
        // Missing comparison operator.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) 3");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The count keyword needs a compare operator and number like '> 3'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggregation_condition_compiler_by() {
        // Nothing after by.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge) by");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The by keyword needs a field name like 'by EventID'".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggregation_condition_compiler_no_ope_afterby() {
        // No number after the comparison operator.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge ) by hoe >");

        assert!(result.is_err());
        assert_eq!("An aggregation condition parse error has occurred. The compare operator needs a number like '> 3'.".to_string(),result.unwrap_err());
    }

    #[test]
    fn test_aggregation_condition_compiler_unnecessary_word() {
        // An extra token after the number.
        let compiler = AggregationConditionCompiler::new();
        let result = compiler.compile("select1 or select2 | count( hogehoge ) by hoe > 3 33");

        assert!(result.is_err());
        assert_eq!(
            "An aggregation condition parse error has occurred. An unnecessary word was found."
                .to_string(),
            result.unwrap_err()
        );
    }

    fn check_aggregation_condition_ope(expr: String, cmp_num: i64) -> AggregationConditionToken {
        let compiler = AggregationConditionCompiler::new();
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

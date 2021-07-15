use regex::Regex;
use serde_json::Value;
use std::collections::VecDeque;
use yaml_rust::Yaml;

use crate::detections::utils;
use mopa::mopafy;

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
pub trait LeafMatcher: mopa::Any {
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
pub struct MinlengthMatcher {
    min_len: i64,
}

impl MinlengthMatcher {
    pub fn new() -> MinlengthMatcher {
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
                utils::concat_selection_key(key_list)
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
pub struct RegexesFileMatcher {
    regexes_csv_content: Vec<Vec<String>>,
}

impl RegexesFileMatcher {
    pub fn new() -> RegexesFileMatcher {
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
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let csv_content = utils::read_csv(&value.unwrap());
        if csv_content.is_err() {
            let errmsg = format!(
                "cannot read regexes file. [key:{}]",
                utils::concat_selection_key(key_list)
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
pub struct WhitelistFileMatcher {
    whitelist_csv_content: Vec<Vec<String>>,
}

impl WhitelistFileMatcher {
    pub fn new() -> WhitelistFileMatcher {
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
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let csv_content = utils::read_csv(&value.unwrap());
        if csv_content.is_err() {
            let errmsg = format!(
                "cannot read whitelist file. [key:{}]",
                utils::concat_selection_key(key_list)
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
pub struct DefaultMatcher {
    re: Option<Regex>,
    pipes: Vec<PipeElement>,
}

impl DefaultMatcher {
    pub fn new() -> DefaultMatcher {
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
                utils::concat_selection_key(key_list)
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
                    utils::concat_selection_key(key_list)
                );
                return Result::Err(vec![errmsg]);
            }

            self.pipes.push(pipe_element.unwrap());
        }
        if self.pipes.len() >= 2 {
            // 現状では複数のパイプは対応していない
            let errmsg = format!(
                "multiple pipe element can't be used. key:{}",
                utils::concat_selection_key(key_list)
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
                utils::concat_selection_key(key_list)
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
    use super::super::matchers::{
        DefaultMatcher, MinlengthMatcher, PipeElement, RegexesFileMatcher, WhitelistFileMatcher,
    };
    use super::super::selectionnodes::{
        AndSelectionNode, LeafSelectionNode, OrSelectionNode, SelectionNode,
    };
    use crate::detections::rule::tests::parse_rule_from_str;

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
        let mut rule_node = parse_rule_from_str(rule_str);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
            }
            Err(_rec) => {
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), false);
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
                assert_eq!(rule_node.select(&"testpath".to_owned(), &record), true);
            }
            Err(_) => {
                assert!(false, "failed to parse json record.");
            }
        }
    }

    #[test]
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
}

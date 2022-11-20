use nested::Nested;
use regex::Regex;
use std::{cmp::Ordering, collections::VecDeque};
use yaml_rust::Yaml;

use crate::detections::{detection::EvtxRecordInfo, utils};
use downcast_rs::Downcast;

use lazy_static::lazy_static;
lazy_static! {
    pub static ref STR_DEFAULT: String = String::default();
}

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
pub trait LeafMatcher: Downcast {
    /// 指定されたkey_listにマッチするLeafMatcherであるかどうか判定する。
    fn is_target_key(&self, key_list: &Nested<String>) -> bool;

    /// 引数に指定されたJSON形式のデータがマッチするかどうか判定する。
    /// main.rsでWindows Event LogをJSON形式に変換していて、そのJSON形式のWindowsのイベントログデータがここには来る
    /// 例えば正規表現でマッチするロジックなら、ここに正規表現でマッチさせる処理を書く。
    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool;

    /// 初期化ロジックをここに記載します。
    /// ルールファイルの書き方が間違っている等の原因により、正しくルールファイルからパースできない場合、戻り値のResult型でエラーを返してください。
    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>>;
}
downcast_rs::impl_downcast!(LeafMatcher);

/// 指定された文字数以上であることをチェックするクラス。
pub struct MinlengthMatcher {
    min_len: i64,
}

impl MinlengthMatcher {
    pub fn new() -> MinlengthMatcher {
        MinlengthMatcher { min_len: 0 }
    }
}

impl LeafMatcher for MinlengthMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        return key_list.get(1).unwrap() == "min_length";
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let min_length = select_value.as_i64();
        if min_length.is_none() {
            let errmsg = format!(
                "min_length value should be an integer. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        self.min_len = min_length.unwrap();
        Result::Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => s.len() as i64 >= self.min_len,
            None => false,
        }
    }
}

/// 正規表現のリストが記載されたファイルを読み取って、比較するロジックを表すクラス
/// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
pub struct RegexesFileMatcher {
    regexes: Vec<Regex>,
}

impl RegexesFileMatcher {
    pub fn new() -> RegexesFileMatcher {
        RegexesFileMatcher { regexes: vec![] }
    }
}

impl LeafMatcher for RegexesFileMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        key_list.get(1).unwrap() == "regexes"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Option::Some(s.to_owned()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_owned()),
            _ => Option::None,
        };
        if value.is_none() {
            let errmsg = format!(
                "regexes value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let regexes_strs = utils::read_txt(&value.unwrap());
        if regexes_strs.is_err() {
            return Result::Err(vec![regexes_strs.unwrap_err()]);
        }
        let regexes_strs = regexes_strs.unwrap();
        self.regexes = regexes_strs
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Result::Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => utils::check_regex(s, &self.regexes),
            None => false,
        }
    }
}

/// ファイルに列挙された文字列に一致する場合に検知するロジックを表す
/// DeepBlueCLIのcheck_cmdメソッドの一部に同様の処理が実装されていた。
pub struct AllowlistFileMatcher {
    regexes: Vec<Regex>,
}

impl AllowlistFileMatcher {
    pub fn new() -> AllowlistFileMatcher {
        AllowlistFileMatcher { regexes: vec![] }
    }
}

impl LeafMatcher for AllowlistFileMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() != 2 {
            return false;
        }

        return key_list.get(1).unwrap() == "allowlist";
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Option::Some(s.to_owned()),
            Yaml::Integer(i) => Option::Some(i.to_string()),
            Yaml::Real(r) => Option::Some(r.to_owned()),
            _ => Option::None,
        };
        if value.is_none() {
            let errmsg = format!(
                "allowlist value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let regexes_strs = utils::read_txt(&value.unwrap());
        if regexes_strs.is_err() {
            return Result::Err(vec![regexes_strs.unwrap_err()]);
        }
        self.regexes = regexes_strs
            .unwrap()
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Result::Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, _recinfo: &EvtxRecordInfo) -> bool {
        match event_value {
            Some(s) => !utils::check_allowlist(s, &self.regexes),
            None => true,
        }
    }
}

/// デフォルトのマッチクラス
/// ワイルドカードの処理やパイプ
pub struct DefaultMatcher {
    re: Option<Regex>,
    pipes: Vec<PipeElement>,
    key_list: Nested<String>,
    eqfield_key: Option<String>,
}

impl DefaultMatcher {
    pub fn new() -> DefaultMatcher {
        DefaultMatcher {
            re: Option::None,
            pipes: Vec::new(),
            key_list: Nested::<String>::new(),
            eqfield_key: Option::None,
        }
    }

    pub fn get_eqfield_key(&self) -> Option<&String> {
        self.eqfield_key.as_ref()
    }

    /// このmatcherの正規表現とマッチするかどうか判定します。
    /// 判定対象の文字列とこのmatcherが保持する正規表現が完全にマッチした場合のTRUEを返します。
    /// 例えば、判定対象文字列が"abc"で、正規表現が"ab"の場合、正規表現は判定対象文字列の一部分にしか一致していないので、この関数はfalseを返します。
    fn is_regex_fullmatch(&self, value: &str) -> bool {
        return self.re.as_ref().unwrap().find_iter(value).any(|match_obj| {
            return match_obj.as_str() == value;
        });
    }

    /// Hayabusaのルールファイルのフィールド名とそれに続いて指定されるパイプを、正規表現形式の文字列に変換します。
    /// ワイルドカードの文字列を正規表現にする処理もこのメソッドに実装されています。patternにワイルドカードの文字列を指定して、pipesにPipeElement::Wildcardを指定すればOK!!
    fn from_pattern_to_regex_str(pattern: String, pipes: &[PipeElement]) -> String {
        // パターンをPipeで処理する。
        pipes
            .iter()
            .fold(pattern, |acc, pipe| pipe.pipe_pattern(acc))
    }
}

impl LeafMatcher for DefaultMatcher {
    fn is_target_key(&self, key_list: &Nested<String>) -> bool {
        if key_list.len() <= 1 {
            return true;
        }

        return key_list.get(1).unwrap_or("") == "value";
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let mut tmp_key_list = Nested::<String>::new();
        tmp_key_list.extend(key_list.iter());
        self.key_list = tmp_key_list;
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
                "An unknown error occured. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }
        let pattern = yaml_value.unwrap();

        // Pipeが指定されていればパースする
        let emp = String::default();
        let mut keys: VecDeque<&str> = key_list.get(0).unwrap_or(&emp).split('|').collect(); // key_listが空はあり得ない
        keys.pop_front(); // 一つ目はただのキーで、2つめ以降がpipe
        while !keys.is_empty() {
            let key = keys.pop_front().unwrap();
            let pipe_element = match key {
                "startswith" => Option::Some(PipeElement::Startswith),
                "endswith" => Option::Some(PipeElement::Endswith),
                "contains" => Option::Some(PipeElement::Contains),
                "re" => Option::Some(PipeElement::Re),
                "equalsfield" => Option::Some(PipeElement::EqualsField),
                _ => Option::None,
            };
            if pipe_element.is_none() {
                let errmsg = format!(
                    "An unknown pipe element was specified. key:{}",
                    utils::concat_selection_key(key_list)
                );
                return Result::Err(vec![errmsg]);
            }

            self.pipes.push(pipe_element.unwrap());
        }
        if self.pipes.len() >= 2 {
            // 現状では複数のパイプは対応していない
            let errmsg = format!(
                "Multiple pipe elements cannot be used. key:{}",
                utils::concat_selection_key(key_list)
            );
            return Result::Err(vec![errmsg]);
        }

        let is_eqfield = self
            .pipes
            .iter()
            .any(|pipe_element| matches!(pipe_element, PipeElement::EqualsField));
        if is_eqfield {
            // PipeElement::EqualsFieldは特別
            self.eqfield_key = Option::Some(pattern);
        } else {
            // 正規表現ではない場合、ワイルドカードであることを表す。
            // ワイルドカードは正規表現でマッチングするので、ワイルドカードを正規表現に変換するPipeを内部的に追加することにする。
            let is_re = self
                .pipes
                .iter()
                .any(|pipe_element| matches!(pipe_element, PipeElement::Re));
            if !is_re {
                self.pipes.push(PipeElement::Wildcard);
            }

            let pattern = DefaultMatcher::from_pattern_to_regex_str(pattern, &self.pipes);
            // Pipeで処理されたパターンを正規表現に変換
            let re_result = Regex::new(&pattern);
            if re_result.is_err() {
                let errmsg = format!(
                    "Cannot parse regex. [regex:{}, key:{}]",
                    pattern,
                    utils::concat_selection_key(key_list)
                );
                return Result::Err(vec![errmsg]);
            }
            self.re = re_result.ok();
        }

        Result::Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        // PipeElement::EqualsFieldが設定されていた場合
        if let Some(eqfield_key) = &self.eqfield_key {
            let another_value = recinfo.get_value(eqfield_key);
            // Evtxのレコードに存在しないeventkeyを指定された場合はfalseにする
            if event_value.is_none() || another_value.is_none() {
                return false;
            }

            return another_value.unwrap().cmp(event_value.unwrap()) == Ordering::Equal;
        }

        // yamlにnullが設定されていた場合
        // keylistが空(==JSONのgrep検索)の場合、無視する。
        if self.key_list.is_empty() && self.re.is_none() {
            return false;
        }

        // yamlにnullが設定されていた場合
        if self.re.is_none() {
            // レコード内に対象のフィールドが存在しなければ検知したものとして扱う
            for v in self.key_list.iter() {
                if recinfo.get_value(v).is_none() {
                    return true;
                }
            }
            return false;
        }

        if event_value.is_none() {
            return false;
        }

        let event_value_str = event_value.unwrap();
        if self.key_list.is_empty() {
            // この場合ただのgrep検索なので、ただ正規表現に一致するかどうか調べればよいだけ
            self.re.as_ref().unwrap().is_match(event_value_str)
        } else {
            // 通常の検索はこっち
            self.is_regex_fullmatch(event_value_str)
        }
    }
}

/// パイプ(|)で指定される要素を表すクラス。
enum PipeElement {
    Startswith,
    Endswith,
    Contains,
    Re,
    Wildcard,
    EqualsField,
}

impl PipeElement {
    /// patternをパイプ処理します
    fn pipe_pattern(&self, pattern: String) -> String {
        // enumでポリモーフィズムを実装すると、一つのメソッドに全部の型の実装をする感じになる。Java使い的にはキモイ感じがする。
        let fn_add_asterisk_end = |patt: String| {
            if patt.ends_with("//*") {
                patt
            } else if patt.ends_with("/*") {
                patt + "*"
            } else if patt.ends_with('*') {
                patt
            } else {
                patt + "*"
            }
        };
        let fn_add_asterisk_begin = |patt: String| {
            if patt.starts_with("//*") {
                patt
            } else if patt.starts_with("/*") {
                "*".to_string() + &patt
            } else if patt.starts_with('*') {
                patt
            } else {
                "*".to_string() + &patt
            }
        };

        match self {
            // startswithの場合はpatternの最後にwildcardを足すことで対応する
            PipeElement::Startswith => fn_add_asterisk_end(pattern),
            // endswithの場合はpatternの最初にwildcardを足すことで対応する
            PipeElement::Endswith => fn_add_asterisk_begin(pattern),
            // containsの場合はpatternの前後にwildcardを足すことで対応する
            PipeElement::Contains => fn_add_asterisk_end(fn_add_asterisk_begin(pattern)),
            // WildCardは正規表現に変換する。
            PipeElement::Wildcard => PipeElement::pipe_pattern_wildcard(pattern),
            _ => pattern,
        }
    }

    /// PipeElement::Wildcardのパイプ処理です。
    /// pipe_pattern()に含めて良い処理ですが、複雑な処理になってしまったので別関数にしました。
    fn pipe_pattern_wildcard(pattern: String) -> String {
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
        let ret = pattern_splits.iter().enumerate().fold(
            String::default(),
            |acc: String, (idx, pattern)| {
                let regex_value = if idx % 2 == 0 {
                    // wildcardじゃない場合はescapeした文字列を返す
                    regex::escape(pattern)
                } else {
                    // wildcardの場合、"*"は".*"という正規表現に変換し、"?"は"."に変換する。
                    let wildcard_regex_value = if *pattern == "*" {
                        "(.|\\a|\\f|\\t|\\n|\\r|\\v)*"
                    } else {
                        "."
                    };
                    wildcard_regex_value.to_string()
                };

                format!("{}{}", acc, regex_value)
            },
        );

        // sigmaのwildcardはcase insensitive
        // なので、正規表現の先頭にcase insensitiveであることを表す記号を付与
        "(?i)".to_string() + &ret
    }
}

#[cfg(test)]
mod tests {
    use super::super::matchers::{
        AllowlistFileMatcher, DefaultMatcher, MinlengthMatcher, PipeElement, RegexesFileMatcher,
    };
    use super::super::selectionnodes::{
        AndSelectionNode, LeafSelectionNode, OrSelectionNode, SelectionNode,
    };
    use crate::detections::rule::tests::parse_rule_from_str;
    use crate::detections::{self, utils};

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
                    regexes: rules/config/regex/detectlist_suspicous_services.txt
                    allowlist: rules/config/regex/allowlist_legitimate_services.txt
        falsepositives:
            - unknown
        level: medium
        details: 'command=%CommandLine%'
        creation_date: 2020/11/8
        updated_date: 2020/11/8
        "#;
        let rule_node = parse_rule_from_str(rule_str);
        let selection_node = &rule_node.detection.name_to_selection["selection"];

        // Root
        let detection_childs = selection_node.get_childs();
        assert_eq!(detection_childs.len(), 4);

        // Channel
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[0] as &dyn SelectionNode; //  TODO キャストしないとエラーでるけど、このキャストよく分からん。
            assert!(child_node.is::<LeafSelectionNode>());
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "Channel");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert!(matcher.is_some());
            let matcher = child_node.matcher.as_ref().unwrap();
            assert!(matcher.is::<DefaultMatcher>());
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

            assert!(matcher.re.is_some());
            let re = matcher.re.as_ref();
            assert_eq!(
                re.unwrap().as_str(),
                r"(?i)Microsoft\-Windows\-PowerShell/Operational"
            );
        }

        // EventID
        {
            // LeafSelectionNodeが正しく読み込めることを確認
            let child_node = detection_childs[1] as &dyn SelectionNode;
            assert!(child_node.is::<LeafSelectionNode>());
            let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
            assert_eq!(child_node.get_key(), "EventID");
            assert_eq!(child_node.get_childs().len(), 0);

            // 比較する正規表現が正しいことを確認
            let matcher = &child_node.matcher;
            assert!(matcher.is_some());
            let matcher = child_node.matcher.as_ref().unwrap();
            assert!(matcher.is::<DefaultMatcher>());
            let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

            assert!(matcher.re.is_some());
            let re = matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "(?i)4103");
        }

        // ContextInfo
        {
            // OrSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[2] as &dyn SelectionNode;
            assert!(child_node.is::<OrSelectionNode>());
            let child_node = child_node.downcast_ref::<OrSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 2);

            // OrSelectionNodeの下にLeafSelectionNodeがあるパターンをテスト
            // LeafSelectionNodeである、Host Applicationノードが正しいことを確認
            let hostapp_en_node = ancestors[0] as &dyn SelectionNode;
            assert!(hostapp_en_node.is::<LeafSelectionNode>());
            let hostapp_en_node = hostapp_en_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_en_matcher = &hostapp_en_node.matcher;
            assert!(hostapp_en_matcher.is_some());
            let hostapp_en_matcher = hostapp_en_matcher.as_ref().unwrap();
            assert!(hostapp_en_matcher.is::<DefaultMatcher>());
            let hostapp_en_matcher = hostapp_en_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(hostapp_en_matcher.re.is_some());
            let re = hostapp_en_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "(?i)Host Application");

            // LeafSelectionNodeである、ホスト アプリケーションノードが正しいことを確認
            let hostapp_jp_node = ancestors[1] as &dyn SelectionNode;
            assert!(hostapp_jp_node.is::<LeafSelectionNode>());
            let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_jp_matcher = &hostapp_jp_node.matcher;
            assert!(hostapp_jp_matcher.is_some());
            let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
            assert!(hostapp_jp_matcher.is::<DefaultMatcher>());
            let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(hostapp_jp_matcher.re.is_some());
            let re = hostapp_jp_matcher.re.as_ref();
            assert_eq!(re.unwrap().as_str(), "(?i)ホスト アプリケーション");
        }

        // ImagePath
        {
            // AndSelectionNodeを正しく読み込めることを確認
            let child_node = detection_childs[3] as &dyn SelectionNode;
            assert!(child_node.is::<AndSelectionNode>());
            let child_node = child_node.downcast_ref::<AndSelectionNode>().unwrap();
            let ancestors = child_node.get_childs();
            assert_eq!(ancestors.len(), 3);

            // min-lenが正しく読み込めることを確認
            {
                let ancestor_node = ancestors[0] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<MinlengthMatcher>());
                let ancestor_matcher = ancestor_matcher.downcast_ref::<MinlengthMatcher>().unwrap();
                assert_eq!(ancestor_matcher.min_len, 1234321);
            }

            // regexesが正しく読み込めることを確認
            {
                let ancestor_node = ancestors[1] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<RegexesFileMatcher>());
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<RegexesFileMatcher>()
                    .unwrap();

                // regexes.txtの中身と一致していることを確認
                let csvcontent = &ancestor_matcher.regexes;

                assert_eq!(csvcontent.len(), 16);
                assert_eq!(
                    csvcontent[0].as_str().to_string(),
                    r"^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$"
                );
                assert_eq!(
                    csvcontent[13].as_str().to_string(),
                    r"\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp"
                );
            }

            // allowlist.txtが読み込めることを確認
            {
                let ancestor_node = ancestors[2] as &dyn SelectionNode;
                assert!(ancestor_node.is::<LeafSelectionNode>());
                let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

                let ancestor_node = &ancestor_node.matcher;
                assert!(ancestor_node.is_some());
                let ancestor_matcher = ancestor_node.as_ref().unwrap();
                assert!(ancestor_matcher.is::<AllowlistFileMatcher>());
                let ancestor_matcher = ancestor_matcher
                    .downcast_ref::<AllowlistFileMatcher>()
                    .unwrap();

                let csvcontent = &ancestor_matcher.regexes;
                assert_eq!(csvcontent.len(), 2);

                assert_eq!(
                    csvcontent[0].as_str().to_string(),
                    r#"^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe""#.to_string()
                );
                assert_eq!(
                    csvcontent[1].as_str().to_string(),
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 410}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);

        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Securit"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ecurity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"Channel": ""}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security9", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security.11", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_regexes() {
        // regexes.txtが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、allowlistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: rules/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_allowlist() {
        // allowlistが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、allowlistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: rules/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_allowlist2() {
        // allowlistが正しく検知できることを確認
        // この場合ではEventIDが一致しているが、allowlistに一致するので検知しないはず。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: rules/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_startswith_case_insensitive() {
        // startswithが大文字小文字を区別しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "ADMINISTRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_endswith_case_insensitive() {
        // endswithが大文字小文字を区別せず検知するかを確認するテスト
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "ADministRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_contains_case_insensitive() {
        // containsが大文字小文字を区別せずに検知することを確認するテスト
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "ADminIstraTOrS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
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
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_rec) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
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
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk() {
        let value = PipeElement::pipe_pattern_wildcard(r"*ho*ge*".to_string());
        assert_eq!("(?i)(.|\\a|\\f|\\t|\\n|\\r|\\v)*ho(.|\\a|\\f|\\t|\\n|\\r|\\v)*ge(.|\\a|\\f|\\t|\\n|\\r|\\v)*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\*ho\*\*ge\*".to_string());
        // wildcardの「\*」は文字列としての「*」を表す。
        // 正規表現で「*」はエスケープする必要があるので、\*が正解
        assert_eq!(r"(?i)\*ho\*\*ge\*", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk3() {
        // wildcardの「\\*」は文字列としての「\」と正規表現の「.*」を表す。
        // 文字列としての「\」はエスケープされるので、「\\.*」が正解
        let value = PipeElement::pipe_pattern_wildcard(r"\\*ho\\*ge\\*".to_string());
        assert_eq!(
            r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*ho\\(.|\a|\f|\t|\n|\r|\v)*ge\\(.|\a|\f|\t|\n|\r|\v)*",
            value
        );
    }

    #[test]
    fn test_pipe_pattern_wildcard_question() {
        let value = PipeElement::pipe_pattern_wildcard(r"?ho?ge?".to_string());
        assert_eq!(r"(?i).ho.ge.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question2() {
        let value = PipeElement::pipe_pattern_wildcard(r"\?ho\?ge\?".to_string());
        assert_eq!(r"(?i)\?ho\?ge\?", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_question3() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\?ho\\?ge\\?".to_string());
        assert_eq!(r"(?i)\\.ho\\.ge\\.", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_backshash() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\ho\\ge\\".to_string());
        assert_eq!(r"(?i)\\\\ho\\\\ge\\\\", value);
    }

    #[test]
    fn test_pipe_pattern_wildcard_mixed() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\*\****\*\\*".to_string());
        assert_eq!(
            r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*\*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*\*\\(.|\a|\f|\t|\n|\r|\v)*",
            value
        );
    }

    #[test]
    fn test_pipe_pattern_wildcard_many_backshashs() {
        let value = PipeElement::pipe_pattern_wildcard(r"\\\*ho\\\*ge\\\".to_string());
        assert_eq!(
            r"(?i)\\\\(.|\a|\f|\t|\n|\r|\v)*ho\\\\(.|\a|\f|\t|\n|\r|\v)*ge\\\\\\",
            value
        );
    }

    #[test]
    fn test_grep_match() {
        // wildcardは大文字小文字関係なくマッチする。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4103
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_grep_not_match() {
        // wildcardは大文字小文字関係なくマッチする。
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4104
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_detect_value_keyword() {
        // 文字列っぽいデータでも確認
        // 完全一致なので、前方一致しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 
                    value: Security
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_notdetect_value_keyword() {
        // 文字列っぽいデータでも確認
        // 完全一致なので、前方一致しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 
                    value: Securiteen
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_eq_field() {
        // equalsfieldsで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_eq_field_notdetect() {
        // equalsfieldsの検知できないパターン
        // equalsfieldsで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_eq_field_emptyfield() {
        // 存在しないフィールドを指定した場合は検知しない
        let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: NoField
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Securiti" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: Channel
        details: 'command=%CommandLine%'
        "#;
        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: NoField1
        details: 'command=%CommandLine%'
        "#;
        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }

    #[test]
    fn test_eq_field_null() {
        // 値でnullであった場合に対象のフィールドが存在しないことを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: 
                    value: Security
                Takoyaki: 
                    value: null
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(rule_node.select(&recinfo));
            }
            Err(_) => {
                panic!("Failed to parse json record.");
            }
        }
    }
    #[test]
    fn test_eq_field_null_not_detect() {
        // 値でnullであった場合に対象のフィールドが存在しないことを確認するテスト
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: null
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let mut rule_node = parse_rule_from_str(rule_str);
        match serde_json::from_str(record_json_str) {
            Ok(record) => {
                let keys = detections::rule::get_detection_keys(&rule_node);
                let recinfo = utils::create_rec_info(record, "testpath".to_owned(), &keys);
                assert!(!rule_node.select(&recinfo));
            }
            Err(e) => {
                panic!("Failed to parse json record.{:?}", e);
            }
        }
    }
}

use cidr_utils::cidr::IpCidr;
use cidr_utils::cidr::errors::NetworkParseError;
use nested::Nested;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use std::{cmp::Ordering, collections::HashMap};
use yaml_rust2::Yaml;

use crate::detections::configs::WINDASH_CHARACTERS;
use crate::detections::rule::base64_match::{
    convert_to_base64_str, to_base64_utf8, to_base64_utf16be, to_base64_utf16le_with_bom,
};
use crate::detections::rule::fast_match::{
    FastMatch, check_fast_match, convert_to_fast_match, create_fast_match,
};
use crate::detections::{detection::EvtxRecordInfo, utils};
use downcast_rs::Downcast;

// 末端ノードがEventLogの値を比較するロジックを表す。
// 正規条件のマッチや文字数制限など、比較ロジック毎にこのtraitを実装したクラスが存在する。
//
// 新規にLeafMatcherを実装するクラスを作成した場合、
// LeafSelectionNodeのget_matchersクラスの戻り値の配列に新規作成したクラスのインスタンスを追加する。
pub trait LeafMatcher: Downcast + Send + Sync {
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

        key_list.get(1).unwrap() == "min_length"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let min_length = select_value.as_i64();
        if min_length.is_none() {
            let errmsg = format!(
                "min_length value should be an integer. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        self.min_len = min_length.unwrap();
        Ok(())
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
            Yaml::String(_) | Yaml::Integer(_) | Yaml::Real(_) => select_value.as_str(),
            _ => None,
        };
        if value.is_none() {
            let errmsg = format!(
                "regexes value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        let regexes_strs = utils::read_txt(value.unwrap());
        if regexes_strs.is_err() {
            return Err(vec![regexes_strs.unwrap_err()]);
        }
        let regexes_strs = regexes_strs.unwrap();
        self.regexes = regexes_strs
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Ok(())
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

        key_list.get(1).unwrap() == "allowlist"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let value = match select_value {
            Yaml::String(s) => Some(s.to_owned()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(r) => Some(r.to_owned()),
            _ => None,
        };
        if value.is_none() {
            let errmsg = format!(
                "allowlist value should be a string. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }

        let regexes_strs = utils::read_txt(&value.unwrap());
        if regexes_strs.is_err() {
            return Err(vec![regexes_strs.unwrap_err()]);
        }
        self.regexes = regexes_strs
            .unwrap()
            .iter()
            .map(|regex_str| Regex::new(regex_str).unwrap())
            .collect();

        Ok(())
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
    re: Option<Vec<Regex>>,
    fast_match: Option<Vec<FastMatch>>,
    pipes: Vec<PipeElement>,
    key_list: Nested<String>,
}

impl DefaultMatcher {
    pub fn new() -> DefaultMatcher {
        DefaultMatcher {
            re: None,
            fast_match: None,
            pipes: Vec::new(),
            key_list: Nested::<String>::new(),
        }
    }

    pub fn get_eqfield_key(&self) -> Option<&String> {
        let pipe = self.pipes.first()?;
        pipe.get_eqfield()
    }

    /// このmatcherの正規表現とマッチするかどうか判定します。
    fn is_regex_fullmatch(&self, value: &str) -> bool {
        self.re.as_ref().unwrap().iter().any(|x| x.is_match(value))
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

        key_list.get(1).unwrap() == "value"
    }

    fn init(&mut self, key_list: &Nested<String>, select_value: &Yaml) -> Result<(), Vec<String>> {
        let mut tmp_key_list = Nested::<String>::new();
        tmp_key_list.extend(key_list.iter());
        self.key_list = tmp_key_list;
        if select_value.is_null() {
            return Ok(());
        }

        // patternをパースする
        let yaml_value = match select_value {
            Yaml::Boolean(b) => Some(b.to_string()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(r) => Some(r.to_string()),
            Yaml::String(s) => Some(s.to_owned()),
            _ => None,
        };
        if yaml_value.is_none() {
            let errmsg = format!(
                "An unknown error occured. [key:{}]",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }
        let mut pattern = Vec::new();
        pattern.push(yaml_value.unwrap());
        // Pipeが指定されていればパースする
        let emp = String::default();
        // 一つ目はただのキーで、2つめ以降がpipe

        let mut keys_all: Vec<&str> = key_list.get(0).unwrap_or(&emp).split('|').collect(); // key_listが空はあり得ない

        //all -> allOnlyの対応関係
        let mut change_map: HashMap<&str, &str> = HashMap::new();
        change_map.insert("all", "allOnly");
        change_map.insert("i", "reignorecase");
        change_map.insert("m", "remultiline");
        change_map.insert("s", "resingleline");

        //先頭が｜の場合を検知して、all -> allOnlyに変更
        if keys_all[0].is_empty() && keys_all.len() == 2 && keys_all[1] == "all" {
            keys_all[1] = change_map["all"];
        }
        if keys_all.len() >= 3 {
            if keys_all[1] == "re" {
                if keys_all[2] == "i" {
                    keys_all[2] = change_map["i"];
                } else if keys_all[2] == "m" {
                    keys_all[2] = change_map["m"];
                } else if keys_all[2] == "s" {
                    keys_all[2] = change_map["s"];
                }
                keys_all.remove(1);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "endswith" {
                keys_all[1] = "fieldrefendswith";
                keys_all.remove(2);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "startswith" {
                keys_all[1] = "fieldrefstartswith";
                keys_all.remove(2);
            } else if keys_all[1] == "fieldref" && keys_all[2] == "contains" {
                keys_all[1] = "fieldrefcontains";
                keys_all.remove(2);
            }
        }

        let keys_without_head = &keys_all[1..];

        let mut err_msges = vec![];
        for key in keys_without_head.iter() {
            let pipe_element = PipeElement::new(key, &pattern[0], key_list);
            match pipe_element {
                Ok(element) => {
                    self.pipes.push(element);
                }
                Err(e) => {
                    err_msges.push(e);
                }
            }
        }
        if !err_msges.is_empty() {
            return Err(err_msges);
        }
        let n = self.pipes.len();
        if n == 0 {
            // パイプがないケース
            self.fast_match = convert_to_fast_match(&pattern[0], true);
        } else if n == 1 {
            // パイプがあるケース
            self.fast_match = create_fast_match(&self.pipes, &pattern);
        } else if n == 2 {
            if self.pipes[0] == PipeElement::Base64 && self.pipes[1] == PipeElement::Contains {
                self.fast_match = convert_to_fast_match(
                    &format!("*{}*", &to_base64_utf8(pattern[0].as_str())),
                    true,
                );
            } else if self.pipes[0] == PipeElement::Base64offset
                && self.pipes[1] == PipeElement::Contains
            {
                self.fast_match = convert_to_base64_str(None, pattern[0].as_str(), &mut err_msges);
            } else if self.pipes[0] == PipeElement::Contains && self.pipes[1] == PipeElement::All
            // |contains|allの場合、事前の分岐でAndSelectionNodeとしているのでここではcontainsのみとして取り扱う
            {
                self.fast_match = convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true);
            } else if self.pipes[0] == PipeElement::Contains
                && self.pipes[1] == PipeElement::Windash
            {
                // |contains|windashの場合
                let mut fastmatches =
                    convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true)
                        .unwrap_or_default();
                let windash_chars = WINDASH_CHARACTERS.as_slice();
                fastmatches.extend(
                    convert_to_fast_match(
                        format!("*{}*", pattern[0].replacen(windash_chars, "/", 1)).as_str(),
                        true,
                    )
                    .unwrap_or_default(),
                );
                if !fastmatches.is_empty() {
                    self.fast_match = Some(fastmatches);
                }
            } else if self.pipes[1] == PipeElement::Cased {
                if self.pipes[0] == PipeElement::Startswith {
                    self.fast_match = convert_to_fast_match(&format!("{}*", pattern[0]), false);
                } else if self.pipes[0] == PipeElement::Endswith {
                    self.fast_match = convert_to_fast_match(&format!("*{}", pattern[0]), false);
                } else if self.pipes[0] == PipeElement::Contains {
                    self.fast_match = convert_to_fast_match(&format!("*{}*", pattern[0]), false);
                }
            }
        } else if n == 3 {
            if self.pipes.contains(&PipeElement::Contains)
                && self.pipes.contains(&PipeElement::All)
                && self.pipes.contains(&PipeElement::Windash)
            // |contains|all|windashの場合、事前の分岐でAndSelectionNodeとしているのでここではcontainsとwindashのみとして取り扱う
            {
                let mut fastmatches =
                    convert_to_fast_match(format!("*{}*", pattern[0]).as_str(), true)
                        .unwrap_or_default();
                let windash_chars = WINDASH_CHARACTERS.as_slice();
                pattern.push(pattern[0].replacen(windash_chars, "/", 1));
                fastmatches.extend(
                    convert_to_fast_match(
                        format!("*{}*", pattern[0].replacen(windash_chars, "/", 1)).as_str(),
                        true,
                    )
                    .unwrap_or_default(),
                );
                if !fastmatches.is_empty() {
                    self.fast_match = Some(fastmatches);
                }
            } else if (self.pipes[0] == PipeElement::Utf16
                || self.pipes[0] == PipeElement::Utf16Le
                || self.pipes[0] == PipeElement::Utf16Be
                || self.pipes[0] == PipeElement::Wide)
                && (self.pipes[1] == PipeElement::Base64offset
                    || self.pipes[1] == PipeElement::Base64)
                && self.pipes[2] == PipeElement::Contains
            {
                if self.pipes[1] == PipeElement::Base64offset {
                    let encode = &self.pipes[0];
                    let org_str = pattern[0].as_str();
                    if encode == &PipeElement::Utf16 {
                        let utf16_le_match = convert_to_base64_str(
                            Some(&PipeElement::Utf16Le),
                            org_str,
                            &mut err_msges,
                        );
                        let utf16_be_match = convert_to_base64_str(
                            Some(&PipeElement::Utf16Be),
                            org_str,
                            &mut err_msges,
                        );
                        if let Some(utf16_le_match) = utf16_le_match {
                            if let Some(utf16_be_match) = utf16_be_match {
                                let mut matches = utf16_le_match;
                                matches.extend(utf16_be_match);
                                self.fast_match = Some(matches);
                            }
                        }
                    } else {
                        self.fast_match =
                            convert_to_base64_str(Some(encode), org_str, &mut err_msges);
                    }
                } else if self.pipes[1] == PipeElement::Base64 {
                    let encode = &self.pipes[0];
                    let org_str = pattern[0].as_str();
                    match encode {
                        PipeElement::Utf16 => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16le_with_bom(org_str, true)),
                                true,
                            );
                        }
                        PipeElement::Utf16Le | PipeElement::Wide => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16le_with_bom(org_str, false)),
                                true,
                            );
                        }
                        PipeElement::Utf16Be => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf16be(org_str)),
                                true,
                            );
                        }
                        _ => {
                            self.fast_match = convert_to_fast_match(
                                &format!("*{}*", &to_base64_utf8(org_str)),
                                true,
                            );
                        }
                    }
                }
            }
        } else {
            let errmsg = format!(
                "Multiple pipe elements cannot be used. key:{}",
                utils::concat_selection_key(key_list)
            );
            return Err(vec![errmsg]);
        }
        if self.fast_match.is_some()
            && matches!(
                &self.fast_match.as_ref().unwrap()[0],
                FastMatch::Exact(_) | FastMatch::Contains(_)
            )
            && !self.key_list.is_empty()
        {
            // FastMatch::Exact/Contains検索に置き換えられたときは正規表現は不要
            return Ok(());
        }
        let is_eqfield = self.pipes.iter().any(|pipe_element| {
            matches!(
                pipe_element,
                PipeElement::EqualsField(_)
                    | PipeElement::Endswithfield(_)
                    | PipeElement::FieldRef(_)
                    | PipeElement::FieldRefEndswith(_)
                    | PipeElement::FieldRefStartswith(_)
                    | PipeElement::FieldRefContains(_)
            )
        });
        if !is_eqfield {
            // 正規表現ではない場合、ワイルドカードであることを表す。
            // ワイルドカードは正規表現でマッチングするので、ワイルドカードを正規表現に変換するPipeを内部的に追加することにする。
            let is_re = self.pipes.iter().any(|pipe_element| {
                matches!(
                    pipe_element,
                    PipeElement::Re
                        | PipeElement::ReIgnoreCase
                        | PipeElement::ReMultiLine
                        | PipeElement::ReSingleLine
                )
            });
            if !is_re {
                self.pipes.push(PipeElement::Wildcard);
            }

            let mut re_result_vec = vec![];
            for p in pattern {
                let pattern = DefaultMatcher::from_pattern_to_regex_str(p, &self.pipes);
                // Pipeで処理されたパターンを正規表現に変換
                if let Ok(re_result) = Regex::new(&pattern) {
                    re_result_vec.push(re_result);
                } else {
                    let errmsg = format!(
                        "Cannot parse regex. [regex:{pattern}, key:{}]",
                        utils::concat_selection_key(key_list)
                    );
                    return Err(vec![errmsg]);
                }
            }
            self.re = Some(re_result_vec);
        }
        Ok(())
    }

    fn is_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        let pipe: &PipeElement = self.pipes.first().unwrap_or(&PipeElement::Wildcard);
        let match_result = match pipe {
            PipeElement::Cidr(ip_result) => match ip_result {
                Ok(matcher_ip) => {
                    let val = String::default();
                    let event_value_str = event_value.unwrap_or(&val);
                    let event_ip = IpAddr::from_str(event_value_str);
                    match event_ip {
                        Ok(target_ip) => Some(matcher_ip.contains(&target_ip)),
                        Err(_) => Some(false), //IPアドレス以外の形式のとき
                    }
                }
                Err(_) => Some(false), //IPアドレス以外の形式のとき
            },
            PipeElement::Exists(..)
            | PipeElement::EqualsField(_)
            | PipeElement::FieldRef(_)
            | PipeElement::FieldRefStartswith(_)
            | PipeElement::FieldRefContains(_)
            | PipeElement::FieldRefEndswith(_)
            | PipeElement::Endswithfield(_) => Some(pipe.is_eqfield_match(event_value, recinfo)),
            PipeElement::Gt(_) | PipeElement::Lt(_) | PipeElement::Gte(_) | PipeElement::Lte(_) => {
                let val = String::default();
                let event_val_str = event_value.unwrap_or(&val);
                let event_val_int = event_val_str.parse::<usize>();
                match event_val_int {
                    Ok(event_val) => {
                        let cmp_result = match pipe {
                            PipeElement::Gt(n) => event_val > *n,
                            PipeElement::Lt(n) => event_val < *n,
                            PipeElement::Gte(n) => event_val >= *n,
                            PipeElement::Lte(n) => event_val <= *n,
                            _ => false,
                        };
                        Some(cmp_result)
                    }
                    Err(_) => Some(false), //数値以外のとき
                }
            }
            _ => None,
        };
        if let Some(result) = match_result {
            return result;
        }

        // yamlにnullが設定されていた場合
        // keylistが空(==JSONのgrep検索)の場合、無視する。
        if self.key_list.is_empty() && self.re.is_none() && self.fast_match.is_none() {
            return false;
        }

        // yamlにnullが設定されていた場合
        if self.re.is_none() && self.fast_match.is_none() {
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
            return self
                .re
                .as_ref()
                .unwrap()
                .iter()
                .any(|x| x.is_match(event_value_str));
        } else if let Some(fast_matcher) = &self.fast_match {
            let fast_match_result = check_fast_match(&self.pipes, event_value_str, fast_matcher);
            if let Some(is_match) = fast_match_result {
                return is_match;
            }
        }
        // 文字数/starts_with/ends_with検索に変換できなかった場合は、正規表現マッチで比較
        self.is_regex_fullmatch(event_value_str)
    }
}

/// パイプ(|)で指定される要素を表すクラス。
/// 要リファクタリング
#[derive(PartialEq)]
pub enum PipeElement {
    Startswith,
    Endswith,
    Contains,
    Re,
    ReIgnoreCase,
    ReMultiLine,
    ReSingleLine,
    Wildcard,
    Expand,
    Exists(String, String),
    EqualsField(String),
    Endswithfield(String),
    FieldRef(String),
    FieldRefStartswith(String),
    FieldRefEndswith(String),
    FieldRefContains(String),
    Base64,
    Base64offset,
    Windash,
    Cidr(Result<IpCidr, NetworkParseError>),
    All,
    AllOnly,
    Cased,
    Gt(usize),
    Lt(usize),
    Gte(usize),
    Lte(usize),
    Utf16,
    Utf16Le,
    Utf16Be,
    Wide,
}

impl PipeElement {
    fn new(key: &str, pattern: &str, key_list: &Nested<String>) -> Result<PipeElement, String> {
        let pipe_element = match key {
            "startswith" => Some(PipeElement::Startswith),
            "endswith" => Some(PipeElement::Endswith),
            "contains" => Some(PipeElement::Contains),
            "re" => Some(PipeElement::Re),
            "exists" => Some(PipeElement::Exists(
                key_list[0].split('|').collect::<Vec<&str>>()[0].to_string(),
                pattern.to_string(),
            )),
            "reignorecase" => Some(PipeElement::ReIgnoreCase),
            "resingleline" => Some(PipeElement::ReSingleLine),
            "remultiline" => Some(PipeElement::ReMultiLine),
            "equalsfield" => Some(PipeElement::EqualsField(pattern.to_string())),
            "endswithfield" => Some(PipeElement::Endswithfield(pattern.to_string())),
            "expand" => Some(PipeElement::Expand),
            "fieldref" => Some(PipeElement::FieldRef(pattern.to_string())),
            "fieldrefstartswith" => Some(PipeElement::FieldRefStartswith(pattern.to_string())),
            "fieldrefendswith" => Some(PipeElement::FieldRefEndswith(pattern.to_string())),
            "fieldrefcontains" => Some(PipeElement::FieldRefContains(pattern.to_string())),
            "base64" => Some(PipeElement::Base64),
            "base64offset" => Some(PipeElement::Base64offset),
            "windash" => Some(PipeElement::Windash),
            "cidr" => Some(PipeElement::Cidr(IpCidr::from_str(pattern))),
            "all" => Some(PipeElement::All),
            "allOnly" => Some(PipeElement::AllOnly),
            "cased" => Some(PipeElement::Cased),
            "gt" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Gt(n)),
                Err(_) => {
                    return Err(format!(
                        "gt value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "lt" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Lt(n)),
                Err(_) => {
                    return Err(format!(
                        "lt value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "gte" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Gte(n)),
                Err(_) => {
                    return Err(format!(
                        "gte value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "lte" => match pattern.parse::<usize>() {
                Ok(n) => Some(PipeElement::Lte(n)),
                Err(_) => {
                    return Err(format!(
                        "lte value should be a number. key:{}",
                        utils::concat_selection_key(key_list)
                    ));
                }
            },
            "utf16" => Some(PipeElement::Utf16),
            "utf16le" => Some(PipeElement::Utf16Le),
            "utf16be" => Some(PipeElement::Utf16Be),
            "wide" => Some(PipeElement::Wide),
            _ => None,
        };

        if let Some(elment) = pipe_element {
            Ok(elment)
        } else {
            Err(format!(
                "An unknown pipe element was specified. key:{}",
                utils::concat_selection_key(key_list)
            ))
        }
    }

    fn get_eqfield(&self) -> Option<&String> {
        match self {
            PipeElement::EqualsField(s)
            | PipeElement::Endswithfield(s)
            | PipeElement::FieldRef(s)
            | PipeElement::FieldRefStartswith(s)
            | PipeElement::FieldRefEndswith(s)
            | PipeElement::FieldRefContains(s) => Some(s),
            _ => None,
        }
    }

    fn is_eqfield_match(&self, event_value: Option<&String>, recinfo: &EvtxRecordInfo) -> bool {
        match self {
            PipeElement::Exists(eq_key, val) => {
                val.to_lowercase() == recinfo.get_value(eq_key).is_some().to_string()
            }
            PipeElement::EqualsField(eq_key) | PipeElement::FieldRef(eq_key) => {
                let eq_value = recinfo.get_value(eq_key);
                // Evtxのレコードに存在しないeventkeyを指定された場合はfalseにする
                if event_value.is_none() || eq_value.is_none() {
                    return false;
                }
                eq_value.unwrap().cmp(event_value.unwrap()) == Ordering::Equal
            }
            PipeElement::FieldRefStartswith(eq_key) => {
                let starts_value = recinfo.get_value(eq_key);
                if event_value.is_none() || starts_value.is_none() {
                    return false;
                }
                let event_value = &event_value.unwrap().to_lowercase();
                let starts_value = &starts_value.unwrap().to_lowercase();
                event_value.starts_with(starts_value)
            }
            PipeElement::Endswithfield(eq_key) | PipeElement::FieldRefEndswith(eq_key) => {
                let ends_value = recinfo.get_value(eq_key);
                // Evtxのレコードに存在しないeventkeyを指定された場合はfalseにする
                if event_value.is_none() || ends_value.is_none() {
                    return false;
                }

                let event_value = &event_value.unwrap().to_lowercase();
                let ends_value = &ends_value.unwrap().to_lowercase();
                event_value.ends_with(ends_value)
            }
            PipeElement::FieldRefContains(eq_key) => {
                let contains_value = recinfo.get_value(eq_key);
                if event_value.is_none() || contains_value.is_none() {
                    return false;
                }
                let event_value = &event_value.unwrap().to_lowercase();
                let contains_value = &contains_value.unwrap().to_lowercase();
                event_value.contains(contains_value)
            }
            _ => false,
        }
    }

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
            } else if patt.ends_with('\\') {
                // 末尾が\(バックスラッシュ1つ)の場合は、末尾を\\* (バックスラッシュ2つとアスタリスク)に変換する
                // 末尾が\\*は、バックスラッシュ1文字とそれに続けてワイルドカードパターンであることを表す
                patt + "\\*"
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
            PipeElement::ReIgnoreCase => "(?i)".to_string() + pattern.as_str(),
            PipeElement::ReMultiLine => "(?m)".to_string() + pattern.as_str(),
            PipeElement::ReSingleLine => "(?s)".to_string() + pattern.as_str(),
            _ => pattern,
        }
    }

    /// PipeElement::Wildcardのパイプ処理です。
    /// pipe_pattern()に含めて良い処理ですが、複雑な処理になってしまったので別関数にしました。
    fn pipe_pattern_wildcard(pattern: String) -> String {
        let wildcards = vec!["*", "?"];

        // patternをwildcardでsplitした結果をpattern_splitsに入れる
        // 以下のアルゴリズムの場合、pattern_splitsの偶数indexの要素はwildcardじゃない文字列となり、奇数indexの要素はwildcardが入る。
        let mut idx = 0;
        let mut pattern_splits = vec![];
        let mut cur_str = String::default();
        while idx < pattern.len() {
            let prev_idx = idx;
            for wildcard in &wildcards {
                let cur_pattern: String = pattern.chars().skip(idx).collect::<String>();
                if cur_pattern.starts_with(&format!(r"\\{wildcard}")) {
                    // wildcardの前にエスケープ文字が2つある場合
                    cur_str = format!("{}{}", cur_str, r"\");
                    pattern_splits.push(cur_str);
                    pattern_splits.push(wildcard.to_string());

                    cur_str = String::default();
                    idx += 3;
                    break;
                } else if cur_pattern.starts_with(&format!(r"\{wildcard}")) {
                    // wildcardの前にエスケープ文字が1つある場合
                    cur_str = format!("{cur_str}{wildcard}");
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

                format!("{acc}{regex_value}")
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
    use crate::detections::configs::{
        Action, Config, CsvOutputOption, OutputOption, STORED_EKEY_ALIAS, StoredStatic,
    };
    use crate::detections::rule::matchers::FastMatch;
    use crate::detections::rule::tests::parse_rule_from_str;
    use crate::detections::{self, utils};

    fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
        let mut rule_node = parse_rule_from_str(rule_str);
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    min_level: "informational".to_string(),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            ..Default::default()
        }));

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
                        &dummy_stored_static.eventkey_alias,
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
                    regexes: test_files/config/regex/detectlist_suspicous_services.txt
                    allowlist: test_files/config/regex/allowlist_legitimate_services.txt
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
            let child_node = detection_childs[0];
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

            assert!(matcher.fast_match.is_some());
            let fast_match = matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact(
                    "Microsoft-Windows-PowerShell/Operational".to_string()
                )]
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
            assert!(matcher.fast_match.is_some());
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
            assert!(hostapp_en_matcher.fast_match.is_some());
            let fast_match = hostapp_en_matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact("Host Application".to_string())]
            );

            // LeafSelectionNodeである、ホスト アプリケーションノードが正しいことを確認
            let hostapp_jp_node = ancestors[1] as &dyn SelectionNode;
            assert!(hostapp_jp_node.is::<LeafSelectionNode>());
            let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let hostapp_jp_matcher = &hostapp_jp_node.matcher;
            assert!(hostapp_jp_matcher.is_some());
            let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
            assert!(hostapp_jp_matcher.is::<DefaultMatcher>());
            let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<DefaultMatcher>().unwrap();
            assert!(hostapp_jp_matcher.fast_match.is_some());
            let fast_match = hostapp_jp_matcher.fast_match.as_ref().unwrap();
            assert_eq!(
                *fast_match,
                vec![FastMatch::Exact("ホスト アプリケーション".to_string())]
            );
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_regex_partial_match() {
        // 正規表現の部分一致
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re: DESKTOP
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
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
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        // JSONで値としてダブルクオートを使う場合、\でエスケープが必要なのに注意
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
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
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        // JSONで値としてダブルクオートを使う場合、\でエスケープが必要なのに注意
        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
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
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_startswith_cased() {
        // startswith|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "Administrators"
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

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_cased2() {
        // startswith|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "administrators"
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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
        check_select(rule_str, record_json_str, false);
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
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased1() {
        // endswith|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "Administrators"
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
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased2() {
        // endswith|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "test"
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
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_endswith_cased3() {
        // endswith|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "sTest"
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
        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_contains_cased1() {
        // contains|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "Administrators"
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

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains_cased2() {
        // contains|casedが正しく検知できることを確認
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "MinistratorS"
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
              "TargetUserName": "TestministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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
        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_pipe_pattern_wildcard_asterisk() {
        let value = PipeElement::pipe_pattern_wildcard(r"*ho*ge*".to_string());
        assert_eq!(
            "(?i)(.|\\a|\\f|\\t|\\n|\\r|\\v)*ho(.|\\a|\\f|\\t|\\n|\\r|\\v)*ge(.|\\a|\\f|\\t|\\n|\\r|\\v)*",
            value
        );
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
        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
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

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_endswith_field() {
        // endswithfieldで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field2() {
        // endswithfieldで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_caseinsensitive() {
        // endswithfieldでcaseinsensitiveで検知することを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "iTy" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_caseinsensitive2() {
        // endswithfieldでcaseinsensitiveで検知することを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "SecuriTy", "Computer": "ity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_endswith_field_notdetect() {
        // endswithfieldで正しく検知しないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "rity", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_endswith_field_notdetect2() {
        // endswithfieldで正しく検知しないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref() {
        // fieldrefで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect() {
        // fieldrefの検知できないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_endswith() {
        // fieldrefで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|endswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_endswith() {
        // fieldrefの検知できないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_startswith() {
        // fieldrefで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_startswith() {
        // fieldrefの検知できないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_eq_field_ref_contains() {
        // fieldrefで正しく検知できることを確認
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_ref_notdetect_contains() {
        // fieldrefの検知できないパターン
        let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_eq_field_notdetect() {
        // equalsfieldsの検知できないパターン
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
        check_select(rule_str, record_json_str, false);
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

        check_select(rule_str, record_json_str, false);

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: Channel
        details: 'command=%CommandLine%'
        "#;
        check_select(rule_str, record_json_str, false);

        let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: NoField1
        details: 'command=%CommandLine%'
        "#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_field_null() {
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
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_field_null_not_detect() {
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

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with() {
        // ワイルドカード1文字を末尾に含む場合、stars_with相当のマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_starts_with_notdetect() {
        // ワイルドカード1文字を末尾に含む場合、stars_with相当のマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: AA-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with_exact_val() {
        // ワイルドカード1文字を末尾に含みかつ、＊を除く比較対象文字がちょうど一致する場合
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_starts_with_shorter_val_notdetect() {
        // ワイルドカード1文字を末尾に含みかつ、比較対象文字のほうが文字数が少ない場合はマッチしない
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST-*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_wildcard_converted_starts_with_multibytes() {
        //ワイルドカードを含むかつascii以外のパターンは正規表現マッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: 社員端末*
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "社員端末A"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with() {
        // ワイルドカード1文字を先頭に含む場合、ends_with相当のマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with_starts_with_exact_val() {
        // ワイルドカード1文字を先頭に含みかつ、＊を除く比較対象文字がちょうど一致する場合
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*A-HOST'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_wildcard_converted_ends_with_shorter_val_notdetect() {
        // ワイルドカード1文字を先頭に含みかつ、比較対象文字のほうが文字数が少ない場合はマッチしない
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOSTA'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_only_wildcard() {
        // ワイルドカードだけの場合、ends_with相当のマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_two_wildcards() {
        // ワイルドカード2文字以上を含む場合、正規表現マッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST-*'
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST-1"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64_contains() {
        // base64|containsのマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64offset_contains() {
        // base64offset|containsのマッチ
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_base64offset_contains_not_match() {
        // base64offset|containsのマッチしないパターン
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "test"
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ipv4_detect() {
        // cidrにマッチするIP
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_cidr_ipv4_not_detect() {
        // cidrにマッチしないIP
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2600:1f18:130c:d900::/56
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "8.8.8.8"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ipv6_detect() {
        // cidrにマッチするIP
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1234:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_cidr_ipv6_not_detect() {
        // cidrにマッチしないIP
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1111:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_cidr_ip_field_not_exists_not_detect() {
        // cidrにマッチしないIP
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_backslash_exact_match() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory: 'C:\Windows\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_backslash1() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_startswith_backslash2() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false); //★ expect false
    }

    #[test]
    fn test_detect_contains_backslash1() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_contains_backslash2() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_detect_backslash_endswith() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|endswith: 'C:\Windows\system32\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_detect_backslash_regex() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|re: '.*system32\\'
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_all_only_detect_case() {
        let rule_str = r"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_all_only_no_detect_case() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_all_only_detected_and_selection_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 'dummy'
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_all_only_not_detect_and_selection_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 3
                - 2
            condition: selection1 and selection2
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_contains_windash() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '-addstore'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

        let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -addstore"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
        check_select(rule_str, record_json_str2, true);
    }

    #[test]
    fn test_contains_all_windash() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '-addstore'
                    - '-test-test'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -test-test /addstore"
            }
          }
        }"#;

        let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test -addstore"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
        check_select(rule_str, record_json_str2, false);
    }

    #[test]
    fn test_contains_windash_multitype_dash() {
        let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '–addstore'
            condition: selection1
        "#;
        let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '—addstore'
            condition: selection1
        "#;
        let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '―addstore'
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

        let record_json_str_en = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –addstore"
            }
          }
        }"#;

        let record_json_str_em = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —addstore"
            }
          }
        }"#;

        let record_json_str_horizontal = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―addstore"
            }
          }
        }"#;

        check_select(rule_str_en_dash, record_json_str, true);
        check_select(rule_str_en_dash, record_json_str_en, true);
        check_select(rule_str_en_dash, record_json_str_em, true);
        check_select(rule_str_en_dash, record_json_str_horizontal, true);
        check_select(rule_str_em_dash, record_json_str, true);
        check_select(rule_str_em_dash, record_json_str_en, true);
        check_select(rule_str_em_dash, record_json_str_em, true);
        check_select(rule_str_em_dash, record_json_str_horizontal, true);
        check_select(rule_str_horizontal_bar, record_json_str, true);
        check_select(rule_str_horizontal_bar, record_json_str_en, true);
        check_select(rule_str_horizontal_bar, record_json_str_em, true);
        check_select(rule_str_horizontal_bar, record_json_str_horizontal, true);
    }

    #[test]
    fn test_contains_all_windash_multitype_dash() {
        let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '–addstore'
                    - '–test–test'
            condition: selection1
        "#;

        let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '—addstore'
                    - '—test—test'
            condition: selection1
        "#;

        let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '―addstore'
                    - '―test―test'
            condition: selection1
        "#;

        let record_json_str_en_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –test–test /addstore"
            }
          }
        }"#;

        let record_json_str_en_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test –addstore"
            }
          }
        }"#;

        let record_json_str_em_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —test—test /addstore"
            }
          }
        }"#;

        let record_json_str_em_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test —addstore"
            }
          }
        }"#;

        let record_json_str_horizontal_bar = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―test―test /addstore"
            }
          }
        }"#;

        let record_json_str_horizontal_bar2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test ―addstore"
            }
          }
        }"#;

        check_select(rule_str_en_dash, record_json_str_en_dash, true);
        check_select(rule_str_en_dash, record_json_str_en_dash2, false);
        check_select(rule_str_em_dash, record_json_str_em_dash, true);
        check_select(rule_str_em_dash, record_json_str_em_dash2, false);
        check_select(
            rule_str_horizontal_bar,
            record_json_str_horizontal_bar,
            true,
        );
        check_select(
            rule_str_horizontal_bar,
            record_json_str_horizontal_bar2,
            false,
        );
    }

    #[test]
    fn test_exists_true() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_caseinsensitive_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|i: ABC
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "abc"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_exists_null_true() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_multiline_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|m: ^ABC$
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_exists_false() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Dummy|exists: false
            condition: selection1
        "#;

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_re_singleline_detect() {
        let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|s: A.*F
        details: 'command=%CommandLine%'
        "#;

        let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_ge() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }

    #[test]
    fn test_ge_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_lt() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_lt_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_gte() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_gte_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }

    #[test]
    fn test_lte() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lte: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

        check_select(rule_str, record_json_str, true);
    }
    #[test]
    fn test_lte_not() {
        let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

        let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
        check_select(rule_str, record_json_str, false);
    }
}

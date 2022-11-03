extern crate csv;

use crate::detections::configs;
use crate::detections::utils::{format_time, write_color_buffer};
use crate::options::profile::{
    LOAEDED_PROFILE_ALIAS, PRELOAD_PROFILE, PRELOAD_PROFILE_REGEX, PROFILES,
};
use chrono::{TimeZone, Utc};
use itertools::Itertools;
use nested::Nested;
use termcolor::{BufferWriter, Color, ColorChoice};

use crate::detections::message::{
    AlertMessage, DetectInfo, CH_CONFIG, DEFAULT_DETAILS, ERROR_LOG_STACK, LOGONSUMMARY_FLAG,
    METRICS_FLAG, PIVOT_KEYWORD_LIST_FLAG, QUIET_ERRORS_FLAG, TAGS_CONFIG,
};
use crate::detections::pivot::insert_pivot_keyword;
use crate::detections::rule::{self, AggResult, RuleNode};
use crate::detections::utils::{get_serde_number_to_string, make_ascii_titlecase};
use crate::filter;
use crate::options::htmlreport::{self, HTML_REPORT_FLAG};
use crate::yaml::ParseYaml;
use hashbrown::HashMap;
use serde_json::Value;
use std::fmt::Write;
use std::path::Path;

use std::sync::Arc;
use tokio::{runtime::Runtime, spawn, task::JoinHandle};

use super::message::{self, LEVEL_ABBR_MAP};

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
    pub data_string: String,
    pub key_2_value: HashMap<String, String>,
    pub record_information: Option<String>,
}

impl EvtxRecordInfo {
    pub fn get_value(&self, key: &str) -> Option<&String> {
        self.key_2_value.get(key)
    }
}

#[derive(Debug)]
pub struct Detection {
    rules: Vec<RuleNode>,
}

impl Detection {
    pub fn new(rule_nodes: Vec<RuleNode>) -> Detection {
        Detection { rules: rule_nodes }
    }

    pub fn start(self, rt: &Runtime, records: Vec<EvtxRecordInfo>) -> Self {
        rt.block_on(self.execute_rules(records))
    }

    // ルールファイルをパースします。
    pub fn parse_rule_files(
        level: String,
        rulespath: &Path,
        exclude_ids: &filter::RuleExclude,
    ) -> Vec<RuleNode> {
        // ルールファイルのパースを実行
        let mut rulefile_loader = ParseYaml::new();
        let result_readdir = rulefile_loader.read_dir(rulespath, &level, exclude_ids);
        if result_readdir.is_err() {
            let errmsg = format!("{}", result_readdir.unwrap_err());
            if configs::CONFIG.read().unwrap().args.verbose {
                AlertMessage::alert(&errmsg).ok();
            }
            if !*QUIET_ERRORS_FLAG {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {}", errmsg));
            }
            return vec![];
        }
        let mut parseerror_count = rulefile_loader.errorrule_count;
        let return_if_success = |mut rule: RuleNode| {
            let err_msgs_result = rule.init();
            if err_msgs_result.is_ok() {
                return Option::Some(rule);
            }

            // ruleファイルのパースに失敗した場合はエラー出力
            err_msgs_result.err().iter().for_each(|err_msgs| {
                let errmsg_body =
                    format!("Failed to parse rule file. (FilePath : {})", rule.rulepath);
                if configs::CONFIG.read().unwrap().args.verbose {
                    AlertMessage::warn(&errmsg_body).ok();

                    err_msgs.iter().for_each(|err_msg| {
                        AlertMessage::warn(err_msg).ok();
                    });
                }
                if !*QUIET_ERRORS_FLAG {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[WARN] {}", errmsg_body));
                    err_msgs.iter().for_each(|err_msg| {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {}", err_msg));
                    });
                }
                parseerror_count += 1;
                println!();
            });
            Option::None
        };
        // parse rule files
        let ret = rulefile_loader
            .files
            .into_iter()
            .map(|rule_file_tuple| rule::create_rule(rule_file_tuple.0, rule_file_tuple.1))
            .filter_map(return_if_success)
            .collect();
        if !*LOGONSUMMARY_FLAG {
            Detection::print_rule_load_info(
                &rulefile_loader.rulecounter,
                &rulefile_loader.rule_load_cnt,
                &rulefile_loader.rule_status_cnt,
                &parseerror_count,
            );
        }
        ret
    }

    // 複数のイベントレコードに対して、複数のルールを1個実行します。
    async fn execute_rules(mut self, records: Vec<EvtxRecordInfo>) -> Self {
        let records_arc = Arc::new(records);
        // // 各rule毎にスレッドを作成して、スレッドを起動する。
        let rules = self.rules;
        let handles: Vec<JoinHandle<RuleNode>> = rules
            .into_iter()
            .map(|rule| {
                let records_cloned = Arc::clone(&records_arc);
                spawn(async move { Detection::execute_rule(rule, records_cloned) })
            })
            .collect();

        // 全スレッドの実行完了を待機
        let mut rules = vec![];
        for handle in handles {
            let ret_rule = handle.await.unwrap();
            rules.push(ret_rule);
        }

        // この関数の先頭でrules.into_iter()を呼び出している。それにより所有権がmapのruleを経由し、execute_ruleの引数に渡しているruleに移っているので、self.rulesには所有権が無くなっている。
        // 所有権を失ったメンバー変数を持つオブジェクトをreturnするコードを書くと、コンパイラが怒になるので(E0382という番号のコンパイルエラー)、ここでself.rulesに所有権を戻している。
        // self.rulesが再度所有権を取り戻せるように、Detection::execute_ruleで引数に渡したruleを戻り値として返すようにしている。
        self.rules = rules;

        self
    }

    pub fn add_aggcondition_msges(self, rt: &Runtime) {
        return rt.block_on(self.add_aggcondition_msg());
    }

    async fn add_aggcondition_msg(&self) {
        for rule in &self.rules {
            if !rule.has_agg_condition() {
                continue;
            }

            let agg_results = rule.judge_satisfy_aggcondition();
            for value in agg_results {
                Detection::insert_agg_message(rule, value);
            }
        }
    }

    // 複数のイベントレコードに対して、ルールを1個実行します。
    fn execute_rule(mut rule: RuleNode, records: Arc<Vec<EvtxRecordInfo>>) -> RuleNode {
        let agg_condition = rule.has_agg_condition();
        for record_info in records.as_ref() {
            let result = rule.select(record_info);
            if !result {
                continue;
            }

            if *PIVOT_KEYWORD_LIST_FLAG {
                insert_pivot_keyword(&record_info.record);
                continue;
            }

            // aggregation conditionが存在しない場合はそのまま出力対応を行う
            if !agg_condition {
                Detection::insert_message(&rule, record_info);
            }
        }

        rule
    }

    /// 条件に合致したレコードを格納するための関数
    fn insert_message(rule: &RuleNode, record_info: &EvtxRecordInfo) {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let recinfo = record_info
            .record_information
            .as_ref()
            .map(|recinfo| recinfo.to_string());
        let rec_id = if LOAEDED_PROFILE_ALIAS.contains("%RecordID%") {
            Some(
                get_serde_number_to_string(&record_info.record["Event"]["System"]["EventRecordID"])
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let ch_str = &get_serde_number_to_string(&record_info.record["Event"]["System"]["Channel"])
            .unwrap_or_default();
        let provider = &get_serde_number_to_string(
            &record_info.record["Event"]["System"]["Provider_attributes"]["Name"],
        )
        .unwrap_or_default();
        let eid = get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"])
            .unwrap_or_else(|| "-".to_owned());
        let default_output = match DEFAULT_DETAILS.get(&format!("{}_{}", provider, &eid)) {
            Some(str) => str.to_owned(),
            None => recinfo.as_ref().unwrap_or(&"-".to_string()).to_string(),
        };
        let opt_record_info = if LOAEDED_PROFILE_ALIAS.contains("%AllFieldInfo%") {
            recinfo
        } else {
            None
        };

        let default_time = Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
        let time = message::get_event_time(&record_info.record).unwrap_or(default_time);
        let level = rule.yaml["level"].as_str().unwrap_or("-").to_string();

        let mut profile_converter: HashMap<String, String> = HashMap::new();
        let mut tags_config_values = TAGS_CONFIG.values();
        for p in PROFILES.as_ref().unwrap().iter() {
            for target_profile in PRELOAD_PROFILE_REGEX.matches(p[1].to_string().as_str()).into_iter() {
                match PRELOAD_PROFILE[target_profile] {
                    "%Timestamp%" => {
                        profile_converter
                            .insert("%Timestamp%".to_string(), format_time(&time, false));
                    }
                    "%Computer%" => {
                        profile_converter.insert(
                            "%Computer%".to_string(),
                            record_info.record["Event"]["System"]["Computer"]
                                .to_string()
                                .replace('\"', ""),
                        );
                    }
                    "%Channel%" => {
                        profile_converter.insert(
                            "%Channel%".to_string(),
                            CH_CONFIG
                                .get(&ch_str.to_ascii_lowercase())
                                .unwrap_or(ch_str)
                                .to_string(),
                        );
                    }
                    "%Level%" => {
                        profile_converter.insert(
                            "%Level%".to_string(),
                            LEVEL_ABBR_MAP.get(&level).unwrap_or(&level).to_string(),
                        );
                    }
                    "%EventID%" => {
                        profile_converter.insert("%EventID%".to_string(), eid.to_owned());
                    }
                    "%RecordID%" => {
                        profile_converter.insert(
                            "%RecordID%".to_string(),
                            rec_id.as_ref().unwrap_or(&"".to_string()).to_owned(),
                        );
                    }
                    "%RuleTitle%" => {
                        profile_converter.insert(
                            "%RuleTitle%".to_string(),
                            rule.yaml["title"].as_str().unwrap_or("").to_string(),
                        );
                    }
                    "%AllFieldInfo%" => {
                        profile_converter.insert(
                            "%AllFieldInfo%".to_string(),
                            opt_record_info
                                .as_ref()
                                .unwrap_or(&"-".to_string())
                                .to_owned(),
                        );
                    }
                    "%RuleFile%" => {
                        profile_converter.insert(
                            "%RuleFile%".to_string(),
                            Path::new(&rule.rulepath)
                                .file_name()
                                .unwrap_or_default()
                                .to_str()
                                .unwrap_or_default()
                                .to_string(),
                        );
                    }
                    "%EvtxFile%" => {
                        profile_converter.insert(
                            "%EvtxFile%".to_string(),
                            Path::new(&record_info.evtx_filepath)
                                .to_str()
                                .unwrap_or_default()
                                .to_string(),
                        );
                    }
                    "%MitreTactics%" => {
                        let tactics: &String = &tag_info
                            .iter()
                            .filter(|x| tags_config_values.contains(&x.to_string()))
                            .join(" ¦ ");

                        profile_converter.insert("%MitreTactics%".to_string(), tactics.to_string());
                    }
                    "%MitreTags%" => {
                        let techniques: &String = &tag_info
                            .iter()
                            .filter(|x| {
                                !tags_config_values.contains(&x.to_string())
                                    && (x.starts_with("attack.t")
                                        || x.starts_with("attack.g")
                                        || x.starts_with("attack.s"))
                            })
                            .map(|y| {
                                let replaced_tag = y.replace("attack.", "");
                                make_ascii_titlecase(&replaced_tag)
                            })
                            .join(" ¦ ");
                        profile_converter.insert("%MitreTags%".to_string(), techniques.to_string());
                    }
                    "%OtherTags%" => {
                        let tags: &String = &tag_info
                            .iter()
                            .filter(|x| {
                                !(TAGS_CONFIG.values().contains(&x.to_string())
                                    || x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                            })
                            .join(" ¦ ");
                        profile_converter.insert("%OtherTags%".to_string(), tags.to_string());
                    }
                    "%RuleAuthor%" => {
                        profile_converter.insert(
                            "%RuleAuthor%".to_string(),
                            rule.yaml["author"].as_str().unwrap_or("-").to_string(),
                        );
                    }
                    "%RuleCreationDate%" => {
                        profile_converter.insert(
                            "%RuleCreationDate%".to_string(),
                            rule.yaml["date"].as_str().unwrap_or("-").to_string(),
                        );
                    }
                    "%RuleModifiedDate%" => {
                        profile_converter.insert(
                            "%RuleModifiedDate%".to_string(),
                            rule.yaml["modified"].as_str().unwrap_or("-").to_string(),
                        );
                    }
                    "%Status%" => {
                        profile_converter.insert(
                            "%Status%".to_string(),
                            rule.yaml["status"].as_str().unwrap_or("-").to_string(),
                        );
                    }
                    _ => {}
                }
            }
        }

        let detect_info = DetectInfo {
            rulepath: rule.rulepath.to_owned(),
            ruletitle: rule.yaml["title"].as_str().unwrap_or("-").to_string(),
            level: LEVEL_ABBR_MAP.get(&level).unwrap_or(&level).to_string(),
            computername: record_info.record["Event"]["System"]["Computer"]
                .to_string()
                .replace('\"', ""),
            eventid: eid,
            detail: String::default(),
            record_information: opt_record_info,
            ext_field: PROFILES.as_ref().unwrap().to_owned(),
        };
        message::insert(
            &record_info.record,
            rule.yaml["details"]
                .as_str()
                .unwrap_or(&default_output)
                .to_string(),
            detect_info,
            time,
            &mut profile_converter,
            false,
        );
    }

    /// insert aggregation condition detection message to output stack
    fn insert_agg_message(rule: &RuleNode, agg_result: AggResult) {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let output = Detection::create_count_output(rule, &agg_result);
        let rec_info = if LOAEDED_PROFILE_ALIAS.contains("%AllFieldInfo%") {
            Option::Some(String::default())
        } else {
            Option::None
        };

        let mut profile_converter: HashMap<String, String> = HashMap::new();
        let level = rule.yaml["level"].as_str().unwrap_or("-").to_string();
        let mut tags_config_values = TAGS_CONFIG.values();

        for p in PROFILES.as_ref().unwrap().iter() {
            for target_profile in PRELOAD_PROFILE_REGEX.matches(p[1].to_string().as_str()).into_iter() {
                match PRELOAD_PROFILE[target_profile] {
                    "%Timestamp%" => {
                        profile_converter.insert(
                            "%Timestamp%".to_string(),
                            format_time(&agg_result.start_timedate, false),
                        );
                    }
                    "%Computer%" => {
                        profile_converter.insert("%Computer%".to_string(), "-".to_owned());
                    }
                    "%Channel%" => {
                        profile_converter.insert("%Channel%".to_string(), "-".to_owned());
                    }
                    "%Level%" => {
                        profile_converter.insert(
                            "%Level%".to_string(),
                            LEVEL_ABBR_MAP.get(&level).unwrap_or(&level).to_string(),
                        );
                    }
                    "%EventID%" => {
                        profile_converter.insert("%EventID%".to_string(), "-".to_owned());
                    }
                    "%RecordID%" => {
                        profile_converter.insert("%RecordID%".to_string(), "".to_owned());
                    }
                    "%RuleTitle%" => {
                        profile_converter.insert(
                            "%RuleTitle%".to_string(),
                            rule.yaml["title"].as_str().unwrap_or("").to_string(),
                        );
                    }
                    "%AllFieldInfo%" => {
                        profile_converter.insert("%AllFieldInfo%".to_string(), "-".to_owned());
                    }
                    "%RuleFile%" => {
                        profile_converter.insert(
                            "%RuleFile%".to_string(),
                            Path::new(&rule.rulepath)
                                .file_name()
                                .unwrap_or_default()
                                .to_str()
                                .unwrap_or_default()
                                .to_string(),
                        );
                    }
                    "%EvtxFile%" => {
                        profile_converter.insert("%EvtxFile%".to_string(), "-".to_owned());
                    }
                    "%MitreTactics%" => {
                        let tactics: &String = &tag_info
                            .iter()
                            .filter(|x| tags_config_values.contains(&x.to_string()))
                            .join(" ¦ ");
                        profile_converter.insert("%MitreTactics%".to_string(), tactics.to_string());
                    }
                    "%MitreTags%" => {
                        let techniques: &String = &tag_info
                            .iter()
                            .filter(|x| {
                                !tags_config_values.contains(&x.to_string())
                                    && (x.starts_with("attack.t")
                                        || x.starts_with("attack.g")
                                        || x.starts_with("attack.s"))
                            })
                            .map(|y| {
                                let replaced_tag = y.replace("attack.", "");
                                make_ascii_titlecase(&replaced_tag)
                            })
                            .join(" ¦ ");
                        profile_converter.insert("%MitreTags%".to_string(), techniques.to_string());
                    }
                    "%OtherTags%" => {
                        let tags: &String = &tag_info
                            .iter()
                            .filter(|x| {
                                !(tags_config_values.contains(&x.to_string())
                                    || x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                            })
                            .join(" ¦ ");
                        profile_converter.insert("%OtherTags%".to_string(), tags.to_string());
                    }
                    _ => {}
                }
            }
        }

        let detect_info = DetectInfo {
            rulepath: rule.rulepath.to_owned(),
            ruletitle: rule.yaml["title"].as_str().unwrap_or("-").to_string(),
            level: LEVEL_ABBR_MAP.get(&level).unwrap_or(&level).to_string(),
            computername: "-".to_owned(),
            eventid: "-".to_owned(),
            detail: output,
            record_information: rec_info,
            ext_field: PROFILES.as_ref().unwrap().to_owned(),
        };

        message::insert(
            &Value::default(),
            rule.yaml["details"].as_str().unwrap_or("-").to_string(),
            detect_info,
            agg_result.start_timedate,
            &mut profile_converter,
            true,
        )
    }

    /// rule内のtagsの内容を配列として返却する関数
    fn get_tag_info(rule: &RuleNode) -> Nested<String> {
        match TAGS_CONFIG.is_empty() {
            false => Nested::from_iter(
                rule.yaml["tags"]
                    .as_vec()
                    .unwrap_or(&Vec::default())
                    .iter()
                    .map(|info| {
                        if let Some(tag) =
                            TAGS_CONFIG.get(info.as_str().unwrap_or(&String::default()))
                        {
                            tag.to_owned()
                        } else {
                            info.as_str().unwrap_or(&String::default()).to_owned()
                        }
                    }),
            ),
            true => Nested::from_iter(
                rule.yaml["tags"]
                    .as_vec()
                    .unwrap_or(&Vec::default())
                    .iter()
                    .map(|info| {
                        match TAGS_CONFIG.get(info.as_str().unwrap_or(&String::default())) {
                            Some(s) => s.to_owned(),
                            _ => info.as_str().unwrap_or("").to_string(),
                        }
                    }),
            ),
        }
    }

    ///aggregation conditionのcount部分の検知出力文の文字列を返す関数
    fn create_count_output(rule: &RuleNode, agg_result: &AggResult) -> String {
        // 条件式部分の出力
        let mut ret: String = "[condition] ".to_owned();
        let agg_condition_raw_str: Vec<&str> = rule.yaml["detection"]["condition"]
            .as_str()
            .unwrap()
            .split('|')
            .collect();
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでunwrap前の確認は行わない
        let agg_condition = rule.get_agg_condition().unwrap();
        let exist_timeframe = rule.yaml["detection"]["timeframe"].as_str().unwrap_or("") != "";
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでagg_conditionの配列の長さは2となる
        ret.push_str(agg_condition_raw_str[1].trim());
        if exist_timeframe {
            ret.push_str(" in timeframe");
        }

        let _ = write!(ret, " [result] count:{}", agg_result.data);
        if agg_condition._field_name.is_some() {
            let _ = write!(
                ret,
                " {}:{}",
                agg_condition._field_name.as_ref().unwrap(),
                agg_result.field_values.join("/")
            );
        }

        if agg_condition._by_field_name.is_some() {
            let _ = write!(
                ret,
                " {}:{}",
                agg_condition._by_field_name.as_ref().unwrap(),
                agg_result.key
            );
        }

        if exist_timeframe {
            let _ = write!(
                ret,
                " timeframe:{}",
                rule.yaml["detection"]["timeframe"].as_str().unwrap()
            );
        }

        ret
    }

    pub fn print_rule_load_info(
        rc: &HashMap<String, u128>,
        ld_rc: &HashMap<String, u128>,
        st_rc: &HashMap<String, u128>,
        err_rc: &u128,
    ) {
        if *METRICS_FLAG {
            return;
        }
        let mut sorted_ld_rc: Vec<(&String, &u128)> = ld_rc.iter().collect();
        sorted_ld_rc.sort_by(|a, b| a.0.cmp(b.0));
        let args = &configs::CONFIG.read().unwrap().args;
        let mut html_report_stock = Nested::<String>::new();

        sorted_ld_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let disable_flag = if key == "noisy" && !args.enable_noisy_rules {
                    " (Disabled)"
                } else {
                    ""
                };
                //タイトルに利用するものはascii文字であることを前提として1文字目を大文字にするように変更する
                let output_str = format!(
                    "{} rules: {}{}",
                    make_ascii_titlecase(key),
                    value,
                    disable_flag
                );
                println!("{}", output_str);
                if *HTML_REPORT_FLAG {
                    html_report_stock.push(format!("- {}", output_str));
                }
            }
        });
        if err_rc != &0_u128 {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                Some(Color::Red),
                &format!("Rule parsing errors: {}", err_rc),
                true,
            )
            .ok();
        }
        println!();

        let mut sorted_st_rc: Vec<(&String, &u128)> = st_rc.iter().collect();
        let total_loaded_rule_cnt: u128 = sorted_st_rc.iter().map(|(_, v)| v.to_owned()).sum();
        sorted_st_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_st_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let rate = (*value as f64) / (total_loaded_rule_cnt as f64) * 100.0;
                let deprecated_flag = if key == "deprecated" && !args.enable_deprecated_rules {
                    " (Disabled)"
                } else {
                    ""
                };
                let output_str = format!(
                    "{} rules: {} ({:.2}%){}",
                    make_ascii_titlecase(key),
                    value,
                    rate,
                    deprecated_flag
                );
                //タイトルに利用するものはascii文字であることを前提として1文字目を大文字にするように変更する
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &output_str,
                    true,
                )
                .ok();
                if *HTML_REPORT_FLAG {
                    html_report_stock.push(format!("- {}", output_str));
                }
            }
        });
        println!();

        let mut sorted_rc: Vec<(&String, &u128)> = rc.iter().collect();
        sorted_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_rc.into_iter().for_each(|(key, value)| {
            let output_str = format!("{} rules: {}", key, value);
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                &output_str,
                true,
            )
            .ok();
            if *HTML_REPORT_FLAG {
                html_report_stock.push(format!("- {}", output_str));
            }
        });

        let tmp_total_detect_output =
            format!("Total enabled detection rules: {}", total_loaded_rule_cnt);
        println!("{}", tmp_total_detect_output);
        println!();
        if *HTML_REPORT_FLAG {
            html_report_stock.push(format!("- {}", tmp_total_detect_output));
        }
        if !html_report_stock.is_empty() {
            htmlreport::add_md_data(
                "General Overview {#general_overview}".to_string(),
                html_report_stock,
            );
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::detections::detection::Detection;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::AggResult;
    use crate::filter;
    use chrono::{TimeZone, Utc};
    use std::path::Path;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_parse_rule_files() {
        let level = "informational";
        let opt_rule_path = Path::new("./test_files/rules/level_yaml");
        let cole =
            Detection::parse_rule_files(level.to_owned(), opt_rule_path, &filter::exclude_ids());
        assert_eq!(5, cole.len());
    }

    #[test]
    fn test_output_aggregation_output_with_output() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, ">= 1".to_string());
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
        output: testdata
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output = "[condition] count() >= 1 [result] count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_no_filed_by() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, ">= 1".to_string());
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 |   count() >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output = "[condition] count() >= 1 [result] count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_timeframe() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, ">= 1".to_string());
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 |   count() >= 1
            timeframe: 15m
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output =
            "[condition] count() >= 1 in timeframe [result] count:2 timeframe:15m";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult = AggResult::new(
            2,
            "_".to_string(),
            vec!["7040".to_owned(), "9999".to_owned()],
            default_time,
            ">= 1".to_string(),
        );
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count(EventID) >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output = "[condition] count(EventID) >= 1 [result] count:2 EventID:7040/9999";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field_by() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult = AggResult::new(
            2,
            "lsass.exe".to_string(),
            vec!["0000".to_owned(), "1111".to_owned()],
            default_time,
            ">= 1".to_string(),
        );
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count(EventID) by process >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output = "[condition] count(EventID) by process >= 1 [result] count:2 EventID:0000/1111 process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }
    #[test]
    fn test_output_aggregation_output_with_by() {
        let default_time = Utc.ymd(1977, 1, 1).and_hms(0, 0, 0);
        let agg_result: AggResult = AggResult::new(
            2,
            "lsass.exe".to_string(),
            vec![],
            default_time,
            ">= 1".to_string(),
        );
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 | count() by process >= 1
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        rule_node.init().ok();
        let expected_output =
            "[condition] count() by process >= 1 [result] count:2 process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_create_fields_value() {}
}

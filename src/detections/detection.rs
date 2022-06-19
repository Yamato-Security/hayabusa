extern crate csv;

use crate::detections::configs;
use crate::detections::pivot::insert_pivot_keyword;
use crate::detections::print::AlertMessage;
use crate::detections::print::DetectInfo;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::MESSAGES;
use crate::detections::print::{CH_CONFIG, DEFAULT_DETAILS, IS_HIDE_RECORD_ID, TAGS_CONFIG};
use crate::detections::print::{
    LOGONSUMMARY_FLAG, PIVOT_KEYWORD_LIST_FLAG, QUIET_ERRORS_FLAG, STATISTICS_FLAG,
};
use crate::detections::rule;
use crate::detections::rule::AggResult;
use crate::detections::rule::RuleNode;
use crate::detections::utils::{get_serde_number_to_string, make_ascii_titlecase};
use crate::filter;
use crate::yaml::ParseYaml;
use hashbrown;
use hashbrown::HashMap;
use serde_json::Value;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::{runtime::Runtime, spawn, task::JoinHandle};

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス　ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
    pub data_string: String,
    pub key_2_value: hashbrown::HashMap<String, String>,
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
            let _ = &rulefile_loader
                .rule_load_cnt
                .insert(String::from("rule parsing error"), parseerror_count);
            Detection::print_rule_load_info(
                &rulefile_loader.rulecounter,
                &rulefile_loader.rule_load_cnt,
                &rulefile_loader.rule_status_cnt,
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

    /// 条件に合致したレコードを表示するための関数
    fn insert_message(rule: &RuleNode, record_info: &EvtxRecordInfo) {
        let tag_info: Vec<String> = match TAGS_CONFIG.is_empty() {
            false => rule.yaml["tags"]
                .as_vec()
                .unwrap_or(&Vec::default())
                .iter()
                .filter_map(|info| TAGS_CONFIG.get(info.as_str().unwrap_or(&String::default())))
                .map(|str| str.to_owned())
                .collect(),
            true => rule.yaml["tags"]
                .as_vec()
                .unwrap_or(&Vec::default())
                .iter()
                .map(
                    |info| match TAGS_CONFIG.get(info.as_str().unwrap_or(&String::default())) {
                        Some(s) => s.to_owned(),
                        _ => info.as_str().unwrap_or("").replace("attack.", ""),
                    },
                )
                .collect(),
        };

        let recinfo = record_info
            .record_information
            .as_ref()
            .map(|recinfo| recinfo.to_string());
        let rec_id = if !*IS_HIDE_RECORD_ID {
            Some(
                get_serde_number_to_string(&record_info.record["Event"]["System"]["EventRecordID"])
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let ch_str = &get_serde_number_to_string(&record_info.record["Event"]["System"]["Channel"])
            .unwrap_or_default();
        let eid = get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"])
            .unwrap_or_else(|| "-".to_owned());
        let default_output = DEFAULT_DETAILS
            .get(&format!("{}_{}", ch_str, &eid))
            .unwrap_or(&"-".to_string())
            .to_string();
        let detect_info = DetectInfo {
            filepath: record_info.evtx_filepath.to_string(),
            rulepath: rule.rulepath.to_string(),
            level: rule.yaml["level"].as_str().unwrap_or("-").to_string(),
            computername: record_info.record["Event"]["System"]["Computer"]
                .to_string()
                .replace('\"', ""),
            eventid: eid,
            channel: CH_CONFIG.get(ch_str).unwrap_or(ch_str).to_string(),
            alert: rule.yaml["title"].as_str().unwrap_or("").to_string(),
            detail: String::default(),
            tag_info: tag_info.join(" | "),
            record_information: recinfo,
            record_id: rec_id,
        };
        MESSAGES.lock().unwrap().insert(
            &record_info.record,
            rule.yaml["details"]
                .as_str()
                .unwrap_or(&default_output)
                .to_string(),
            detect_info,
        );
    }

    /// insert aggregation condition detection message to output stack
    fn insert_agg_message(rule: &RuleNode, agg_result: AggResult) {
        let tag_info: Vec<String> = rule.yaml["tags"]
            .as_vec()
            .unwrap_or(&Vec::default())
            .iter()
            .filter_map(|info| TAGS_CONFIG.get(info.as_str().unwrap_or(&String::default())))
            .map(|str| str.to_owned())
            .collect();
        let output = Detection::create_count_output(rule, &agg_result);
        let rec_info = if configs::CONFIG.read().unwrap().args.full_data {
            Option::Some(String::default())
        } else {
            Option::None
        };
        let rec_id = if !*IS_HIDE_RECORD_ID {
            Some(String::default())
        } else {
            None
        };
        let detect_info = DetectInfo {
            filepath: "-".to_owned(),
            rulepath: rule.rulepath.to_owned(),
            level: rule.yaml["level"].as_str().unwrap_or("").to_owned(),
            computername: "-".to_owned(),
            eventid: "-".to_owned(),
            channel: "-".to_owned(),
            alert: rule.yaml["title"].as_str().unwrap_or("").to_owned(),
            detail: output,
            record_information: rec_info,
            tag_info: tag_info.join(" : "),
            record_id: rec_id,
        };

        MESSAGES
            .lock()
            .unwrap()
            .insert_message(detect_info, agg_result.start_timedate)
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
    ) {
        if *STATISTICS_FLAG {
            return;
        }
        let mut sorted_ld_rc: Vec<(&String, &u128)> = ld_rc.iter().collect();
        sorted_ld_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_ld_rc.into_iter().for_each(|(key, value)| {
            //タイトルに利用するものはascii文字であることを前提として1文字目を大文字にするように変更する
            println!(
                "{} rules: {}",
                make_ascii_titlecase(key.clone().as_mut()),
                value,
            );
        });
        println!();

        let mut sorted_st_rc: Vec<(&String, &u128)> = st_rc.iter().collect();
        let total_loaded_rule_cnt: u128 = sorted_st_rc.iter().map(|(_, v)| v.to_owned()).sum();
        sorted_st_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_st_rc.into_iter().for_each(|(key, value)| {
            let rate = if value == &0_u128 {
                0 as f64
            } else {
                (*value as f64) / (total_loaded_rule_cnt as f64) * 100.0
            };
            //タイトルに利用するものはascii文字であることを前提として1文字目を大文字にするように変更する
            println!(
                "{} rules: {} ({:.2}%)",
                make_ascii_titlecase(key.clone().as_mut()),
                value,
                rate
            );
        });
        println!();

        let mut sorted_rc: Vec<(&String, &u128)> = rc.iter().collect();
        sorted_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_rc.into_iter().for_each(|(key, value)| {
            println!("{} rules: {}", key, value);
        });
        println!("Total enabled detection rules: {}", total_loaded_rule_cnt);
        println!();
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

extern crate csv;

use crate::detections::configs;
use crate::detections::print::AlertMessage;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::MESSAGES;
use crate::detections::print::QUIET_ERRORS_FLAG;
use crate::detections::print::STATISTICS_FLAG;
use crate::detections::rule;
use crate::detections::rule::AggResult;
use crate::detections::rule::RuleNode;
use crate::detections::utils::get_serde_number_to_string;
use crate::filter;
use crate::yaml::ParseYaml;
use hashbrown;
use hashbrown::HashMap;
use serde_json::Value;
use std::io::BufWriter;
use std::sync::Arc;
use tokio::{runtime::Runtime, spawn, task::JoinHandle};

const DIRPATH_RULES: &str = "rules";

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス　ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
    pub data_string: String,
    pub key_2_value: hashbrown::HashMap<String, String>,
}

impl EvtxRecordInfo {
    pub fn get_value(&self, key: &String) -> Option<&String> {
        return self.key_2_value.get(key);
    }
}

#[derive(Debug)]
pub struct Detection {
    rules: Vec<RuleNode>,
}

impl Detection {
    pub fn new(rule_nodes: Vec<RuleNode>) -> Detection {
        return Detection { rules: rule_nodes };
    }

    pub fn start(self, rt: &Runtime, records: Vec<EvtxRecordInfo>) -> Self {
        return rt.block_on(self.execute_rules(records));
    }

    // ルールファイルをパースします。
    pub fn parse_rule_files(
        level: String,
        rulespath: Option<&str>,
        exclude_ids: &filter::RuleExclude,
    ) -> Vec<RuleNode> {
        // ルールファイルのパースを実行
        let mut rulefile_loader = ParseYaml::new();
        let result_readdir =
            rulefile_loader.read_dir(rulespath.unwrap_or(DIRPATH_RULES), &level, exclude_ids);
        if result_readdir.is_err() {
            let errmsg = format!("{}", result_readdir.unwrap_err());
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::alert(&mut BufWriter::new(std::io::stderr().lock()), &errmsg).ok();
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
                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    AlertMessage::warn(&mut std::io::stdout().lock(), &errmsg_body).ok();

                    err_msgs.iter().for_each(|err_msg| {
                        AlertMessage::warn(&mut std::io::stdout().lock(), err_msg).ok();
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
                println!(); // 一行開けるためのprintln
            });
            return Option::None;
        };
        // parse rule files
        let ret = rulefile_loader
            .files
            .into_iter()
            .map(|rule_file_tuple| rule::create_rule(rule_file_tuple.0, rule_file_tuple.1))
            .filter_map(return_if_success)
            .collect();
        Detection::print_rule_load_info(
            &rulefile_loader.rulecounter,
            &parseerror_count,
            &rulefile_loader.ignorerule_count,
        );
        return ret;
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
                return spawn(async move {
                    let moved_rule = Detection::execute_rule(rule, records_cloned);
                    return moved_rule;
                });
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

        return self;
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
            let result = rule.select(&record_info);
            if !result {
                continue;
            }
            // aggregation conditionが存在しない場合はそのまま出力対応を行う
            if !agg_condition {
                Detection::insert_message(&rule, &record_info);
            }
        }

        return rule;
    }

    /// 条件に合致したレコードを表示するための関数
    fn insert_message(rule: &RuleNode, record_info: &EvtxRecordInfo) {
        let tag_info: Vec<String> = rule.yaml["tags"]
            .as_vec()
            .unwrap_or(&Vec::default())
            .into_iter()
            .map(|info| info.as_str().unwrap_or("").replace("attack.", ""))
            .collect();
        MESSAGES.lock().unwrap().insert(
            record_info.evtx_filepath.to_string(),
            rule.rulepath.to_string(),
            &record_info.record,
            rule.yaml["level"].as_str().unwrap_or("-").to_string(),
            record_info.record["Event"]["System"]["Computer"]
                .to_string()
                .replace("\"", ""),
            get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"])
                .unwrap_or("-".to_owned())
                .to_string(),
            rule.yaml["title"].as_str().unwrap_or("").to_string(),
            rule.yaml["details"].as_str().unwrap_or("").to_string(),
            tag_info.join(" : "),
        );
    }

    /// insert aggregation condition detection message to output stack
    fn insert_agg_message(rule: &RuleNode, agg_result: AggResult) {
        let tag_info: Vec<String> = rule.yaml["tags"]
            .as_vec()
            .unwrap_or(&Vec::default())
            .into_iter()
            .map(|info| info.as_str().unwrap_or("").replace("attack.", ""))
            .collect();
        let output = Detection::create_count_output(rule, &agg_result);
        MESSAGES.lock().unwrap().insert_message(
            "-".to_owned(),
            rule.rulepath.to_owned(),
            agg_result.start_timedate,
            rule.yaml["level"].as_str().unwrap_or("").to_owned(),
            "-".to_owned(),
            "-".to_owned(),
            rule.yaml["title"].as_str().unwrap_or("").to_owned(),
            output.to_owned(),
            tag_info.join(" : "),
        )
    }

    ///aggregation conditionのcount部分の検知出力文の文字列を返す関数
    fn create_count_output(rule: &RuleNode, agg_result: &AggResult) -> String {
        // 条件式部分の出力
        let mut ret: String = "[condition] ".to_owned();
        let agg_condition_raw_str: Vec<&str> = rule.yaml["detection"]["condition"]
            .as_str()
            .unwrap()
            .split("|")
            .collect();
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでunwrap前の確認は行わない
        let agg_condition = rule.get_agg_condition().unwrap();
        let exist_timeframe = rule.yaml["detection"]["timeframe"]
            .as_str()
            .unwrap_or("")
            .to_string()
            != "";
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでagg_conditionの配列の長さは2となる
        ret.push_str(agg_condition_raw_str[1].trim());
        if exist_timeframe {
            ret.push_str(" in timeframe");
        }

        ret.push_str(&format!(" [result] count:{}", agg_result.data));
        if agg_condition._field_name.is_some() {
            ret.push_str(&format!(
                " {}:{}",
                agg_condition._field_name.as_ref().unwrap(),
                agg_result.field_values.join("/")
            ));
        }

        if agg_condition._by_field_name.is_some() {
            ret.push_str(&format!(
                " {}:{}",
                agg_condition._by_field_name.as_ref().unwrap(),
                agg_result.key
            ));
        }

        if exist_timeframe {
            ret.push_str(&format!(
                " timeframe:{}",
                rule.yaml["detection"]["timeframe"].as_str().unwrap()
            ));
        }

        return ret;
    }
    pub fn print_rule_load_info(
        rc: &HashMap<String, u128>,
        parseerror_count: &u128,
        ignore_count: &u128,
    ) {
        if *STATISTICS_FLAG {
            return;
        }
        let mut total = parseerror_count + ignore_count;
        rc.into_iter().for_each(|(key, value)| {
            println!("{} rules: {}", key, value);
            total += value;
        });
        println!("Ignored rules: {}", ignore_count);
        println!("Rule parsing errors: {}", parseerror_count);
        println!(
            "Total enabled detection rules: {}",
            total - ignore_count - parseerror_count
        );
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
    use yaml_rust::YamlLoader;

    #[test]
    fn test_parse_rule_files() {
        let level = "informational";
        let opt_rule_path = Some("./test_files/rules/level_yaml");
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
}

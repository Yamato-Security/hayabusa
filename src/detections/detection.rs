extern crate csv;

use crate::detections::utils::{create_recordinfos, format_time, write_color_buffer};
use crate::options::profile::Profile::{
    self, Channel, Computer, EventID, EvtxFile, Level, MitreTactics, MitreTags, OtherTags,
    Provider, RecordID, RenderedMessage, RuleAuthor, RuleCreationDate, RuleFile, RuleID,
    RuleModifiedDate, RuleTitle, SrcASN, SrcCity, SrcCountry, Status, TgtASN, TgtCity, TgtCountry,
    Timestamp,
};
use chrono::{TimeZone, Utc};
use compact_str::CompactString;
use itertools::Itertools;
use nested::Nested;
use std::default::Default;
use termcolor::{BufferWriter, Color, ColorChoice};
use yaml_rust::YamlLoader;

use crate::detections::message::{AlertMessage, DetectInfo, ERROR_LOG_STACK, TAGS_CONFIG};
use crate::detections::pivot::insert_pivot_keyword;
use crate::detections::rule::{self, AggResult, RuleNode};
use crate::detections::utils::{get_serde_number_to_string, make_ascii_titlecase};
use crate::options::htmlreport;
use crate::yaml::ParseYaml;
use crate::{filter, yaml};
use hashbrown::HashMap;
use serde_json::Value;
use std::fmt::Write;
use std::path::Path;

use crate::detections::configs::STORED_EKEY_ALIAS;
use std::sync::Arc;
use tokio::{runtime::Runtime, spawn, task::JoinHandle};

use super::configs::{
    EventKeyAliasConfig, StoredStatic, CURRENT_EXE_PATH, GEOIP_DB_PARSER, STORED_STATIC,
};
use super::message::{self, LEVEL_ABBR_MAP};
use super::utils;

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
    pub data_string: String,
    pub key_2_value: HashMap<String, String>,
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
        level: &str,
        rulespath: &Path,
        exclude_ids: &filter::RuleExclude,
        stored_static: &StoredStatic,
    ) -> Vec<RuleNode> {
        // ルールファイルのパースを実行
        let mut rulefile_loader = ParseYaml::new(stored_static);
        let result_readdir = rulefile_loader.read_dir(rulespath, level, exclude_ids, stored_static);
        if result_readdir.is_err() {
            let errmsg = format!("{}", result_readdir.unwrap_err());
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
            }
            return vec![];
        }
        let mut parseerror_count = rulefile_loader.errorrule_count;
        let return_if_success = |mut rule: RuleNode| {
            let err_msgs_result = rule.init(stored_static);
            if err_msgs_result.is_ok() {
                return Some(rule);
            }

            // ruleファイルのパースに失敗した場合はエラー出力
            err_msgs_result.err().iter().for_each(|err_msgs| {
                let errmsg_body =
                    format!("Failed to parse rule file. (FilePath : {})", rule.rulepath);
                if stored_static.verbose_flag {
                    AlertMessage::warn(&errmsg_body).ok();
                    err_msgs.iter().for_each(|err_msg| {
                        AlertMessage::warn(err_msg).ok();
                    });
                    println!();
                }
                if !stored_static.quiet_errors_flag {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[WARN] {errmsg_body}"));
                    err_msgs.iter().for_each(|err_msg| {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {err_msg}"));
                    });
                }
                parseerror_count += 1;
            });
            None
        };
        // parse rule files
        let ret = rulefile_loader
            .files
            .into_iter()
            .map(|rule_file_tuple| rule::create_rule(rule_file_tuple.0, rule_file_tuple.1))
            .filter_map(return_if_success)
            .collect();
        if !stored_static.logon_summary_flag {
            Detection::print_rule_load_info(
                &rulefile_loader.rulecounter,
                &rulefile_loader.rule_load_cnt,
                &rulefile_loader.rule_status_cnt,
                &parseerror_count,
                stored_static,
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

    pub fn add_aggcondition_msges(self, rt: &Runtime, stored_static: &StoredStatic) {
        return rt.block_on(self.add_aggcondition_msg(stored_static));
    }

    async fn add_aggcondition_msg(&self, stored_static: &StoredStatic) {
        for rule in &self.rules {
            if !rule.has_agg_condition() {
                continue;
            }

            for value in rule.judge_satisfy_aggcondition(stored_static) {
                Detection::insert_agg_message(rule, value, stored_static);
            }
        }
    }

    // 複数のイベントレコードに対して、ルールを1個実行します。
    fn execute_rule(mut rule: RuleNode, records: Arc<Vec<EvtxRecordInfo>>) -> RuleNode {
        let agg_condition = rule.has_agg_condition();
        let binding = STORED_STATIC.read().unwrap();
        let stored_static = binding.as_ref().unwrap();
        for record_info in records.as_ref() {
            let result = rule.select(
                record_info,
                stored_static.verbose_flag,
                stored_static.quiet_errors_flag,
                stored_static.json_input_flag,
                &stored_static.eventkey_alias,
            );
            if !result {
                continue;
            }

            if stored_static.pivot_keyword_list_flag {
                insert_pivot_keyword(&record_info.record, &stored_static.eventkey_alias);
                continue;
            }

            // aggregation conditionが存在しない場合はそのまま出力対応を行う
            if !agg_condition {
                Detection::insert_message(&rule, record_info, stored_static);
            }
        }

        rule
    }

    /// 条件に合致したレコードを格納するための関数
    fn insert_message(rule: &RuleNode, record_info: &EvtxRecordInfo, stored_static: &StoredStatic) {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let rec_id = if stored_static
            .profiles
            .as_ref()
            .unwrap()
            .iter()
            .any(|(_s, p)| *p == RecordID(Default::default()))
        {
            get_serde_number_to_string(&record_info.record["Event"]["System"]["EventRecordID"])
                .unwrap_or_default()
        } else {
            CompactString::from("")
        };
        let ch_str = &get_serde_number_to_string(&record_info.record["Event"]["System"]["Channel"])
            .unwrap_or_default();
        let provider = &get_serde_number_to_string(
            &record_info.record["Event"]["System"]["Provider_attributes"]["Name"],
        )
        .unwrap_or_default();
        let eid = get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"])
            .unwrap_or_else(|| "-".into());

        let default_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let time = message::get_event_time(&record_info.record, stored_static.json_input_flag)
            .unwrap_or(default_time);
        let level = rule.yaml["level"].as_str().unwrap_or("-");

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();
        let binding = STORED_EKEY_ALIAS.read().unwrap();
        let eventkey_alias = binding.as_ref().unwrap();

        let mut geo_ip_mapping = vec![];
        if GEOIP_DB_PARSER.read().unwrap().is_some() {
            let yml_parser = yaml::ParseYaml::new(stored_static);
            let geo_ip_file_path =
                utils::check_setting_path(&stored_static.config_path, "geoip_field_mapping", false)
                    .unwrap_or_else(|| {
                        utils::check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/geoip_field_mapping.txt",
                            true,
                        )
                        .unwrap()
                    });
            let binding = geo_ip_file_path.clone();
            let output_path_str = binding.to_str().unwrap();

            geo_ip_mapping = if let Ok(loaded_profile) = yml_parser.read_file(geo_ip_file_path) {
                match YamlLoader::load_from_str(&loaded_profile) {
                    Ok(geo_ip_map) => geo_ip_map,
                    Err(e) => {
                        AlertMessage::alert(&format!("Parse error: {output_path_str}. {e}")).ok();
                        YamlLoader::load_from_str("").unwrap()
                    }
                }
            } else {
                AlertMessage::alert(&format!(
                    "not found geoip field mapping file. filepath: {output_path_str}"
                ))
                .ok();
                YamlLoader::load_from_str("").unwrap()
            };
        }

        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(CompactString::from(format_time(
                            &time,
                            false,
                            stored_static.output_option.as_ref().unwrap(),
                        ))),
                    );
                }
                Computer(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Computer(CompactString::from(
                            record_info.record["Event"]["System"]["Computer"]
                                .to_string()
                                .replace('\"', ""),
                        )),
                    );
                }
                Channel(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Channel(
                            stored_static
                                .ch_config
                                .get(&CompactString::from(ch_str.to_ascii_lowercase()))
                                .unwrap_or(ch_str)
                                .to_owned(),
                        ),
                    );
                }
                Level(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Level(CompactString::from(
                            LEVEL_ABBR_MAP.get(level).unwrap_or(&level).to_string(),
                        )),
                    );
                }
                EventID(_) => {
                    profile_converter.insert(key.as_str(), EventID(eid.clone()));
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID(rec_id.to_owned()));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(CompactString::from(
                            rule.yaml["title"].as_str().unwrap_or(""),
                        )),
                    );
                }
                RuleFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleFile(CompactString::from(
                            Path::new(&rule.rulepath)
                                .file_name()
                                .unwrap_or_default()
                                .to_str()
                                .unwrap_or_default(),
                        )),
                    );
                }
                EvtxFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EvtxFile(CompactString::from(
                            Path::new(&record_info.evtx_filepath)
                                .to_str()
                                .unwrap_or_default(),
                        )),
                    );
                }
                MitreTactics(_) => {
                    let tactics = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| tags_config_values.contains(&&CompactString::from(*x)))
                            .join(" ¦ "),
                    );

                    profile_converter.insert(key.as_str(), MitreTactics(tactics));
                }
                MitreTags(_) => {
                    let techniques = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| {
                                !tags_config_values.contains(&&CompactString::from(*x))
                                    && (x.starts_with("attack.t")
                                        || x.starts_with("attack.g")
                                        || x.starts_with("attack.s"))
                            })
                            .map(|y| {
                                let replaced_tag = y.replace("attack.", "");
                                make_ascii_titlecase(&replaced_tag)
                            })
                            .join(" ¦ "),
                    );
                    profile_converter.insert(key.as_str(), MitreTags(techniques));
                }
                OtherTags(_) => {
                    let tags = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| {
                                !(TAGS_CONFIG.values().contains(&CompactString::from(*x))
                                    || x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                            })
                            .join(" ¦ "),
                    );
                    profile_converter.insert(key.as_str(), OtherTags(tags));
                }
                RuleAuthor(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleAuthor(CompactString::from(
                            rule.yaml["author"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(CompactString::from(
                            rule.yaml["date"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(CompactString::from(
                            rule.yaml["modified"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(CompactString::from(
                            rule.yaml["status"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(CompactString::from(rule.yaml["id"].as_str().unwrap_or("-"))),
                    );
                }
                Provider(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Provider(CompactString::from(
                            record_info.record["Event"]["System"]["Provider_attributes"]["Name"]
                                .to_string()
                                .replace('\"', ""),
                        )),
                    );
                }
                RenderedMessage(_) => {
                    let convert_value = if let Some(message) =
                        record_info.record["Event"]["RenderingInfo"]["Message"].as_str()
                    {
                        CompactString::from(
                            message
                                .replace('\t', "\\t")
                                .split("\r\n")
                                .map(|x| x.trim())
                                .join("\r\n")
                                .replace('\n', "\\n")
                                .replace('\r', "\\r"),
                        )
                    } else {
                        CompactString::from("n/a")
                    };
                    profile_converter.insert(key.as_str(), RenderedMessage(convert_value));
                }
                TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // initialize geo-ip Tgt associated fields
                    profile_converter.insert("TgtASN", TgtASN("-".into()));
                    profile_converter.insert("TgtCountry", TgtCountry("-".into()));
                    profile_converter.insert("TgtCity", TgtCity("-".into()));
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping[0]["TgtIP"];
                    if target_alias.is_badvalue() {
                        continue;
                    }
                    let alias_data = Self::get_alias_data(
                        target_alias
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                    );
                    let geo_data = GEOIP_DB_PARSER
                        .read()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .convert_ip_to_geo(&alias_data);
                    if geo_data.is_err() {
                        continue;
                    }
                    let binding = geo_data.unwrap();
                    let mut tgt_data = binding
                        .split('🦅')
                        .map(|x| if x.is_empty() { "-" } else { x });
                    profile_converter
                        .entry("TgtASN")
                        .and_modify(|p| *p = TgtASN(tgt_data.next().unwrap().into()));
                    profile_converter
                        .entry("TgtCountry")
                        .and_modify(|p| *p = TgtCountry(tgt_data.next().unwrap().into()));
                    profile_converter
                        .entry("TgtCity")
                        .and_modify(|p| *p = TgtCity(tgt_data.next().unwrap().into()));
                }
                SrcASN(_) | SrcCountry(_) | SrcCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // initialize geo-ip Tgt associated fields
                    profile_converter.insert("SrcASN", SrcASN("-".into()));
                    profile_converter.insert("SrcCountry", SrcCountry("-".into()));
                    profile_converter.insert("SrcCity", SrcCity("-".into()));
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping[0]["SrcIP"];
                    if target_alias.is_badvalue() {
                        continue;
                    }

                    let alias_data = Self::get_alias_data(
                        target_alias
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                    );

                    let geo_data = GEOIP_DB_PARSER
                        .read()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .convert_ip_to_geo(&alias_data);
                    if geo_data.is_err() {
                        continue;
                    }
                    let binding = geo_data.unwrap();
                    let mut src_data = binding
                        .split('🦅')
                        .map(|x| if x.is_empty() { "-" } else { x });
                    profile_converter
                        .entry("SrcASN")
                        .and_modify(|p| *p = SrcASN(src_data.next().unwrap().into()));
                    profile_converter
                        .entry("SrcCountry")
                        .and_modify(|p| *p = SrcCountry(src_data.next().unwrap().into()));
                    profile_converter
                        .entry("SrcCity")
                        .and_modify(|p| *p = SrcCity(src_data.next().unwrap().into()));
                }
                _ => {}
            }
        }
        let details_fmt_str = match rule.yaml["details"].as_str() {
            Some(s) => s.to_string(),
            None => match stored_static
                .default_details
                .get(&CompactString::from(format!("{provider}_{eid}")))
            {
                Some(str) => str.to_string(),
                None => create_recordinfos(&record_info.record),
            },
        };

        let detect_info = DetectInfo {
            rulepath: CompactString::from(&rule.rulepath),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            level: CompactString::from(LEVEL_ABBR_MAP.get(level).unwrap_or(&level).to_string()),
            computername: CompactString::from(
                record_info.record["Event"]["System"]["Computer"]
                    .to_string()
                    .replace('\"', ""),
            ),
            eventid: eid,
            detail: CompactString::default(),
            ext_field: stored_static.profiles.as_ref().unwrap().to_owned(),
            is_condition: false,
        };
        message::insert(
            &record_info.record,
            CompactString::new(details_fmt_str),
            detect_info,
            time,
            &mut profile_converter,
            false,
            eventkey_alias,
        );
    }

    /// insert aggregation condition detection message to output stack
    fn insert_agg_message(rule: &RuleNode, agg_result: AggResult, stored_static: &StoredStatic) {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let output = Detection::create_count_output(rule, &agg_result);

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let level = rule.yaml["level"].as_str().unwrap_or("-");
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();

        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(CompactString::from(format_time(
                            &agg_result.start_timedate,
                            false,
                            stored_static.output_option.as_ref().unwrap(),
                        ))),
                    );
                }
                Computer(_) => {
                    profile_converter.insert(key.as_str(), Computer(CompactString::from("-")));
                }
                Channel(_) => {
                    profile_converter.insert(key.as_str(), Channel(CompactString::from("-")));
                }
                Level(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Level(CompactString::from(
                            LEVEL_ABBR_MAP.get(level).unwrap_or(&level).to_string(),
                        )),
                    );
                }
                EventID(_) => {
                    profile_converter.insert(key.as_str(), EventID(CompactString::from("-")));
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID(CompactString::from("")));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(CompactString::from(
                            rule.yaml["title"].as_str().unwrap_or(""),
                        )),
                    );
                }
                RuleFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleFile(CompactString::from(
                            Path::new(&rule.rulepath)
                                .file_name()
                                .unwrap_or_default()
                                .to_str()
                                .unwrap_or_default(),
                        )),
                    );
                }
                EvtxFile(_) => {
                    profile_converter.insert(key.as_str(), EvtxFile(CompactString::from("-")));
                }
                MitreTactics(_) => {
                    let tactics = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| tags_config_values.contains(&&CompactString::from(*x)))
                            .join(" ¦ "),
                    );
                    profile_converter.insert(key.as_str(), MitreTactics(tactics));
                }
                MitreTags(_) => {
                    let techniques = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| {
                                !tags_config_values.contains(&&CompactString::from(*x))
                                    && (x.starts_with("attack.t")
                                        || x.starts_with("attack.g")
                                        || x.starts_with("attack.s"))
                            })
                            .map(|y| {
                                let replaced_tag = y.replace("attack.", "");
                                make_ascii_titlecase(&replaced_tag)
                            })
                            .join(" ¦ "),
                    );
                    profile_converter.insert(key.as_str(), MitreTags(techniques));
                }
                OtherTags(_) => {
                    let tags = CompactString::from(
                        &tag_info
                            .iter()
                            .filter(|x| {
                                !(tags_config_values.contains(&&CompactString::from(*x))
                                    || x.starts_with("attack.t")
                                    || x.starts_with("attack.g")
                                    || x.starts_with("attack.s"))
                            })
                            .join(" ¦ "),
                    );
                    profile_converter.insert(key.as_str(), OtherTags(tags));
                }
                RuleAuthor(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleAuthor(CompactString::from(
                            rule.yaml["author"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(CompactString::from(
                            rule.yaml["date"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(CompactString::from(
                            rule.yaml["modified"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(CompactString::from(
                            rule.yaml["status"].as_str().unwrap_or("-"),
                        )),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(CompactString::from(rule.yaml["id"].as_str().unwrap_or("-"))),
                    );
                }
                Provider(_) => {
                    profile_converter.insert(key.as_str(), Provider(CompactString::from("-")));
                }
                RenderedMessage(_) => {
                    profile_converter
                        .insert(key.as_str(), RenderedMessage(CompactString::from("-")));
                }
                TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    profile_converter.insert("TgtASN", TgtASN("-".into()));
                    profile_converter.insert("TgtCountry", TgtCountry("-".into()));
                    profile_converter.insert("TgtCity", TgtCity("-".into()));
                }
                SrcASN(_) | SrcCountry(_) | SrcCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    profile_converter.insert("SrcASN", SrcASN("-".into()));
                    profile_converter.insert("SrcCountry", SrcCountry("-".into()));
                    profile_converter.insert("SrcCity", SrcCity("-".into()));
                }
                _ => {}
            }
        }

        let detect_info = DetectInfo {
            rulepath: CompactString::from(&rule.rulepath),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            level: CompactString::from(*LEVEL_ABBR_MAP.get(level).unwrap_or(&level)),
            computername: CompactString::from("-"),
            eventid: CompactString::from("-"),
            detail: output,
            ext_field: stored_static.profiles.as_ref().unwrap().to_owned(),
            is_condition: true,
        };
        let binding = STORED_EKEY_ALIAS.read().unwrap();
        let eventkey_alias = binding.as_ref().unwrap();
        message::insert(
            &Value::default(),
            CompactString::new(rule.yaml["details"].as_str().unwrap_or("-")),
            detect_info,
            agg_result.start_timedate,
            &mut profile_converter,
            true,
            eventkey_alias,
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
                        if let Some(tag) = TAGS_CONFIG.get(info.as_str().unwrap_or_default()) {
                            tag.to_owned()
                        } else {
                            CompactString::from(info.as_str().unwrap_or_default())
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
                            _ => CompactString::from(info.as_str().unwrap_or("")),
                        }
                    }),
            ),
        }
    }

    ///aggregation conditionのcount部分の検知出力文の文字列を返す関数
    fn create_count_output(rule: &RuleNode, agg_result: &AggResult) -> CompactString {
        // 条件式部分の出力
        let mut ret: String = "[condition] ".to_string();
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでunwrap前の確認は行わない
        let agg_condition = rule.get_agg_condition().unwrap();
        let exist_timeframe = rule.yaml["detection"]["timeframe"].as_str().unwrap_or("") != "";
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでagg_conditionの配列の長さは2となる
        ret.push_str(
            rule.yaml["detection"]["condition"]
                .as_str()
                .unwrap()
                .split('|')
                .nth(1)
                .unwrap_or_default()
                .trim(),
        );
        if exist_timeframe {
            ret.push_str(" in timeframe");
        }

        write!(ret, " [result] count:{}", agg_result.data).ok();
        if agg_condition._field_name.is_some() {
            write!(
                ret,
                " {}:{}",
                agg_condition._field_name.as_ref().unwrap(),
                agg_result.field_values.join("/")
            )
            .ok();
        }

        if agg_condition._by_field_name.is_some() {
            write!(
                ret,
                " {}:{}",
                agg_condition._by_field_name.as_ref().unwrap(),
                agg_result.key
            )
            .ok();
        }

        if exist_timeframe {
            write!(
                ret,
                " timeframe:{}",
                rule.yaml["detection"]["timeframe"].as_str().unwrap()
            )
            .ok();
        }

        CompactString::from(ret)
    }

    pub fn print_rule_load_info(
        rc: &HashMap<String, u128>,
        ld_rc: &HashMap<String, u128>,
        st_rc: &HashMap<String, u128>,
        err_rc: &u128,
        stored_static: &StoredStatic,
    ) {
        if stored_static.metrics_flag {
            return;
        }
        let mut sorted_ld_rc: Vec<(&String, &u128)> = ld_rc.iter().collect();
        sorted_ld_rc.sort_by(|a, b| a.0.cmp(b.0));
        let mut html_report_stock = Nested::<String>::new();

        sorted_ld_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let disable_flag = if key == "noisy"
                    && !stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .enable_noisy_rules
                {
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
                println!("{output_str}");
                if stored_static.html_report_flag {
                    html_report_stock.push(format!("- {output_str}"));
                }
            }
        });
        if err_rc != &0_u128 {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                Some(Color::Red),
                &format!("Rule parsing errors: {err_rc}"),
                true,
            )
            .ok();
        }
        println!();

        let mut sorted_st_rc: Vec<(&String, &u128)> = st_rc.iter().collect();
        let total_loaded_rule_cnt: u128 = sorted_st_rc.iter().map(|(_, v)| *v).sum();
        sorted_st_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_st_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let rate = (*value as f64) / (total_loaded_rule_cnt as f64) * 100.0;
                let deprecated_flag = if key == "deprecated"
                    && !stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .enable_deprecated_rules
                {
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
                if stored_static.html_report_flag {
                    html_report_stock.push(format!("- {output_str}"));
                }
            }
        });
        println!();

        let mut sorted_rc: Vec<(&String, &u128)> = rc.iter().collect();
        sorted_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_rc.into_iter().for_each(|(key, value)| {
            let output_str = format!("{key} rules: {value}");
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                &output_str,
                true,
            )
            .ok();
            if stored_static.html_report_flag {
                html_report_stock.push(format!("- {output_str}"));
            }
        });

        let tmp_total_detect_output =
            format!("Total enabled detection rules: {total_loaded_rule_cnt}");
        println!("{tmp_total_detect_output}");
        println!();
        println!("Scanning in progress. Please wait.");
        println!();
        if stored_static.html_report_flag {
            html_report_stock.push(format!("- {tmp_total_detect_output}"));
        }
        if !html_report_stock.is_empty() {
            htmlreport::add_md_data("General Overview {#general_overview}", html_report_stock);
        }
    }

    /// Retrieve the value of a given alias in a record.
    fn get_alias_data(
        target_alias: Vec<&str>,
        record: &Value,
        eventkey_alias: &EventKeyAliasConfig,
    ) -> CompactString {
        for alias in target_alias {
            let search_data =
                message::parse_message(record, CompactString::from(alias), eventkey_alias);
            if search_data != "n/a" {
                return search_data;
            }
        }
        CompactString::from("-")
    }
}

#[cfg(test)]
mod tests {
    use crate::detections;
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::configs::Action;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::InputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::STORED_EKEY_ALIAS;
    use crate::detections::detection::Detection;
    use crate::detections::message;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::AggResult;
    use crate::detections::rule::RuleNode;
    use crate::detections::utils;
    use crate::filter;
    use crate::options::profile::Profile;
    use chrono::TimeZone;
    use chrono::Utc;
    use compact_str::CompactString;
    use serde_json::Value;
    use std::path::Path;
    use yaml_rust::Yaml;
    use yaml_rust::YamlLoader;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                    },
                    profile: None,
                    output: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                },
                json_input: false,
                geo_ip: None,
            })),
            no_color: false,
            quiet: false,
            debug: false,
        }))
    }

    #[test]
    fn test_parse_rule_files() {
        let level = "informational";
        let opt_rule_path = Path::new("./test_files/rules/level_yaml");
        let dummy_stored_static = create_dummy_stored_static();
        let cole = Detection::parse_rule_files(
            level,
            opt_rule_path,
            &filter::exclude_ids(&dummy_stored_static),
            &dummy_stored_static,
        );
        assert_eq!(5, cole.len());
    }

    #[test]
    fn test_output_aggregation_output_with_output() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "[condition] count() >= 1 [result] count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_no_filed_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "[condition] count() >= 1 [result] count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_timeframe() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output =
            "[condition] count() >= 1 in timeframe [result] count:2 timeframe:15m";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "[condition] count(EventID) >= 1 [result] count:2 EventID:7040/9999";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_field_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output = "[condition] count(EventID) by process >= 1 [result] count:2 EventID:0000/1111 process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }
    #[test]
    fn test_output_aggregation_output_with_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
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
        rule_node.init(&create_dummy_stored_static()).ok();
        let expected_output =
            "[condition] count() by process >= 1 [result] count:2 process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_insert_message_with_geoip() {
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let expect_time = Utc
            .datetime_from_str("1996-02-27T01:05:01Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                profile: None,
                output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: true,
            },
            json_input: false,
            geo_ip: Some(Path::new("test_files/mmdb").to_path_buf()),
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            no_color: false,
            quiet: false,
            debug: false,
        });
        let stored_static = StoredStatic::create_static_data(dummy_config);
        {
            let eventkey_alias = load_eventkey_alias(
                utils::check_setting_path(
                    &CURRENT_EXE_PATH.to_path_buf(),
                    "rules/config/eventkey_alias.txt",
                    true,
                )
                .unwrap()
                .to_str()
                .unwrap(),
            );
            *STORED_EKEY_ALIAS.write().unwrap() = Some(eventkey_alias);

            let messages = &message::MESSAGES;
            messages.clear();
            let val = r##"
            {
                "Event": {
                    "EventData": {
                        "CommandRLine": "hoge",
                        "IpAddress": "89.160.20.128",
                        "DestAddress": "2.125.160.216"
                    },
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "1996-02-27T01:05:01Z"
                        },
                        "EventRecordID": "11111",
                        "Channel": "Security"
                    }
                }
            }
        "##;
            let event: Value = serde_json::from_str(val).unwrap();
            let dummy_rule = RuleNode::new(test_rulepath.to_string(), Yaml::from_str(""));
            let keys = detections::rule::get_detection_keys(&dummy_rule);

            let input_evtxrecord = utils::create_rec_info(event, test_filepath.to_owned(), &keys);
            Detection::insert_message(&dummy_rule, &input_evtxrecord, &stored_static);
            let multi = message::MESSAGES.get(&expect_time).unwrap();
            let (_, detect_infos) = multi.pair();
            assert!(detect_infos.len() == 1);
            let expect_geo_ip_data: Vec<(CompactString, Profile)> = vec![
                ("SrcASN".into(), Profile::SrcASN("Bredband2 AB".into())),
                ("SrcCountry".into(), Profile::SrcCountry("Sweden".into())),
                ("SrcCity".into(), Profile::SrcCity("Linköping".into())),
                ("TgtASN".into(), Profile::TgtASN("-".into())),
                (
                    "TgtCountry".into(),
                    Profile::TgtCountry("United Kingdom".into()),
                ),
                ("TgtCity".into(), Profile::TgtCity("Boxford".into())),
            ];
            let ext_field = detect_infos[0].ext_field.clone();
            for expect in expect_geo_ip_data.iter() {
                assert!(ext_field.contains(expect));
            }
        }
    }

    #[test]
    fn test_create_fields_value() {}
}

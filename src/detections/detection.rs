extern crate csv;

use std::collections::HashSet;
use std::default::Default;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use compact_str::CompactString;
use hashbrown::HashMap;
use itertools::Itertools;
use nested::Nested;
use num_format::{Locale, ToFormattedString};
use serde_json::Value;
use termcolor::{BufferWriter, Color, ColorChoice};
use tokio::{runtime::Runtime, spawn, task::JoinHandle};
use yaml_rust::Yaml;

use crate::detections::configs::Action;
use crate::detections::configs::STORED_EKEY_ALIAS;
use crate::detections::field_data_map::FieldDataMapKey;
use crate::detections::message::{AlertMessage, DetectInfo, ERROR_LOG_STACK, TAGS_CONFIG};
use crate::detections::rule::correlation_parser::parse_correlation_rules;
use crate::detections::rule::{self, AggResult, RuleNode};
use crate::detections::utils::{create_recordinfos, format_time, write_color_buffer};
use crate::detections::utils::{get_serde_number_to_string, make_ascii_titlecase};
use crate::filter;
use crate::options::htmlreport;
use crate::options::pivot::insert_pivot_keyword;
use crate::options::profile::Profile::{
    self, Channel, Computer, EventID, EvtxFile, Level, MitreTactics, MitreTags, OtherTags,
    Provider, RecordID, RecoveredRecord, RenderedMessage, RuleAuthor, RuleCreationDate, RuleFile,
    RuleID, RuleModifiedDate, RuleTitle, SrcASN, SrcCity, SrcCountry, Status, TgtASN, TgtCity,
    TgtCountry, Timestamp,
};
use crate::yaml::ParseYaml;

use super::configs::{
    EventKeyAliasConfig, StoredStatic, GEOIP_DB_PARSER, GEOIP_DB_YAML, GEOIP_FILTER, STORED_STATIC,
};
use super::message::{self, COMPUTER_MITRE_ATTCK_MAP, LEVEL_ABBR_MAP};

// イベントファイルの1レコード分の情報を保持する構造体
#[derive(Clone, Debug)]
pub struct EvtxRecordInfo {
    pub evtx_filepath: String, // イベントファイルのファイルパス ログで出力するときに使う
    pub record: Value,         // 1レコード分のデータをJSON形式にシリアライズしたもの
    pub data_string: String,   //1レコード内のデータを文字列にしたもの
    pub key_2_value: HashMap<String, String>, // 階層化されたキーを.でつないだデータとその値のマップ
    pub recovered_record: bool, // レコードが復元されたかどうか
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

    pub fn start(self, rt: &Runtime, records: Vec<EvtxRecordInfo>) -> (Self, Vec<DetectInfo>) {
        rt.block_on(self.execute_rules(records))
    }

    // ルールファイルをパースします。
    pub fn parse_rule_files(
        min_level: &str,
        target_level: &str,
        rulespath: &Path,
        exclude_ids: &filter::RuleExclude,
        stored_static: &StoredStatic,
    ) -> Vec<RuleNode> {
        // ルールファイルのパースを実行
        let mut rulefile_loader = ParseYaml::new(stored_static);
        let result_readdir = rulefile_loader.read_dir(
            rulespath,
            min_level,
            target_level,
            exclude_ids,
            stored_static,
        );
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
        let mut ret = rulefile_loader
            .files
            .into_iter()
            .map(|rule_file_tuple| rule::create_rule(rule_file_tuple.0, rule_file_tuple.1))
            .filter_map(return_if_success)
            .collect();
        ret = parse_correlation_rules(ret, stored_static, &mut parseerror_count);
        if !(stored_static.logon_summary_flag
            || stored_static.search_flag
            || stored_static.metrics_flag
            || stored_static.computer_metrics_flag)
        {
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
    async fn execute_rules(mut self, records: Vec<EvtxRecordInfo>) -> (Self, Vec<DetectInfo>) {
        let records_arc = Arc::new(records);
        // // 各rule毎にスレッドを作成して、スレッドを起動する。
        let rules = self.rules;
        let handles: Vec<JoinHandle<(RuleNode, Vec<DetectInfo>)>> = rules
            .into_iter()
            .map(|rule| {
                let records_cloned = Arc::clone(&records_arc);
                spawn(async move { Detection::execute_rule(rule, records_cloned) })
            })
            .collect();

        // 全スレッドの実行完了を待機
        let mut rules = vec![];
        let mut all_log_records = vec![];
        for handle in handles {
            let (ret_rule, log_records) = handle.await.unwrap();
            rules.push(ret_rule);
            for log_record in log_records {
                all_log_records.push(log_record);
            }
        }

        // この関数の先頭でrules.into_iter()を呼び出している。それにより所有権がmapのruleを経由し、execute_ruleの引数に渡しているruleに移っているので、self.rulesには所有権が無くなっている。
        // 所有権を失ったメンバー変数を持つオブジェクトをreturnするコードを書くと、コンパイラが怒になるので(E0382という番号のコンパイルエラー)、ここでself.rulesに所有権を戻している。
        // self.rulesが再度所有権を取り戻せるように、Detection::execute_ruleで引数に渡したruleを戻り値として返すようにしている。
        self.rules = rules;

        (self, all_log_records)
    }

    pub fn add_aggcondition_msges(
        self,
        rt: &Runtime,
        stored_static: &StoredStatic,
    ) -> Vec<DetectInfo> {
        return rt.block_on(self.add_aggcondition_msg(stored_static));
    }

    async fn add_aggcondition_msg(&self, stored_static: &StoredStatic) -> Vec<DetectInfo> {
        let mut ret = vec![];
        for rule in &self.rules {
            if !rule.has_agg_condition() {
                continue;
            }

            for value in rule.judge_satisfy_aggcondition(stored_static) {
                ret.push(Detection::create_agg_log_record(rule, value, stored_static));
            }
        }

        ret
    }

    // 複数のイベントレコードに対して、ルールを1個実行します。
    fn execute_rule(
        mut rule: RuleNode,
        records: Arc<Vec<EvtxRecordInfo>>,
    ) -> (RuleNode, Vec<DetectInfo>) {
        let agg_condition = rule.has_agg_condition();
        let binding = STORED_STATIC.read().unwrap();
        let stored_static = binding.as_ref().unwrap();
        let mut ret = vec![];
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
                ret.push(Detection::create_log_record(
                    &rule,
                    record_info,
                    stored_static,
                ));
            }
        }

        (rule, ret)
    }

    /// create log record
    fn create_log_record(
        rule: &RuleNode,
        record_info: &EvtxRecordInfo,
        stored_static: &StoredStatic,
    ) -> DetectInfo {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let rec_id = if stored_static
            .profiles
            .as_ref()
            .unwrap()
            .iter()
            .any(|(_s, p)| *p == RecordID(Default::default()))
        {
            get_serde_number_to_string(
                &record_info.record["Event"]["System"]["EventRecordID"],
                false,
            )
            .unwrap_or_default()
        } else {
            CompactString::from("")
        };
        let ch_str =
            &get_serde_number_to_string(&record_info.record["Event"]["System"]["Channel"], false)
                .unwrap_or_default();
        let provider = get_serde_number_to_string(
            &record_info.record["Event"]["System"]["Provider_attributes"]["Name"],
            false,
        )
        .unwrap_or_default()
        .replace('\'', "");
        let eid =
            get_serde_number_to_string(&record_info.record["Event"]["System"]["EventID"], false)
                .unwrap_or_else(|| "-".into());
        let recovered_record = if record_info.recovered_record {
            "Y"
        } else {
            ""
        };

        let default_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let time = message::get_event_time(&record_info.record, stored_static.json_input_flag)
            .unwrap_or(default_time);
        let level = rule.yaml["level"].as_str().unwrap_or("-").to_string();

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();
        let binding = STORED_EKEY_ALIAS.read().unwrap();
        let eventkey_alias = binding.as_ref().unwrap();
        let is_json_timeline = matches!(stored_static.config.action, Some(Action::JsonTimeline(_)));

        let mut computer_name_to_mitre_tactics = CompactString::default();
        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(
                            format_time(
                                &time,
                                false,
                                stored_static.output_option.as_ref().unwrap(),
                            )
                            .into(),
                        ),
                    );
                }
                Computer(_) => {
                    let computer_name = CompactString::from(
                        record_info.record["Event"]["System"]["Computer"]
                            .as_str()
                            .unwrap_or_default()
                            .replace('\"', ""),
                    );
                    if stored_static.html_report_flag {
                        computer_name_to_mitre_tactics = computer_name.clone();
                    }
                    profile_converter.insert(key.as_str(), Computer(computer_name.into()));
                }
                Channel(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Channel(
                            stored_static
                                .disp_abbr_generic
                                .replace_all(
                                    stored_static
                                        .ch_config
                                        .get(&CompactString::from(ch_str.to_ascii_lowercase()))
                                        .unwrap_or(ch_str)
                                        .as_str(),
                                    &stored_static.disp_abbr_general_values,
                                )
                                .into(),
                        ),
                    );
                }
                Level(_) => {
                    let str_level = level.as_str();
                    let abbr_level = LEVEL_ABBR_MAP.get(str_level).unwrap_or(&str_level);
                    let prof_level = if stored_static.output_path.is_none() {
                        abbr_level
                    } else {
                        abbr_level.trim()
                    };
                    profile_converter.insert(key.as_str(), Level(prof_level.to_string().into()));
                }
                EventID(_) => {
                    profile_converter.insert(key.as_str(), EventID(eid.to_string().into()));
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID(rec_id.to_string().into()));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(
                            rule.yaml["title"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string()
                                .into(),
                        ),
                    );
                }
                RuleFile(_) => {
                    let rule_file_path = CompactString::from(
                        Path::new(&rule.rulepath)
                            .file_name()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or_default(),
                    );
                    profile_converter.insert(key.as_str(), RuleFile(rule_file_path.into()));
                }
                EvtxFile(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EvtxFile(
                            Path::new(&record_info.evtx_filepath)
                                .display()
                                .to_string()
                                .into(),
                        ),
                    );
                }
                MitreTactics(_) => {
                    let tactics = tag_info
                        .iter()
                        .filter(|x| tags_config_values.contains(&&CompactString::from(*x)));
                    // .map(|x| TAGS_CONFIG.get(x.into()).unwrap());
                    let output_tactics_str = CompactString::from(
                        tactics
                            .clone()
                            .filter_map(|x| x.split(',').next())
                            .join(" ¦ "),
                    );

                    profile_converter.insert(
                        key.as_str(),
                        MitreTactics(output_tactics_str.clone().into()),
                    );

                    let html_output_tactics_str = tactics
                        .into_iter()
                        .map(|x| x.split(',').nth(1).unwrap_or_default())
                        .collect_vec();
                    if stored_static.html_report_flag && !html_output_tactics_str.is_empty() {
                        let mut v = COMPUTER_MITRE_ATTCK_MAP
                            .entry(computer_name_to_mitre_tactics.clone())
                            .or_default();
                        let (_, attck_tac) = v.pair_mut();
                        for html_attck_tac in html_output_tactics_str {
                            if !attck_tac.contains(&html_attck_tac.into()) {
                                attck_tac.push(html_attck_tac.into());
                                attck_tac.sort_unstable();
                            }
                        }
                    }
                    // profile_converter.insert(key.as_str(), MitreTactics(output_tactics_str.into()));
                }
                MitreTags(_) => {
                    let techniques = tag_info
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
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), MitreTags(techniques.into()));
                }
                OtherTags(_) => {
                    let tags = tag_info
                        .iter()
                        .filter(|x| {
                            !(TAGS_CONFIG.values().contains(&CompactString::from(*x))
                                || x.starts_with("attack.t")
                                || x.starts_with("attack.g")
                                || x.starts_with("attack.s"))
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), OtherTags(tags.into()));
                }
                RuleAuthor(_) => {
                    let author = if stored_static.multiline_flag {
                        rule.yaml["author"]
                            .as_str()
                            .unwrap_or("-")
                            .split([',', '/', ';'])
                            .map(|x| x.trim())
                            .join("🛂🛂")
                    } else {
                        rule.yaml["author"].as_str().unwrap_or("-").to_string()
                    };
                    profile_converter.insert(key.as_str(), RuleAuthor(author.into()));
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(
                            rule.yaml["date"].as_str().unwrap_or("-").to_string().into(),
                        ),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(
                            rule.yaml["modified"]
                                .as_str()
                                .unwrap_or("-")
                                .to_string()
                                .into(),
                        ),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(
                            rule.yaml["status"]
                                .as_str()
                                .unwrap_or("-")
                                .to_string()
                                .into(),
                        ),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(rule.yaml["id"].as_str().unwrap_or("-").to_string().into()),
                    );
                }
                Provider(_) => {
                    let provider_value = CompactString::from(
                        record_info.record["Event"]["System"]["Provider_attributes"]["Name"]
                            .to_string()
                            .replace('\"', ""),
                    );
                    profile_converter.insert(
                        key.as_str(),
                        Provider(
                            stored_static
                                .disp_abbr_generic
                                .replace_all(
                                    stored_static
                                        .provider_abbr_config
                                        .get(&provider_value)
                                        .unwrap_or(&provider_value),
                                    &stored_static.disp_abbr_general_values,
                                )
                                .into(),
                        ),
                    );
                }
                RecoveredRecord(_) => {
                    profile_converter
                        .insert("RecoveredRecord", RecoveredRecord(recovered_record.into()));
                }
                RenderedMessage(_) => {
                    let convert_value = if let Some(message) =
                        record_info.record["Event"]["RenderingInfo"]["Message"].as_str()
                    {
                        message
                            .replace('\t', "\\t")
                            .split("\r\n")
                            .map(|x| x.trim())
                            .join("\\r\\n")
                    } else {
                        "n/a".into()
                    };
                    profile_converter.insert(key.as_str(), RenderedMessage(convert_value.into()));
                }
                TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // initialize GeoIP Tgt associated fields
                    profile_converter.insert("TgtASN", TgtASN("-".into()));
                    profile_converter.insert("TgtCountry", TgtCountry("-".into()));
                    profile_converter.insert("TgtCity", TgtCity("-".into()));
                    let binding = GEOIP_DB_YAML.read().unwrap();
                    let geo_ip_mapping = binding.as_ref().unwrap();
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping.get("TgtIP");
                    if target_alias.is_none() {
                        continue;
                    }
                    let binding = GEOIP_FILTER.read().unwrap();
                    let target_condition = binding.as_ref().unwrap();
                    let mut geoip_target_flag = false;
                    for condition in target_condition.iter() {
                        geoip_target_flag = condition.as_hash().unwrap().iter().any(
                            |(target_channel, target_eids)| {
                                ch_str.as_str() == target_channel.as_str().unwrap()
                                    && target_eids
                                        .as_vec()
                                        .unwrap()
                                        .contains(&Yaml::from_str(eid.as_str()))
                            },
                        );
                        if geoip_target_flag {
                            break;
                        }
                    }
                    if !geoip_target_flag {
                        continue;
                    }
                    let alias_data = Self::get_alias_data(
                        target_alias
                            .unwrap()
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                        is_json_timeline,
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
                        .and_modify(|p| *p = TgtASN(tgt_data.next().unwrap().to_owned().into()));
                    profile_converter.entry("TgtCountry").and_modify(|p| {
                        *p = TgtCountry(tgt_data.next().unwrap().to_owned().into())
                    });
                    profile_converter
                        .entry("TgtCity")
                        .and_modify(|p| *p = TgtCity(tgt_data.next().unwrap().to_owned().into()));
                }
                SrcASN(_) | SrcCountry(_) | SrcCity(_) => {
                    if profile_converter.contains_key(key.as_str()) {
                        continue;
                    }
                    // initialize GeoIP Tgt associated fields
                    profile_converter.insert("SrcASN", SrcASN("-".into()));
                    profile_converter.insert("SrcCountry", SrcCountry("-".into()));
                    profile_converter.insert("SrcCity", SrcCity("-".into()));
                    let binding = GEOIP_DB_YAML.read().unwrap();
                    let geo_ip_mapping = binding.as_ref().unwrap();
                    if geo_ip_mapping.is_empty() {
                        continue;
                    }
                    let target_alias = &geo_ip_mapping.get("SrcIP");
                    if target_alias.is_none() || GEOIP_FILTER.read().unwrap().is_none() {
                        continue;
                    }

                    let binding = GEOIP_FILTER.read().unwrap();
                    let target_condition = binding.as_ref().unwrap();
                    let mut geoip_target_flag = false;
                    for condition in target_condition.iter() {
                        geoip_target_flag = condition.as_hash().unwrap().iter().any(
                            |(target_channel, target_eids)| {
                                ch_str.as_str() == target_channel.as_str().unwrap()
                                    && target_eids
                                        .as_vec()
                                        .unwrap()
                                        .contains(&Yaml::from_str(eid.as_str()))
                            },
                        );
                        if geoip_target_flag {
                            break;
                        }
                    }
                    if !geoip_target_flag {
                        continue;
                    }

                    let alias_data = Self::get_alias_data(
                        target_alias
                            .unwrap()
                            .as_vec()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect(),
                        &record_info.record,
                        eventkey_alias,
                        is_json_timeline,
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
                        .and_modify(|p| *p = SrcASN(src_data.next().unwrap().to_owned().into()));
                    profile_converter.entry("SrcCountry").and_modify(|p| {
                        *p = SrcCountry(src_data.next().unwrap().to_owned().into())
                    });
                    profile_converter
                        .entry("SrcCity")
                        .and_modify(|p| *p = SrcCity(src_data.next().unwrap().to_owned().into()));
                }
                _ => {}
            }
        }
        //ルール側にdetailsの項目があればそれをそのまま出力し、そうでない場合はproviderとeventidの組で設定したdetailsの項目を出力する
        let details_fmt_str = match rule.yaml["details"].as_str() {
            Some(s) => s.to_string(),
            None => match stored_static
                .default_details
                .get(&CompactString::from(format!("{provider}_{eid}")))
            {
                Some(str) => str.to_string(),
                None => create_recordinfos(&record_info.record, &FieldDataMapKey::default(), &None)
                    .join(" ¦ "),
            },
        };
        let field_data_map_key: FieldDataMapKey = if stored_static.field_data_map.is_none() {
            FieldDataMapKey::default()
        } else {
            FieldDataMapKey {
                channel: CompactString::from(ch_str.clone().to_lowercase()),
                event_id: eid.clone(),
            }
        };
        let detect_info = DetectInfo {
            detected_time: time,
            rulepath: CompactString::from(&rule.rulepath),
            ruleid: CompactString::from(rule.yaml["id"].as_str().unwrap_or("-")),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            level: CompactString::from(
                LEVEL_ABBR_MAP
                    .get(&level.as_str())
                    .unwrap_or(&level.as_str())
                    .to_string(),
            ),
            computername: CompactString::from(
                record_info.record["Event"]["System"]["Computer"]
                    .as_str()
                    .unwrap_or_default()
                    .replace('\"', ""),
            ),
            eventid: eid,
            detail: CompactString::default(),
            ext_field: stored_static.profiles.as_ref().unwrap().to_owned(),
            agg_result: None,
            details_convert_map: HashMap::default(),
        };

        message::create_message(
            &record_info.record,
            CompactString::new(details_fmt_str),
            detect_info,
            &profile_converter,
            (false, is_json_timeline),
            (
                eventkey_alias,
                &field_data_map_key,
                &stored_static.field_data_map,
            ),
        )
    }

    fn create_agg_log_record(
        rule: &RuleNode,
        agg_result: AggResult,
        stored_static: &StoredStatic,
    ) -> DetectInfo {
        let tag_info: &Nested<String> = &Detection::get_tag_info(rule);
        let output = Detection::create_count_output(rule, &agg_result);

        let mut profile_converter: HashMap<&str, Profile> = HashMap::new();
        let level = rule.yaml["level"].as_str().unwrap_or("-").to_string();
        let tags_config_values: Vec<&CompactString> = TAGS_CONFIG.values().collect();
        let is_json_timeline = matches!(stored_static.config.action, Some(Action::JsonTimeline(_)));
        for (key, profile) in stored_static.profiles.as_ref().unwrap().iter() {
            match profile {
                Timestamp(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Timestamp(
                            format_time(
                                &agg_result.start_timedate,
                                false,
                                stored_static.output_option.as_ref().unwrap(),
                            )
                            .into(),
                        ),
                    );
                }
                Computer(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Computer(
                            agg_result
                                .agg_record_time_info
                                .iter()
                                .map(|x| x.computer.clone())
                                .collect::<HashSet<_>>() // HashSetに変換して重複を削除
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" ¦ ")
                                .into(),
                        ),
                    );
                }
                Channel(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Channel(
                            agg_result
                                .agg_record_time_info
                                .iter()
                                .map(|x| x.channel.clone())
                                .collect::<HashSet<_>>() // HashSetに変換して重複を削除
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" ¦ ")
                                .into(),
                        ),
                    );
                }
                Level(_) => {
                    let str_level = level.as_str();
                    let abbr_level = LEVEL_ABBR_MAP.get(str_level).unwrap_or(&str_level);
                    let prof_level = if stored_static.output_path.is_none() {
                        abbr_level
                    } else {
                        abbr_level.trim()
                    };
                    profile_converter.insert(key.as_str(), Level(prof_level.to_string().into()));
                }
                EventID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        EventID(
                            agg_result
                                .agg_record_time_info
                                .iter()
                                .map(|x| x.event_id.clone())
                                .collect::<HashSet<_>>() // HashSetに変換して重複を削除
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" ¦ ")
                                .into(),
                        ),
                    );
                }
                RecordID(_) => {
                    profile_converter.insert(key.as_str(), RecordID("-".into()));
                }
                RuleTitle(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleTitle(
                            rule.yaml["title"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                RuleFile(_) => {
                    let rule_path = Path::new(&rule.rulepath)
                        .file_name()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default()
                        .to_string();

                    profile_converter.insert(key.as_str(), RuleFile(rule_path.into()));
                }
                EvtxFile(_) => {
                    profile_converter.insert(key.as_str(), EvtxFile("-".into()));
                }
                MitreTactics(_) => {
                    let tactics = tag_info
                        .iter()
                        .filter(|x| tags_config_values.contains(&&CompactString::from(*x)))
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), MitreTactics(tactics.into()));
                }
                MitreTags(_) => {
                    let techniques = tag_info
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
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), MitreTags(techniques.into()));
                }
                OtherTags(_) => {
                    let tags = tag_info
                        .iter()
                        .filter(|x| {
                            !(tags_config_values.contains(&&CompactString::from(*x))
                                || x.starts_with("attack.t")
                                || x.starts_with("attack.g")
                                || x.starts_with("attack.s"))
                        })
                        .join(" ¦ ");
                    profile_converter.insert(key.as_str(), OtherTags(tags.into()));
                }
                RuleAuthor(_) => {
                    let author = if stored_static.multiline_flag {
                        rule.yaml["author"]
                            .as_str()
                            .unwrap_or("-")
                            .split([',', '/', ';'])
                            .map(|x| x.trim())
                            .join("🛂🛂")
                    } else {
                        rule.yaml["author"].as_str().unwrap_or("-").to_string()
                    };
                    profile_converter.insert(key.as_str(), RuleAuthor(author.into()));
                }
                RuleCreationDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleCreationDate(
                            rule.yaml["date"].as_str().unwrap_or("-").to_owned().into(),
                        ),
                    );
                }
                RuleModifiedDate(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleModifiedDate(
                            rule.yaml["modified"]
                                .as_str()
                                .unwrap_or("-")
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                Status(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        Status(
                            rule.yaml["status"]
                                .as_str()
                                .unwrap_or("-")
                                .to_owned()
                                .into(),
                        ),
                    );
                }
                RuleID(_) => {
                    profile_converter.insert(
                        key.as_str(),
                        RuleID(rule.yaml["id"].as_str().unwrap_or("-").to_owned().into()),
                    );
                }
                Provider(_) => {
                    profile_converter.insert(key.as_str(), Provider("-".into()));
                }
                RecoveredRecord(_) => {
                    profile_converter.insert("RecoveredRecord", RenderedMessage("".into()));
                }
                RenderedMessage(_) => {
                    profile_converter.insert(key.as_str(), RenderedMessage("-".into()));
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
        let str_level = level.as_str();
        let detect_info = DetectInfo {
            detected_time: agg_result.start_timedate,
            rulepath: CompactString::from(&rule.rulepath),
            ruleid: CompactString::from(rule.yaml["id"].as_str().unwrap_or("-")),
            ruletitle: CompactString::from(rule.yaml["title"].as_str().unwrap_or("-")),
            level: CompactString::from(
                LEVEL_ABBR_MAP
                    .get(str_level)
                    .unwrap_or(&str_level)
                    .to_string(),
            ),
            computername: CompactString::from("-"),
            eventid: CompactString::from("-"),
            detail: output,
            ext_field: stored_static.profiles.as_ref().unwrap().to_owned(),
            agg_result: Some(agg_result),
            details_convert_map: HashMap::default(),
        };
        let binding = STORED_EKEY_ALIAS.read().unwrap();
        let eventkey_alias = binding.as_ref().unwrap();

        let field_data_map_key = FieldDataMapKey::default();

        let detect_info = message::create_message(
            &Value::default(),
            CompactString::from(detect_info.detail.as_str()),
            detect_info,
            &profile_converter,
            (true, is_json_timeline),
            (eventkey_alias, &field_data_map_key, &None),
        );
        detect_info
    }

    /// rule内のtagsの内容を配列として返却する関数
    fn get_tag_info(rule: &RuleNode) -> Nested<String> {
        Nested::from_iter(
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
        )
    }

    ///aggregation conditionのcount部分の検知出力文の文字列を返す関数
    fn create_count_output(rule: &RuleNode, agg_result: &AggResult) -> CompactString {
        let mut ret: String = "".to_string();
        // この関数が呼び出されている段階で既にaggregation conditionは存在する前提なのでagg_conditionの配列の長さは2となる
        let agg_condition = rule.get_agg_condition().unwrap();
        write!(ret, "Count:{}", agg_result.data).ok();
        if agg_condition._field_name.is_some() {
            write!(
                ret,
                " ¦ {}:{}",
                agg_condition._field_name.as_ref().unwrap(),
                agg_result.field_values.join("/")
            )
            .ok();
        }

        if agg_condition._by_field_name.is_some() {
            let field_name = agg_condition._by_field_name.as_ref().unwrap();
            if field_name.contains(',') {
                write!(
                    ret,
                    " ¦ {}",
                    Self::zip_and_concat_strings(field_name, &agg_result.key)
                )
                .ok();
            } else {
                write!(ret, " ¦ {}:{}", field_name, agg_result.key).ok();
            }
        }

        CompactString::from(ret)
    }

    fn zip_and_concat_strings(s1: &str, s2: &str) -> String {
        let v1: Vec<&str> = s1.split(',').collect();
        let v2: Vec<&str> = s2.split(',').collect();
        v1.into_iter()
            .zip(v2)
            .map(|(s1, s2)| format!("{}:{}", s1, s2))
            .collect::<Vec<String>>()
            .join(" ¦ ")
    }

    pub fn print_rule_load_info(
        rc: &HashMap<CompactString, u128>,
        ld_rc: &HashMap<CompactString, u128>,
        st_rc: &HashMap<CompactString, u128>,
        err_rc: &u128,
        stored_static: &StoredStatic,
    ) {
        let mut sorted_ld_rc: Vec<(&CompactString, &u128)> = ld_rc.iter().collect();
        sorted_ld_rc.sort_by(|a, b| a.0.cmp(b.0));
        let mut html_report_stock = Nested::<String>::new();

        sorted_ld_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let disable_flag = if key.as_str() == "noisy"
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
                    value.to_formatted_string(&Locale::en),
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

        let mut sorted_st_rc: Vec<(&CompactString, &u128)> = st_rc.iter().collect();
        let output_opt = stored_static.output_option.as_ref().unwrap();
        let enable_deprecated_flag = output_opt.enable_deprecated_rules;
        let enable_unsupported_flag = output_opt.enable_unsupported_rules;
        let is_filtered_rule_flag = |x: &CompactString| {
            x == &"deprecated" && !enable_deprecated_flag
                || x == &"unsupported" && !enable_unsupported_flag
        };
        let total_loaded_rule_cnt: u128 = sorted_st_rc
            .iter()
            .filter(|(k, _)| !is_filtered_rule_flag(k))
            .map(|(_, v)| *v)
            .sum();
        sorted_st_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_st_rc.into_iter().for_each(|(key, value)| {
            if value != &0_u128 {
                let rate = (*value as f64) / (total_loaded_rule_cnt as f64) * 100.0;
                let disabled_flag = if is_filtered_rule_flag(key) {
                    " (Disabled)"
                } else {
                    ""
                };
                let output_str = format!(
                    "{} rules: {} ({:.2}%){}",
                    make_ascii_titlecase(key),
                    value.to_formatted_string(&Locale::en),
                    rate,
                    disabled_flag
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

        let mut sorted_rc: Vec<(&CompactString, &u128)> = rc.iter().collect();
        sorted_rc.sort_by(|a, b| a.0.cmp(b.0));
        sorted_rc.into_iter().for_each(|(key, value)| {
            let output_str = format!("{key} rules: {}", value.to_formatted_string(&Locale::en));
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

        let tmp_total_detect_output = format!(
            "Total detection rules: {}",
            total_loaded_rule_cnt.to_formatted_string(&Locale::en)
        );
        println!("{tmp_total_detect_output}");
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
        is_csv_output: bool,
    ) -> CompactString {
        for alias in target_alias {
            let (search_data, _) = message::parse_message(
                record,
                &CompactString::from(alias),
                eventkey_alias,
                is_csv_output,
                &FieldDataMapKey::default(),
                &None,
            );
            if search_data != "n/a" {
                return search_data;
            }
        }
        CompactString::from("-")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::TimeZone;
    use chrono::Utc;
    use compact_str::CompactString;
    use serde_json::Value;
    use yaml_rust::Yaml;
    use yaml_rust::YamlLoader;

    use crate::detections;
    use crate::detections::configs::load_eventkey_alias;
    use crate::detections::configs::Action;
    use crate::detections::configs::CommonOptions;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::DetectCommonOption;
    use crate::detections::configs::InputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::CURRENT_EXE_PATH;
    use crate::detections::configs::STORED_EKEY_ALIAS;
    use crate::detections::detection::Detection;
    use crate::detections::rule::create_rule;
    use crate::detections::rule::AggResult;
    use crate::detections::rule::RuleNode;
    use crate::detections::utils;
    use crate::filter;
    use crate::options::profile::Profile;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        timeline_offset: None,
                    },
                    profile: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    exact_level: None,
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
                    common_options: CommonOptions {
                        no_color: false,
                        quiet: false,
                        help: None,
                    },
                    detect_common_options: DetectCommonOption {
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                        json_input: false,
                        include_computer: None,
                        exclude_computer: None,
                    },
                    enable_unsupported_rules: false,
                    clobber: false,
                    proven_rules: false,
                    include_tag: None,
                    exclude_tag: None,
                    include_category: None,
                    exclude_category: None,
                    include_eid: None,
                    exclude_eid: None,
                    no_field: false,
                    no_pwsh_field_extraction: false,
                    remove_duplicate_data: false,
                    remove_duplicate_detections: false,
                    no_wizard: true,
                    include_status: None,
                    sort_events: false,
                    enable_all_rules: false,
                    scan_all_evtx_files: false,
                },
                geo_ip: None,
                output: None,
                multiline: false,
            })),
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
            "",
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
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
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
        let expected_output = "Count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_no_filed_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
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
        let expected_output = "Count:2";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_output_aggregation_output_with_timeframe() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "_".to_string(), vec![], default_time, vec![]);
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
        let expected_output = "Count:2";
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
            vec![],
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
        let expected_output = "Count:2 ¦ EventID:7040/9999";
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
            vec![],
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
        let expected_output = "Count:2 ¦ EventID:0000/1111 ¦ process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }
    #[test]
    fn test_output_aggregation_output_with_by() {
        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let agg_result: AggResult =
            AggResult::new(2, "lsass.exe".to_string(), vec![], default_time, vec![]);
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
        let expected_output = "Count:2 ¦ process:lsass.exe";
        assert_eq!(
            Detection::create_count_output(&rule_node, &agg_result),
            expected_output
        );
    }

    #[test]
    fn test_insert_message_with_geoip() {
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
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
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                sort_events: false,
                enable_all_rules: false,
                scan_all_evtx_files: false,
            },
            geo_ip: Some(Path::new("test_files/mmdb").to_path_buf()),
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: false,
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
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

            let val = r#"
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
                        "Channel": "Security",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let dummy_rule = RuleNode::new(test_rulepath.to_string(), Yaml::from_str(""));
            let keys = detections::rule::get_detection_keys(&dummy_rule);

            let input_evtxrecord =
                utils::create_rec_info(event, test_filepath.to_owned(), &keys, &false, &false);
            {
                let rule = &dummy_rule;
                let record_info = &input_evtxrecord;
                let stored_static = &stored_static;
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

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
                let ext_field = detect_info.ext_field.clone();
                for expect in expect_geo_ip_data.iter() {
                    assert!(ext_field.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_filtered_insert_message_with_geoip() {
        let test_filepath: &str = "test.evtx";
        let test_rulepath: &str = "test-rule.yml";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
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
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                sort_events: false,
                enable_all_rules: false,
                scan_all_evtx_files: false,
            },
            geo_ip: Some(Path::new("test_files/mmdb").to_path_buf()),
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: false,
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
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

            let val = r#"
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
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let dummy_rule = RuleNode::new(test_rulepath.to_string(), Yaml::from_str(""));
            let keys = detections::rule::get_detection_keys(&dummy_rule);

            let input_evtxrecord =
                utils::create_rec_info(event, test_filepath.to_owned(), &keys, &false, &false);
            {
                let rule = &dummy_rule;
                let record_info = &input_evtxrecord;
                let stored_static = &stored_static;
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);
                let expect_geo_ip_data: Vec<(CompactString, Profile)> = vec![
                    ("SrcASN".into(), Profile::SrcASN("-".into())),
                    ("SrcCountry".into(), Profile::SrcCountry("-".into())),
                    ("SrcCity".into(), Profile::SrcCity("-".into())),
                    ("TgtASN".into(), Profile::TgtASN("-".into())),
                    ("TgtCountry".into(), Profile::TgtCountry("-".into())),
                    ("TgtCity".into(), Profile::TgtCity("-".into())),
                ];
                let ext_field = detect_info.ext_field.clone();
                for expect in expect_geo_ip_data.iter() {
                    assert!(ext_field.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_insert_message_extra_field_info() {
        let test_filepath: &str = "test.evtx";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
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
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                sort_events: false,
                enable_all_rules: false,
                scan_all_evtx_files: false,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: true,
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(dummy_config);
        stored_static.profiles.as_mut().unwrap().push((
            "ExtraFieldInfo".into(),
            Profile::ExtraFieldInfo(Default::default()),
        ));
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

            let val = r#"
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
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let rule_str = r#"
        enabled: true
        author: "Test, Test2/Test3; Test4 "
        detection:
            selection:
                Channel: 'Dummy'
        details: 'Channel: %Channel% ¦ EventID: %EventID% ¦ EventRecordID: %EventRecordID% ¦ TimeCreated: %TimeCreated% ¦ IpAddress: %IpAddress%'
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let rule_yaml = YamlLoader::load_from_str(rule_str);
            assert!(rule_yaml.is_ok());
            let rule_yamls = rule_yaml.unwrap();
            let mut rule_yaml = rule_yamls.into_iter();
            let mut rule_node = create_rule(test_filepath.to_string(), rule_yaml.next().unwrap());
            assert!(rule_node.init(&create_dummy_stored_static()).is_ok());

            let keys = detections::rule::get_detection_keys(&rule_node);
            let input_evtxrecord =
                utils::create_rec_info(event, test_filepath.to_owned(), &keys, &false, &false);
            {
                let rule = &rule_node;
                let record_info = &input_evtxrecord;
                let stored_static: &StoredStatic = &stored_static.clone();
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

                let expect_extra_field_data: Vec<(CompactString, Profile)> = vec![(
                    "ExtraFieldInfo".into(),
                    Profile::ExtraFieldInfo(
                        "CommandRLine: hoge ¦ DestAddress: 2.125.160.216".into(),
                    ),
                )];
                let ext_field = detect_info.ext_field.clone();
                for expect in expect_extra_field_data.iter() {
                    assert!(ext_field.contains(expect));
                }
            };
        }
    }

    #[test]
    fn test_insert_message_multiline_ruleauthor() {
        let test_filepath: &str = "test.evtx";
        let dummy_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                profile: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                exact_level: None,
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
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    json_input: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                enable_unsupported_rules: false,
                clobber: false,
                proven_rules: false,
                include_tag: None,
                exclude_tag: None,
                include_category: None,
                exclude_category: None,
                include_eid: None,
                exclude_eid: None,
                no_field: false,
                no_pwsh_field_extraction: false,
                remove_duplicate_data: false,
                remove_duplicate_detections: false,
                no_wizard: true,
                include_status: None,
                sort_events: false,
                enable_all_rules: false,
                scan_all_evtx_files: false,
            },
            geo_ip: None,
            output: Some(Path::new("./test_emit_csv.csv").to_path_buf()),
            multiline: true,
        });
        let dummy_config = Some(Config {
            action: Some(dummy_action),
            debug: false,
        });
        let mut stored_static = StoredStatic::create_static_data(dummy_config);
        stored_static
            .profiles
            .as_mut()
            .unwrap()
            .push(("RuleAuthor".into(), Profile::RuleAuthor(Default::default())));
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

            let val = r#"
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
                        "Channel": "Dummy",
                        "EventID": "4624"
                    }
                }
            }
        "#;
            let rule_str = r#"
        enabled: true
        author: "Test, Test2/Test3; Test4 "
        detection:
            selection:
                Channel: 'Dummy'
        details: 'Test'
        "#;
            let event: Value = serde_json::from_str(val).unwrap();
            let rule_yaml = YamlLoader::load_from_str(rule_str);
            assert!(rule_yaml.is_ok());
            let rule_yamls = rule_yaml.unwrap();
            let mut rule_yaml = rule_yamls.into_iter();
            let mut rule_node = create_rule(test_filepath.to_string(), rule_yaml.next().unwrap());
            assert!(rule_node.init(&create_dummy_stored_static()).is_ok());

            let keys = detections::rule::get_detection_keys(&rule_node);
            let input_evtxrecord =
                utils::create_rec_info(event, test_filepath.to_owned(), &keys, &false, &false);
            {
                let rule = &rule_node;
                let record_info = &input_evtxrecord;
                let stored_static: &StoredStatic = &stored_static.clone();
                let detect_info = Detection::create_log_record(rule, record_info, stored_static);

                println!("{:?}", detect_info.ext_field);
                assert!(detect_info.ext_field.iter().any(|x| x
                    == &(
                        CompactString::from("RuleAuthor"),
                        Profile::RuleAuthor("Test🛂🛂Test2🛂🛂Test3🛂🛂Test4".into())
                    )));
            }
        }
    }
}

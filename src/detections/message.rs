extern crate lazy_static;
use crate::detections::configs::CURRENT_EXE_PATH;
use crate::detections::field_data_map::{convert_field_data, FieldDataMap, FieldDataMapKey};
use crate::detections::utils::{self, get_serde_number_to_string, write_color_buffer};
use crate::options::profile::Profile::{
    self, AllFieldInfo, Details, ExtraFieldInfo, Literal, SrcASN, SrcCity, SrcCountry, TgtASN,
    TgtCity, TgtCountry,
};
use chrono::{DateTime, Local, Utc};
use compact_str::CompactString;
use dashmap::DashMap;
use hashbrown::HashMap;
use hashbrown::HashSet;
use itertools::Itertools;
use lazy_static::lazy_static;
use nested::Nested;
use regex::Regex;
use serde_json::Value;
use std::env;
use std::fs::{create_dir, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use termcolor::{BufferWriter, ColorChoice};

use super::configs::EventKeyAliasConfig;
use super::utils::remove_sp_char;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetectInfo {
    pub rulepath: CompactString,
    pub ruleid: CompactString,
    pub ruletitle: CompactString,
    pub level: CompactString,
    pub computername: CompactString,
    pub eventid: CompactString,
    pub detail: CompactString,
    pub ext_field: Vec<(CompactString, Profile)>,
    pub is_condition: bool,
    pub details_convert_map: HashMap<CompactString, Vec<CompactString>>,
}

pub struct AlertMessage {}

lazy_static! {
    #[derive(Debug,PartialEq, Eq, Ord, PartialOrd)]
    pub static ref MESSAGES: DashMap<DateTime<Utc>, Vec<DetectInfo>> = DashMap::new();
    pub static ref MESSAGEKEYS: Mutex<HashSet<DateTime<Utc>>> = Mutex::new(HashSet::new());
    pub static ref ALIASREGEX: Regex = Regex::new(r"%[a-zA-Z0-9-_\[\]]+%").unwrap();
    pub static ref SUFFIXREGEX: Regex = Regex::new(r"\[([0-9]+)\]").unwrap();
    pub static ref ERROR_LOG_STACK: Mutex<Nested<String>> = Mutex::new(Nested::<String>::new());
    pub static ref TAGS_CONFIG: HashMap<CompactString, CompactString> = create_output_filter_config(
        utils::check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "config/mitre_tactics.txt", true)
            .unwrap().to_str()
            .unwrap(),
        true
    );
    pub static ref COMPUTER_MITRE_ATTCK_MAP : DashMap<CompactString, Vec<CompactString>> = DashMap::new();
    pub static ref LEVEL_ABBR_MAP:HashMap<&'static str, &'static str> = HashMap::from_iter(vec![
        ("critical", "crit"),
        ("high", "high"),
        ("medium", "med "),
        ("low", "low "),
        ("informational", "info"),
    ]
);
    pub static ref LEVEL_FULL: HashMap<&'static str, &'static str> = HashMap::from([
        ("crit", "critical"),
        ("high", "high"),
        ("med ", "medium"),
        ("low ", "low"),
        ("info", "informational")
    ]);
}

/// ファイルパスで記載されたtagでのフル名、表示の際に置き換えられる文字列のHashMapを作成する関数。
/// ex. attack.impact,Impact
pub fn create_output_filter_config(
    path: &str,
    is_lower_case: bool,
) -> HashMap<CompactString, CompactString> {
    let mut ret: HashMap<CompactString, CompactString> = HashMap::new();
    let read_result = match utils::read_csv(path) {
        Ok(c) => c,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return HashMap::default();
        }
    };
    read_result.iter().for_each(|line| {
        let key = if is_lower_case {
            line[0].trim().to_ascii_lowercase()
        } else {
            line[0].trim().to_string()
        };
        ret.insert(
            CompactString::from(key),
            CompactString::from(line[1..].iter().map(|x| x.trim()).join(",")),
        );
    });
    ret
}

/// メッセージの設定を行う関数。aggcondition対応のためrecordではなく出力をする対象時間がDatetime形式での入力としている
pub fn insert_message(detect_info: DetectInfo, event_time: DateTime<Utc>) {
    MESSAGEKEYS.lock().unwrap().insert(event_time);
    let mut v = MESSAGES.entry(event_time).or_default();
    let (_, info) = v.pair_mut();
    info.push(detect_info);
}

/// メッセージを設定 TODO 要リファクタリング
pub fn insert(
    event_record: &Value,
    output: CompactString,
    mut detect_info: DetectInfo,
    time: DateTime<Utc>,
    profile_converter: &HashMap<&str, Profile>,
    (is_agg, is_json_timeline): (bool, bool),
    (eventkey_alias, field_data_map_key, field_data_map): (
        &EventKeyAliasConfig,
        &FieldDataMapKey,
        &Option<FieldDataMap>,
    ),
) {
    let mut record_details_info_map = HashMap::new();
    let mut sp_removed_details_in_record = vec![];
    if !is_agg {
        //ここの段階でdetailsの内容でaliasを置き換えた内容と各種、key,valueの組み合わせのmapを取得する
        let (removed_sp_parsed_detail, mut details_in_record) = parse_message(
            event_record,
            &output,
            eventkey_alias,
            is_json_timeline,
            field_data_map_key,
            field_data_map,
        );
        details_in_record.drain(..).for_each(|v| {
            sp_removed_details_in_record.push(remove_sp_char(v));
        });
        if is_json_timeline {
            record_details_info_map.insert("#Details".into(), sp_removed_details_in_record.clone());
        }
        // 特殊文字の除外のためのretain処理
        // Details内にある改行文字は除外しないために絵文字を含めた特殊な文字に変換することで対応する
        let parsed_detail = remove_sp_char(removed_sp_parsed_detail);
        detect_info.detail = if parsed_detail.is_empty() {
            CompactString::from("-")
        } else {
            parsed_detail
        };
    } else if output != "-" {
        record_details_info_map.insert("#Details".into(), vec![output]);
    } else if detect_info.detail != "-" {
        record_details_info_map.insert("#Details".into(), vec![detect_info.detail.clone()]);
    } else {
        record_details_info_map.insert("#Details".into(), vec!["-".into()]);
    }
    let mut replaced_profiles: Vec<(CompactString, Profile)> = vec![];
    let mut exist_all_field_info_in_ext_field = false;
    for (key, profile) in detect_info.ext_field.iter() {
        match profile {
            Details(_) => {
                if detect_info.detail.is_empty() {
                    //Detailsの中身が何も入っていない場合はそのままの値を入れる
                    replaced_profiles.push((key.to_owned(), profile.to_owned()));
                } else {
                    replaced_profiles.push((key.to_owned(), Details(detect_info.detail.into())));

                    // メモリの節約のためにDetailsの中身を空にする
                    detect_info.detail = CompactString::default();
                }
            }
            AllFieldInfo(_) => {
                exist_all_field_info_in_ext_field = true;
                if is_agg {
                    replaced_profiles.push((key.to_owned(), AllFieldInfo("-".into())));
                } else {
                    let recinfos = if let Some(c) = record_details_info_map.get("#AllFieldInfo") {
                        c.to_owned()
                    } else {
                        utils::create_recordinfos(event_record, field_data_map_key, field_data_map)
                    };
                    if is_json_timeline {
                        record_details_info_map.insert("#AllFieldInfo".into(), recinfos);
                        replaced_profiles.push((key.to_owned(), AllFieldInfo("".into())));
                        continue;
                    }
                    let rec = if recinfos.is_empty() {
                        "-".to_string()
                    } else if !is_json_timeline {
                        recinfos.join(" ¦ ")
                    } else {
                        String::default()
                    };
                    replaced_profiles.push((key.to_owned(), AllFieldInfo(rec.into())));
                }
            }
            Literal(_) => replaced_profiles.push((key.to_owned(), profile.to_owned())),
            ExtraFieldInfo(_) => {
                if is_agg {
                    if is_json_timeline {
                        record_details_info_map
                            .insert("#ExtraFieldInfo".into(), vec![CompactString::from("-")]);
                        replaced_profiles.push((key.to_owned(), ExtraFieldInfo("".into())));
                    } else {
                        replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                    }
                    continue;
                }
                let profile_all_field_info_prof = record_details_info_map.get("#AllFieldInfo");
                let details_splits: HashSet<&str> = {
                    let details = sp_removed_details_in_record.iter().map(|x| {
                        let v = x.split_once(": ").unwrap_or_default().1;
                        // 末尾のカンマが含まれている場合と含まれていない場合でExtraFieldInfoでの一致判定が変わってしまうため判定用のハッシュセットの末尾のカンマを削除する
                        v.strip_suffix(',').unwrap_or(v)
                    });
                    HashSet::from_iter(details)
                };
                let profile_all_field_info = if let Some(all_field_info_val) =
                    profile_all_field_info_prof
                {
                    all_field_info_val.to_owned()
                } else {
                    let recinfo =
                        utils::create_recordinfos(event_record, field_data_map_key, field_data_map);
                    record_details_info_map.insert("#AllFieldInfo".into(), recinfo.clone());
                    recinfo
                };
                let extra_field_vec = profile_all_field_info
                    .iter()
                    .filter(|x| {
                        let value = x.split_once(": ").unwrap_or_default().1;
                        !details_splits.contains(value)
                    })
                    .map(|y| y.to_owned())
                    .sorted_unstable()
                    .collect();
                if is_json_timeline {
                    record_details_info_map.insert("#ExtraFieldInfo".into(), extra_field_vec);
                    replaced_profiles.push((key.to_owned(), ExtraFieldInfo("".into())));
                } else if extra_field_vec.is_empty() {
                    replaced_profiles.push((key.to_owned(), ExtraFieldInfo("-".into())));
                } else {
                    replaced_profiles.push((
                        key.to_owned(),
                        ExtraFieldInfo(extra_field_vec.join(" ¦ ").into()),
                    ));
                }
            }
            SrcASN(_) | SrcCountry(_) | SrcCity(_) | TgtASN(_) | TgtCountry(_) | TgtCity(_) => {
                replaced_profiles.push((
                    key.to_owned(),
                    profile_converter.get(key.as_str()).unwrap().to_owned(),
                ))
            }
            _ => {
                if let Some(p) = profile_converter.get(key.as_str()) {
                    let (parsed_message, _) = &parse_message(
                        event_record,
                        &CompactString::new(p.to_value()),
                        eventkey_alias,
                        is_json_timeline,
                        field_data_map_key,
                        field_data_map,
                    );
                    replaced_profiles.push((key.to_owned(), profile.convert(parsed_message)))
                }
            }
        }
    }
    if !exist_all_field_info_in_ext_field {
        record_details_info_map.remove("#AllFieldInfo");
    }
    detect_info.ext_field = replaced_profiles;
    detect_info.details_convert_map = record_details_info_map;
    insert_message(detect_info, time)
}

/// メッセージ内の%で囲まれた箇所をエイリアスとしてレコード情報を参照して置き換える関数
pub fn parse_message(
    event_record: &Value,
    output: &CompactString,
    eventkey_alias: &EventKeyAliasConfig,
    json_timeline_flag: bool,
    field_data_map_key: &FieldDataMapKey,
    field_data_map: &Option<FieldDataMap>,
) -> (CompactString, Vec<CompactString>) {
    let mut return_message = output.clone();
    let mut hash_map: Vec<(CompactString, Vec<CompactString>)> = vec![];
    let details_key: Vec<&str> = output.split(" ¦ ").collect();
    for caps in ALIASREGEX.captures_iter(&return_message) {
        let full_target_str = &caps[0];
        let target_str = full_target_str
            .strip_suffix('%')
            .unwrap()
            .strip_prefix('%')
            .unwrap();
        let array_str = if let Some(_array_str) = eventkey_alias.get_event_key(target_str) {
            _array_str.to_string()
        } else {
            format!("Event.EventData.{target_str}")
        };

        let mut tmp_event_record: &Value = event_record;
        let mut field = "";
        for s in array_str.split('.') {
            if let Some(record) = tmp_event_record.get(s) {
                tmp_event_record = record;
                field = s;
            }
        }
        let suffix_match = SUFFIXREGEX.captures(target_str);
        let suffix: i64 = match suffix_match {
            Some(cap) => cap.get(1).map_or(-1, |a| a.as_str().parse().unwrap_or(-1)),
            None => -1,
        };
        if suffix >= 1 {
            tmp_event_record = tmp_event_record
                .get("Data")
                .unwrap_or(tmp_event_record)
                .get((suffix - 1) as usize)
                .unwrap_or(tmp_event_record);
        }
        let hash_value = get_serde_number_to_string(tmp_event_record, false);
        if hash_value.is_some() {
            if let Some(hash_value) = hash_value {
                let field_data = if field_data_map.is_none() || field.is_empty() {
                    hash_value
                } else {
                    let converted_str = convert_field_data(
                        field_data_map.as_ref().unwrap(),
                        field_data_map_key,
                        field.to_lowercase().as_str(),
                        hash_value.as_str(),
                    );
                    converted_str.unwrap_or(hash_value)
                };
                if json_timeline_flag {
                    hash_map.push((CompactString::from(full_target_str), [field_data].to_vec()));
                } else {
                    hash_map.push((
                        CompactString::from(full_target_str),
                        [field_data.split_ascii_whitespace().join(" ").into()].to_vec(),
                    ));
                }
            }
        } else {
            hash_map.push((
                CompactString::from(full_target_str),
                ["n/a".into()].to_vec(),
            ));
        }
    }
    let mut details_key_and_value: Vec<CompactString> = vec![];
    for (k, v) in hash_map.iter() {
        // JSON出力の場合は各種のaliasを置き換える処理はafterfactの出力用の関数で行うため、ここでは行わない
        if !json_timeline_flag {
            return_message = CompactString::new(return_message.replace(k.as_str(), v[0].as_str()));
        }
        for detail_contents in details_key.iter() {
            if detail_contents.contains(k.as_str()) {
                let key = detail_contents.split_once(": ").unwrap_or_default().0;
                details_key_and_value.push(format!("{}: {}", key, v[0]).into());
                break;
            }
        }
    }
    (return_message, details_key_and_value)
}

/// メッセージを返す
pub fn get(time: DateTime<Utc>) -> Vec<DetectInfo> {
    match MESSAGES.get(&time) {
        Some(v) => v.to_vec(),
        None => Vec::new(),
    }
}

pub fn get_event_time(event_record: &Value, json_input_flag: bool) -> Option<DateTime<Utc>> {
    let system_time = if json_input_flag {
        &event_record["Event"]["System"]["@timestamp"]
    } else {
        &event_record["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
    };
    return utils::str_time_to_datetime(system_time.as_str().unwrap_or(""));
}

impl AlertMessage {
    ///対象のディレクトリが存在することを確認後、最初の定型文を追加して、ファイルのbufwriterを返す関数
    pub fn create_error_log(quiet_errors_flag: bool) {
        if quiet_errors_flag {
            return;
        }
        let file_path = format!(
            "./logs/errorlog-{}.log",
            Local::now().format("%Y%m%d_%H%M%S")
        );
        let path = Path::new(&file_path);
        if !path.parent().unwrap().exists() {
            create_dir(path.parent().unwrap()).ok();
        }
        let mut error_log_writer = BufWriter::new(File::create(path).unwrap());
        error_log_writer
            .write_all(
                format!(
                    "user input: {:?}\n",
                    format_args!(
                        "{}",
                        env::args().collect::<Nested<String>>().iter().join(" ")
                    )
                )
                .as_bytes(),
            )
            .ok();
        let error_logs = ERROR_LOG_STACK.lock().unwrap();
        error_logs.iter().for_each(|error_log| {
            writeln!(error_log_writer, "{error_log}").ok();
        });
        println!("Errors were generated. Please check {file_path} for details.");
        println!();
    }

    /// ERRORメッセージを表示する関数
    pub fn alert(contents: &str) -> io::Result<()> {
        write_color_buffer(
            &BufferWriter::stderr(ColorChoice::Always),
            None,
            &format!("[ERROR] {contents}"),
            true,
        )
    }

    /// WARNメッセージを表示する関数
    pub fn warn(contents: &str) -> io::Result<()> {
        write_color_buffer(
            &BufferWriter::stderr(ColorChoice::Always),
            None,
            &format!("[WARN] {contents}"),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::configs::{load_eventkey_alias, StoredStatic, CURRENT_EXE_PATH};
    use crate::detections::field_data_map::FieldDataMapKey;
    use crate::detections::message::{get, insert_message, AlertMessage, DetectInfo};
    use crate::detections::message::{parse_message, MESSAGES};
    use crate::detections::utils;
    use chrono::Utc;
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use rand::Rng;
    use serde_json::Value;
    use std::thread;
    use std::time::Duration;

    use super::create_output_filter_config;

    #[test]
    fn test_error_message() {
        let input = "TEST!";
        AlertMessage::alert(input).expect("[ERROR] TEST!");
    }

    #[test]
    fn test_warn_message() {
        let input = "TESTWarn!";
        AlertMessage::warn(input).expect("[WARN] TESTWarn!");
    }

    #[test]
    /// outputで指定されているキー(eventkey_alias.txt内で設定済み)から対象のレコード内の情報でメッセージをパースしているか確認する関数
    fn test_parse_message() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest1"
                },
                "System": {
                    "Computer": "testcomputer1",
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest1 computername:testcomputer1";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% computername:%ComputerName%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }

    #[test]
    fn test_parse_message_auto_search() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "NoAlias": "no_alias"
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "alias:no_alias";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("alias:%NoAlias%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }

    #[test]
    /// outputで指定されているキーが、eventkey_alias.txt内で設定されていない場合の出力テスト
    fn test_parse_message_not_exist_key_in_output() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest2"
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "NoExistAlias:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("NoExistAlias:%NoAliasNoHit%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// output test when no exist info in target record output and described key-value data in eventkey_alias.txt
    fn test_parse_message_not_exist_value_in_record() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3"
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 computername:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% computername:%ComputerName%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// output test when no exist info in target record output and described key-value data in eventkey_alias.txt
    fn test_parse_message_multiple_no_suffix_in_record() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:[\"data1\",\"data2\",\"data3\"]";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// output test when no exist info in target record output and described key-value data in eventkey_alias.txt
    fn test_parse_message_multiple_with_suffix_in_record() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:data2";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data[2]%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// output test when no exist info in target record output and described key-value data in eventkey_alias.txt
    fn test_parse_message_multiple_no_exist_in_record() {
        MESSAGES.clear();
        let json_str = r#"
        {
            "Event": {
                "EventData": {
                    "CommandLine": "parsetest3",
                    "Data": [
                        "data1",
                        "data2",
                        "data3"
                    ]
                },
                "System": {
                    "TimeCreated_attributes": {
                        "SystemTime": "1996-02-27T01:05:01Z"
                    }
                }
            }
        }
    "#;
        let event_record: Value = serde_json::from_str(json_str).unwrap();
        let expected = "commandline:parsetest3 data:n/a";
        assert_eq!(
            parse_message(
                &event_record,
                &CompactString::new("commandline:%CommandLine% data:%Data[0]%"),
                &load_eventkey_alias(
                    utils::check_setting_path(
                        &CURRENT_EXE_PATH.to_path_buf(),
                        "rules/config/eventkey_alias.txt",
                        true,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ),
                false,
                &FieldDataMapKey::default(),
                &None
            )
            .0,
            expected,
        );
    }
    #[test]
    /// test of loading output filter config by mitre_tactics.txt
    fn test_load_mitre_tactics_log() {
        let actual = create_output_filter_config("test_files/config/mitre_tactics.txt", true);
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("attack.impact".into(), "Impact".into()),
            ("xxx".into(), "yyy".into()),
        ]);
        _check_hashmap_element(&expected, actual);
    }

    #[test]
    /// loading test to channel_abbrevations.txt
    fn test_load_abbrevations() {
        let actual =
            create_output_filter_config("test_files/config/channel_abbreviations.txt", true);
        let actual2 =
            create_output_filter_config("test_files/config/channel_abbreviations.txt", true);
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("security".into(), "Sec".into()),
            ("xxx".into(), "yyy".into()),
        ]);
        _check_hashmap_element(&expected, actual);
        _check_hashmap_element(&expected, actual2);
    }

    #[test]
    fn _get_default_defails() {
        let expected: HashMap<CompactString, CompactString> = HashMap::from([
            ("Microsoft-Windows-PowerShell_4104".into(),"%ScriptBlockText%".into()),("Microsoft-Windows-Security-Auditing_4624".into(), "User: %TargetUserName% | Comp: %WorkstationName% | IP Addr: %IpAddress% | LID: %TargetLogonId% | Process: %ProcessName%".into()),
            ("Microsoft-Windows-Sysmon_1".into(), "Cmd: %CommandLine% | Process: %Image% | User: %User% | Parent Cmd: %ParentCommandLine% | LID: %LogonId% | PID: %ProcessId% | PGUID: %ProcessGuid%".into()),
            ("Service Control Manager_7031".into(), "Svc: %param1% | Crash Count: %param2% | Action: %param5%".into()),
        ]);
        let actual = StoredStatic::get_default_details("test_files/config/default_details.txt");
        _check_hashmap_element(&expected, actual);
    }

    /// check two HashMap element length and value
    fn _check_hashmap_element(
        expected: &HashMap<CompactString, CompactString>,
        actual: HashMap<CompactString, CompactString>,
    ) {
        assert_eq!(expected.len(), actual.len());
        for (k, v) in expected.iter() {
            assert!(actual.get(k).unwrap_or(&CompactString::default()) == v);
        }
    }

    #[test]
    fn test_insert_message_race_condition() {
        MESSAGES.clear();

        // Setup test detect_info before starting threads.
        let mut sample_detects = vec![];
        let mut rng = rand::thread_rng();
        let sample_event_time = Utc::now();
        for i in 1..2001 {
            let detect_info = DetectInfo {
                rulepath: CompactString::default(),
                ruleid: CompactString::default(),
                ruletitle: CompactString::default(),
                level: CompactString::default(),
                computername: CompactString::default(),
                eventid: CompactString::from(i.to_string()),
                detail: CompactString::default(),
                ext_field: vec![],
                is_condition: false,
                details_convert_map: HashMap::default(),
            };
            sample_detects.push((sample_event_time, detect_info, rng.gen_range(0..10)));
        }

        // Starting threads and randomly insert_message in parallel.
        let mut handles = vec![];
        for (event_time, detect_info, random_num) in sample_detects {
            let handle = thread::spawn(move || {
                thread::sleep(Duration::from_micros(random_num));
                insert_message(detect_info, event_time);
            });
            handles.push(handle);
        }

        // Wait for all threads execution completion.
        for handle in handles {
            handle.join().unwrap();
        }

        // Expect all sample_detects to be included, but the len() size will be different each time I run it
        assert_eq!(get(sample_event_time).len(), 2000)
    }
}

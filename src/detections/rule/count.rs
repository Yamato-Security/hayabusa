use crate::detections::configs::EventKeyAliasConfig;
use crate::detections::configs::StoredStatic;
use crate::detections::configs::STORED_EKEY_ALIAS;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message;
use crate::detections::message::AlertMessage;
use crate::detections::message::ERROR_LOG_STACK;
use crate::detections::rule::aggregation_parser::AggregationConditionToken;
use crate::detections::rule::AggResult;
use crate::detections::rule::RuleNode;
use chrono::{DateTime, TimeZone, Utc};
use hashbrown::HashMap;
use serde_json::Value;
use std::num::ParseIntError;
use std::path::Path;

use crate::detections::utils;

/// 検知された際にカウント情報を投入する関数
pub fn count(
    rule: &mut RuleNode,
    evtx_rec: &EvtxRecordInfo,
    verbose_flag: bool,
    quiet_errors_flag: bool,
    json_input_flag: bool,
) {
    let key: String = create_count_key(
        rule,
        &evtx_rec.record,
        verbose_flag,
        quiet_errors_flag,
        STORED_EKEY_ALIAS.read().unwrap().as_ref().unwrap(),
    );
    let binding = String::default();
    let field_name = match rule.get_agg_condition() {
        None => "",
        Some(aggcondition) => aggcondition
            ._field_name
            .as_ref()
            .unwrap_or(&binding)
            .as_str(),
    };
    let field_value = get_alias_value_in_record(
        rule,
        field_name,
        &evtx_rec.record,
        false,
        verbose_flag,
        quiet_errors_flag,
        STORED_EKEY_ALIAS.read().unwrap().as_ref().unwrap(),
    )
    .unwrap_or_default();
    countup(rule, key, field_value, evtx_rec, json_input_flag);
}

///count byの条件に合致する検知済みレコードの数を増やすための関数
pub fn countup(
    rule: &mut RuleNode,
    key: String,
    field_value: String,
    evtx_rec: &EvtxRecordInfo,
    json_input_flag: bool,
) {
    let record = &evtx_rec.record;
    let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
    let time = message::get_event_time(record, json_input_flag).unwrap_or(default_time);
    let event_id = utils::get_event_value(
        "Event.System.EventID",
        record,
        STORED_EKEY_ALIAS.read().unwrap().as_ref().unwrap(),
    )
    .unwrap();
    let event_id = event_id.to_string().trim_matches('\"').to_string();
    let computer = utils::get_event_value(
        "Event.System.Computer",
        record,
        STORED_EKEY_ALIAS.read().unwrap().as_ref().unwrap(),
    )
    .unwrap();
    let computer = computer.to_string().trim_matches('\"').to_string();
    let channel = utils::get_event_value(
        "Event.System.Channel",
        record,
        STORED_EKEY_ALIAS.read().unwrap().as_ref().unwrap(),
    )
    .unwrap();
    let channel = channel.to_string().trim_matches('\"').to_string();
    let evtx_file_path = evtx_rec.evtx_filepath.to_string();
    let value_map = rule.countdata.entry(key).or_default();
    value_map.push(AggRecordTimeInfo {
        field_value,
        time,
        event_id,
        computer,
        channel,
        evtx_file_path,
    });
}

/// 与えられたエイリアスから対象レコード内の値を取得してダブルクオーテーションを外す関数。
///  ダブルクオーテーションを外す理由は結果表示の際に余計なダブルクオーテーションが入るのを防ぐため
/// is_by_aliasはこの関数を呼び出す際はcountのbyの値もしくはfieldの値のどちらかであるためboolとした
fn get_alias_value_in_record(
    rule: &RuleNode,
    alias: &str,
    record: &Value,
    is_by_alias: bool,
    verbose_flag: bool,
    quiet_errors_flag: bool,
    eventkey_alias: &EventKeyAliasConfig,
) -> Option<String> {
    if alias.is_empty() {
        return None;
    }
    match utils::get_event_value(alias, record, eventkey_alias) {
        Some(value) => Some(value.to_string().replace('\"', "")),
        None => {
            let errmsg = match is_by_alias {
                true => format!(
          "count by clause alias value not found in count process. rule file:{} EventID:{}",
          Path::new(&rule.rulepath)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
          utils::get_event_value(&utils::get_event_id_key(), record, eventkey_alias).unwrap()
        ),
                false => format!(
          "count field clause alias value not found in count process. rule file:{} EventID:{}",
          Path::new(&rule.rulepath)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
          utils::get_event_value(&utils::get_event_id_key(), record, eventkey_alias).unwrap()
        ),
            };
            if verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
            }
            None
        }
    }
}

/// countでgroupbyなどの情報を区分するためのハッシュマップのキーを作成する関数。
/// 以下の場合は空文字を返却
/// groupbyの指定がない、groubpbyで指定したエイリアスがレコードに存在しない場合は_のみとする。空文字ではキーを指定してデータを取得することができなかった
pub fn create_count_key(
    rule: &RuleNode,
    record: &Value,
    verbose_flag: bool,
    quiet_errors_flag: bool,
    eventkey_alias: &EventKeyAliasConfig,
) -> String {
    let agg_condition = rule.get_agg_condition().unwrap();
    if agg_condition._by_field_name.is_some() {
        let by_field_key = agg_condition._by_field_name.as_ref().unwrap();
        if by_field_key.contains(',') {
            let mut res = String::default();
            for key in by_field_key.split(',') {
                res.push_str(
                    &get_alias_value_in_record(
                        rule,
                        key.trim(),
                        record,
                        true,
                        verbose_flag,
                        quiet_errors_flag,
                        eventkey_alias,
                    )
                    .unwrap_or_else(|| "_".to_string()),
                );
                res.push(',');
            }
            res.pop();
            res
        } else {
            get_alias_value_in_record(
                rule,
                by_field_key,
                record,
                true,
                verbose_flag,
                quiet_errors_flag,
                eventkey_alias,
            )
            .unwrap_or_else(|| "_".to_string())
        }
    } else {
        "_".to_string()
    }
}

///現状のレコードの状態から条件式に一致しているかを判定する関数
pub fn aggregation_condition_select(
    rule: &RuleNode,
    stored_static: &StoredStatic,
) -> Vec<AggResult> {
    // recordでaliasが登録されている前提とする
    let value_map = &rule.countdata;
    let mut ret = Vec::new();
    for (key, value) in value_map {
        ret.append(&mut judge_timeframe(rule, value, key, stored_static));
    }
    ret
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// countの括弧内の情報とレコードの情報を所持する構造体
pub struct AggRecordTimeInfo {
    pub field_value: String,
    pub time: DateTime<Utc>,
    pub event_id: String,
    pub computer: String,
    pub channel: String,
    pub evtx_file_path: String,
}

#[derive(Debug)]
/// timeframeに設定された情報。SIGMAルール上timeframeで複数の単位(日、時、分、秒)が複合で記載されているルールがなかったためタイプと数値のみを格納する構造体
pub struct TimeFrameInfo {
    pub timetype: String,
    pub timenum: Result<i64, ParseIntError>,
}

impl TimeFrameInfo {
    /// timeframeの文字列をパースし、構造体を返す関数
    pub fn parse_tframe(value: String, stored_static: &StoredStatic) -> TimeFrameInfo {
        let mut ttype = "";
        let mut target_val = value.as_str();
        if target_val.ends_with('s') {
            ttype = "s";
        } else if target_val.ends_with('m') {
            ttype = "m";
        } else if target_val.ends_with('h') {
            ttype = "h";
        } else if target_val.ends_with('d') {
            ttype = "d";
        } else {
            let errmsg = format!("Timeframe is invalid. Input value:{value}");
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
            }
        }
        if !ttype.is_empty() {
            target_val = &value[..value.len() - 1];
        }
        TimeFrameInfo {
            timetype: ttype.to_string(),
            timenum: target_val.parse::<i64>(),
        }
    }
}

/// TimeFrameInfoで格納されたtimeframeの値を秒数に変換した結果を返す関数
pub fn get_sec_timeframe(rule: &RuleNode, stored_static: &StoredStatic) -> Option<i64> {
    let timeframe = rule.detection.timeframe.as_ref();
    let tfi = timeframe?;
    match &tfi.timenum {
        Ok(n) => {
            if tfi.timetype == "d" {
                Some(n * 86400)
            } else if tfi.timetype == "h" {
                Some(n * 3600)
            } else if tfi.timetype == "m" {
                Some(n * 60)
            } else {
                Some(*n)
            }
        }
        Err(err) => {
            let errmsg = format!("Timeframe number is invalid. timeframe. {err}");
            if stored_static.verbose_flag {
                AlertMessage::alert(&errmsg).ok();
            }
            if !stored_static.quiet_errors_flag {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {errmsg}"));
            }
            Option::None
        }
    }
}
/// conditionのパイプ以降の処理をAggregationParseInfoを参照し、conditionの条件を満たすか判定するための関数
pub fn select_aggcon(cnt: i64, rule: &RuleNode) -> bool {
    let agg_condition = rule.detection.aggregation_condition.as_ref();
    if agg_condition.is_none() {
        return false;
    }

    let agg_condition = agg_condition.unwrap();
    match agg_condition._cmp_op {
        AggregationConditionToken::EQ => cnt == agg_condition._cmp_num,
        AggregationConditionToken::GE => cnt >= agg_condition._cmp_num,
        AggregationConditionToken::GT => cnt > agg_condition._cmp_num,
        AggregationConditionToken::LE => cnt <= agg_condition._cmp_num,
        AggregationConditionToken::LT => cnt < agg_condition._cmp_num,
        _ => false,
    }
}

/// condtionの分岐によって同じ型を返すif-letのジェネリクス
fn _if_condition_fn_caller<T: FnMut() -> S, S, U: FnMut() -> S>(
    condition: bool,
    mut process_true: T,
    mut process_false: U,
) -> S {
    if condition {
        process_true()
    } else {
        process_false()
    }
}

/**
 * count()の数え方の違いを吸収するtrait
 */
trait CountStrategy {
    /**
     * datas[idx]のデータをtimeframeに追加します
     */
    fn add_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], rule: &RuleNode);
    /**
     * datas[idx]のデータをtimeframeから削除します。
     */
    fn remove_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], rule: &RuleNode);
    /**
     * count()の値を返します。
     */
    fn count(&mut self) -> i64;
    /**
     * AggResultを作成します。
     */
    fn create_agg_result(&mut self, datas: &[AggRecordTimeInfo], cnt: i64, key: &str) -> AggResult;
}

/**
 * countにfieldが指定されている場合のjudgeの計算方法を表す構造体
 */
struct FieldStrategy {
    value_2_cnt: HashMap<String, i64>,
}

impl CountStrategy for FieldStrategy {
    fn add_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], _rule: &RuleNode) {
        if idx >= datas.len() as i64 || idx < 0 {
            return;
        }

        let value = &datas[idx as usize].field_value;
        let key_val = self.value_2_cnt.get_key_value_mut(value);
        if let Some(kv) = key_val {
            let (_, val) = kv;
            *val += 1;
        } else {
            self.value_2_cnt.insert(value.to_string(), 1);
        }
    }

    fn remove_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], _rule: &RuleNode) {
        if idx >= datas.len() as i64 || idx < 0 {
            return;
        }

        let record_value = &datas[idx as usize].field_value;
        let key_val = self.value_2_cnt.get_key_value_mut(record_value);
        if key_val.is_none() {
            return;
        }

        let val: &mut i64 = key_val.unwrap().1;
        if val <= &mut 1 {
            // 0になる場合はキー自体削除する
            self.value_2_cnt.remove(record_value);
        } else {
            *val += -1; // 個数を減らす
        }
    }

    fn count(&mut self) -> i64 {
        return self.value_2_cnt.keys().len() as i64;
    }

    fn create_agg_result(
        &mut self,
        datas: &[AggRecordTimeInfo],
        _cnt: i64,
        key: &str,
    ) -> AggResult {
        let values: Vec<String> = self.value_2_cnt.drain().map(|(key, _)| key).collect(); // drainで初期化
        AggResult::new(
            values.len() as i64,
            key.to_string(),
            values,
            datas.first().unwrap().time,
            datas.to_vec(),
        )
    }
}

/**
 * countにfieldが指定されていない場合のjudgeの計算方法を表す構造体
 */
struct NoFieldStrategy {
    cnt: i64,
}

impl CountStrategy for NoFieldStrategy {
    fn add_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], _rule: &RuleNode) {
        if idx >= datas.len() as i64 || idx < 0 {
            return;
        }

        self.cnt += 1;
    }

    fn remove_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], _rule: &RuleNode) {
        if idx >= datas.len() as i64 || idx < 0 {
            return;
        }

        self.cnt += -1;
    }

    fn count(&mut self) -> i64 {
        self.cnt
    }

    fn create_agg_result(&mut self, datas: &[AggRecordTimeInfo], cnt: i64, key: &str) -> AggResult {
        let ret = AggResult::new(
            cnt,
            key.to_string(),
            vec![],
            datas.first().unwrap().time,
            datas.to_vec(),
        );
        self.cnt = 0; //cntを初期化
        ret
    }
}

fn _create_counter(rule: &RuleNode) -> Box<dyn CountStrategy> {
    let agg_cond = rule.get_agg_condition().unwrap();
    if agg_cond._field_name.is_some() {
        Box::new(FieldStrategy {
            value_2_cnt: HashMap::new(),
        })
    } else {
        Box::new(NoFieldStrategy { cnt: 0 })
    }
}

fn _get_timestamp(idx: i64, datas: &[AggRecordTimeInfo]) -> i64 {
    datas[idx as usize].time.timestamp()
}

fn _get_timestamp_subsec_nano(idx: i64, datas: &[AggRecordTimeInfo]) -> u32 {
    datas[idx as usize].time.timestamp_subsec_nanos()
}

// data[left]からdata[right-1]までのデータがtimeframeに収まっているか判定する
fn _is_in_timeframe(left: i64, right: i64, frame: i64, datas: &[AggRecordTimeInfo]) -> bool {
    let left_time = _get_timestamp(left, datas);
    let left_time_nano = _get_timestamp_subsec_nano(left, datas);
    // evtxのSystemTimeは小数点7桁秒まで記録されているので、それを考慮する
    let mut right_time = _get_timestamp(right, datas);
    let right_time_nano = _get_timestamp_subsec_nano(right, datas);
    if right_time_nano > left_time_nano {
        right_time += 1;
    }
    right_time - left_time <= frame
}

/// count済みデータ内でタイムフレーム内に存在するselectの条件を満たすレコードが、timeframe単位でcountの条件を満たしているAggResultを配列として返却する関数
pub fn judge_timeframe(
    rule: &RuleNode,
    time_datas: &[AggRecordTimeInfo],
    key: &str,
    stored_static: &StoredStatic,
) -> Vec<AggResult> {
    let mut ret: Vec<AggResult> = Vec::new();
    if time_datas.is_empty() {
        return ret;
    }

    // AggRecordTimeInfoを時間順がソートされている前提で処理を進める
    let mut datas = time_datas.to_owned();
    datas.sort_by(|a, b| a.time.cmp(&b.time));

    // timeframeの設定がルールにない時は最初と最後の要素の時間差をtimeframeに設定する。
    let def_frame =
        datas.last().unwrap().time.timestamp() - datas.first().unwrap().time.timestamp();
    let frame = get_sec_timeframe(rule, stored_static).unwrap_or(def_frame);

    // left <= i < rightの範囲にあるdata[i]がtimeframe内にあるデータであると考える
    let mut left: i64 = 0;
    let mut right: i64 = 0;
    let mut counter = _create_counter(rule);
    let data_len = datas.len() as i64;
    // rightは開区間なので+1
    while left < data_len && right < data_len + 1 {
        // timeframeの範囲にある限りrightをincrement
        while right < data_len && _is_in_timeframe(left, right, frame, &datas) {
            counter.add_data(right, &datas, rule);
            right += 1;
        }

        let cnt = counter.count();
        if select_aggcon(cnt, rule) {
            // 条件を満たすtimeframeが見つかった
            ret.push(counter.create_agg_result(&datas[left as usize..right as usize], cnt, key));
            left = right;
        } else {
            // 条件を満たさなかったので、rightとleftを+1ずらす
            counter.add_data(right, &datas, rule);
            right += 1;
            counter.remove_data(left, &datas, rule);
            left += 1;
        }
    }

    ret
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::detections;
    use crate::detections::configs::CommonOptions;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::DetectCommonOption;
    use crate::detections::configs::InputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::StoredStatic;
    use crate::detections::configs::STORED_EKEY_ALIAS;
    use crate::detections::configs::{Action, TimeFormatOptions};
    use crate::detections::rule::create_rule;
    use crate::detections::rule::AggResult;
    use crate::detections::utils;
    use chrono::DateTime;
    use chrono::NaiveDate;
    use hashbrown::HashMap;

    use chrono::{TimeZone, Utc};
    use yaml_rust2::YamlLoader;

    const SIMPLE_RECORD_STR: &str = r#"
    {
      "Event": {
        "System": {
          "EventID": 7040,
          "Channel": "System"
        },
        "EventData": {
          "param1": "Windows Event Log",
          "param2": "auto start"
        }
      },
      "Event_attributes": {
        "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
      }
    }"#;

    fn create_dummy_stored_static() -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        recover_records: false,
                        time_offset: None,
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
                    time_format_options: TimeFormatOptions {
                        european_time: false,
                        iso_8601: false,
                        rfc_2822: false,
                        rfc_3339: false,
                        us_military_time: false,
                        us_time: false,
                        utc: false,
                    },
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
                disable_abbreviations: false,
            })),
            debug: false,
        }))
    }

    #[test]
    /// countのカッコ内の記載及びcount byの記載がない場合(timeframeなし)にruleで検知ができることのテスト
    fn test_count_no_field_and_by() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
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
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        let mut expected_count = HashMap::new();
        expected_count.insert("_".to_owned(), 2);
        let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
            2,
            "_".to_string(),
            vec![],
            Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
            vec![],
        )];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    #[test]
    /// countのカッコ内の記載及びcount byの記載がない場合(timeframeあり)にruleで検知ができることのテスト
    fn test_count_no_field_and_by_with_timeframe() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
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
            timeframe: 15m
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        let mut expected_count = HashMap::new();
        expected_count.insert("_".to_owned(), 2);
        let expected_agg_result: Vec<AggResult> = vec![
            AggResult::new(
                1,
                "_".to_string(),
                vec![],
                Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
                vec![],
            ),
            AggResult::new(
                1,
                "_".to_string(),
                vec![],
                Utc.with_ymd_and_hms(1996, 2, 27, 1, 5, 1).unwrap(),
                vec![],
            ),
        ];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    #[test]
    /// countでカッコ内の記載がある場合にruleでcountの検知ができることを確認する
    fn test_count_exist_field() {
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count(Channel) >= 1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        let mut expected_count = HashMap::new();
        expected_count.insert("_".to_owned(), 1);
        let expected_agg_result = AggResult::new(
            1,
            "_".to_string(),
            vec!["System".to_owned()],
            Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
            vec![],
        );
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string()],
            expected_count,
            vec![expected_agg_result],
        );
    }

    #[test]
    /// countでカッコ内の記載、byの記載両方がある場合にruleでcountの検知ができることを確認する
    fn test_count_exist_field_and_by() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "Test",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let mut expected_count = HashMap::new();
        expected_count.insert("System".to_owned(), 1);
        expected_count.insert("Test".to_owned(), 1);
        let expected_agg_result: Vec<AggResult> = vec![
            AggResult::new(
                1,
                "System".to_owned(),
                vec!["7040".to_owned()],
                Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
                vec![],
            ),
            AggResult::new(
                1,
                "Test".to_owned(),
                vec!["9999".to_owned()],
                Utc.with_ymd_and_hms(1996, 2, 27, 1, 5, 1).unwrap(),
                vec![],
            ),
        ];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    #[test]
    /// countでカッコ内の記載、byの記載両方がある場合(複数レコードでカッコ内の指定する値が異なる場合)に値の組み合わせごとに分けてcountが実行していることを確認する
    fn test_count_exist_field_and_by_with_othervalue_in_timeframe() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:05:00Z"
              }
            },
            "EventData": {
              "param1": "Test",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: selection1 | count(EventID) by param1 >= 1
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        let mut expected_count = HashMap::new();
        expected_count.insert("Windows Event Log".to_owned(), 1);
        expected_count.insert("Test".to_owned(), 1);
        let expected_agg_result: Vec<AggResult> = vec![
            AggResult::new(
                1,
                "Windows Event Log".to_owned(),
                vec!["7040".to_owned()],
                Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
                vec![],
            ),
            AggResult::new(
                1,
                "Test".to_owned(),
                vec!["9999".to_owned()],
                Utc.with_ymd_and_hms(1977, 1, 1, 0, 5, 0).unwrap(),
                vec![],
            ),
        ];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    #[test]
    /// countでtimeframeの条件によってruleのcountの条件を満たさない場合に空の配列を返すことを確認する
    fn test_count_not_satisfy_in_timeframe() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T01:05:00Z"
              }
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: selection1 | count(EventID) >= 2
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        let dummy_stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());

        let init_result = rule_node.init(&dummy_stored_static);
        assert!(init_result.is_ok());
        let target = vec![SIMPLE_RECORD_STR, record_str];
        for record in target {
            match serde_json::from_str(record) {
                Ok(rec) => {
                    let keys = detections::rule::get_detection_keys(&rule_node);
                    let recinfo =
                        utils::create_rec_info(rec, "testpath".to_owned(), &keys, &false, &false);
                    let _result = rule_node.select(
                        &recinfo,
                        dummy_stored_static.verbose_flag,
                        dummy_stored_static.quiet_errors_flag,
                        dummy_stored_static.json_input_flag,
                        &dummy_stored_static.eventkey_alias,
                    );
                }
                Err(_) => {
                    panic!("failed to parse json record.");
                }
            }
        }
        //countupの関数が機能しているかを確認
        assert_eq!(
            rule_node.countdata.get(&"_".to_owned()).unwrap().len() as i32,
            2
        );
        let judge_result = rule_node.judge_satisfy_aggcondition(&dummy_stored_static);
        assert_eq!(judge_result.len(), 0);
    }
    #[test]
    /// countでカッコ内の記載、byの記載両方がありtimeframe内に存在する場合にruleでcountの検知ができることを確認する
    fn test_count_exist_field_and_by_with_timeframe() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:05:00Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 2
            timeframe: 30m
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let mut expected_count = HashMap::new();
        expected_count.insert("System".to_owned(), 2);
        let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
            2,
            "System".to_owned(),
            vec!["7040".to_owned(), "9999".to_owned()],
            Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap(),
            vec![],
        )];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    #[test]
    /// countで括弧内の記載、byの記載両方がありtimeframe内に存在する場合にruleでcountの検知ができることを確認する(countの括弧内の項目が異なる場合)
    fn test_count_exist_field_and_by_with_timeframe_other_field_value() {
        let record_str: &str = r#"
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:30:00Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
        let rule_str = r#"
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 1
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        "#;

        let default_time = Utc.with_ymd_and_hms(1977, 1, 1, 0, 0, 0).unwrap();
        let mut expected_count = HashMap::new();
        expected_count.insert("System".to_owned(), 2);
        let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
            2,
            "System".to_owned(),
            vec!["7040".to_owned(), "9999".to_owned()],
            default_time,
            vec![],
        )];
        check_count(
            rule_str,
            &[SIMPLE_RECORD_STR.to_string(), record_str.to_string()],
            expected_count,
            expected_agg_result,
        );
    }

    // timeframeのsecondsが動くことを確認
    #[test]
    fn test_count_timeframe_seconds() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T00:30:10Z"),
            test_create_recstr_std("3", "1977-01-09T00:30:20Z"),
        ];

        // timeframe=20sはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "20s");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=19sはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "19s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // timeframeのminitutesが動くことを確認
    #[test]
    fn test_count_timeframe_minitues() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T00:40:00Z"),
            test_create_recstr_std("3", "1977-01-09T00:50:00Z"),
        ];

        // timeframe=20mはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "20m");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=19mはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "19m");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // timeframeのhourが動くことを確認
    #[test]
    fn test_count_timeframe_hour() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T02:30:00Z"),
        ];

        // timeframe=3hはHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "3h");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=2hはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "2h");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=1hはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "1h");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }

        // timeframe=120minはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "120m");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=119minはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "119m");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // timeframeのdayが動くことを確認
    #[test]
    fn test_count_timeframe_day() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-13T00:30:00Z"),
            test_create_recstr_std("3", "1977-01-20T00:30:00Z"),
        ];

        // timeframe=11dはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "11d");
            let default_time = Utc.with_ymd_and_hms(1977, 1, 9, 0, 30, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=10dはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10d");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // evtx的には小数点の秒数が指定されうるので、それが正しく制御できることを確認
    #[test]
    fn test_count_timeframe_milsecs() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0003000Z"),
        ];

        // timeframe=11secはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "11s");
            let default_time = Utc.with_ymd_and_hms(2021, 12, 21, 10, 40, 0).unwrap();
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=10dはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // evtx的には小数点の秒数が指定されうるので、それが正しく制御できることを確認
    #[test]
    fn test_count_timeframe_milsecs2() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0400000Z"),
        ];

        // timeframe=10secはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let default_time = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2021, 12, 21)
                    .unwrap()
                    .and_hms_milli_opt(10, 40, 0, 50)
                    .unwrap(),
                Utc,
            );
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=10dはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "9s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // evtx的には小数点の秒数が指定されうるので、それが正しく制御できることを確認
    #[test]
    fn test_count_timeframe_milsecs3() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0600000Z"),
        ];

        // timeframe=11secはギリギリHit
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "11s");
            let default_time = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2021, 12, 21)
                    .unwrap()
                    .and_hms_milli_opt(10, 40, 0, 50)
                    .unwrap(),
                Utc,
            );
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // timeframe=10dはギリギリHitしない
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Hitしたレコードがない時のテスト
    #[test]
    fn test_count_norecord() {
        let recs = vec![];

        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let expected_count = HashMap::new();
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // 1レコードで正しく検知できることを確認
    #[test]
    fn test_count_onerecord() {
        let recs = vec![test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z")];

        // byない
        {
            let rule_str = create_std_rule("count(EventID) >= 1", "1s");
            let default_time = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2021, 12, 21)
                    .unwrap()
                    .and_hms_milli_opt(10, 40, 0, 0)
                    .unwrap(),
                Utc,
            );
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 1);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                1,
                "_".to_owned(),
                vec!["1".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }

        // byある
        {
            let rule_str = create_std_rule("count(EventID) by param1>= 1", "1s");
            let default_time = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2021, 12, 21)
                    .unwrap()
                    .and_hms_milli_opt(10, 40, 0, 0)
                    .unwrap(),
                Utc,
            );
            let mut expected_count = HashMap::new();
            expected_count.insert("Windows Event Log".to_owned(), 1);
            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                1,
                "Windows Event Log".to_owned(),
                vec!["1".to_owned()],
                default_time,
                vec![],
            )];
            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }
    }

    // timeframeの検査
    // timeframe=2hで、パイプ以降はcount(EventID) >= 3とする。
    //
    // このとき先頭の3行だと検知しないが、2行目から4行目は検知するはず
    // このように先頭行ではなく、途中から数えて検知するパターンをチェックする。
    // 0:30 EventID=1
    // 1:30 EventID=1
    // 2:30 EventID=2
    // 3:30 EventID=3
    // 10:30 EventID=4
    // 11:30 EventID=5
    // 12:30 EventID=4
    #[test]
    fn test_count_timeframe1() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T10:30:00Z"),
            test_create_recstr_std("5", "1977-01-09T11:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T12:30:00Z"),
        ];
        let rule_str = create_std_rule("count(EventID) >= 3", "2h");

        let mut expected_count = HashMap::new();
        expected_count.insert("_".to_owned(), 7);
        let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
            3,
            "_".to_owned(),
            vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
            Utc.with_ymd_and_hms(1977, 1, 9, 1, 30, 0).unwrap(),
            vec![],
        )];
        check_count(&rule_str, &recs, expected_count, expected_agg_result);
    }

    // ずっと微妙に検知しない
    #[test]
    fn test_count_timeframe2() {
        let recs = vec![
            test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T04:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T05:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T06:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T07:30:00Z"),
        ];

        {
            let rule_str = create_std_rule("count(EventID) >= 3", "2h");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 7);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // 同じ時刻のレコードがあっても正しくcount出来る
    #[test]
    fn test_count_sametime() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T02:30:00Z"),
        ];

        {
            let rule_str = create_std_rule("count(EventID) >= 4", "1h");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 4);

            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                4,
                "_".to_owned(),
                vec![
                    "1".to_owned(),
                    "2".to_owned(),
                    "3".to_owned(),
                    "4".to_owned(),
                ],
                Utc.with_ymd_and_hms(1977, 1, 9, 1, 30, 0).unwrap(),
                vec![],
            )];

            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }
    }

    // countの実装で番兵をおいてないので、それで正しく動くかチェック
    // Hitした全レコードのtimeframeが条件のtimeframeよりも狭い場合にエラーがでないかチェック
    #[test]
    fn test_count_sentinel() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
        ];

        // Hitするパターン
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "1d");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);

            let expected_agg_result: Vec<AggResult> = vec![AggResult::new(
                3,
                "_".to_owned(),
                vec!["1".to_owned(), "2".to_owned(), "3".to_owned()],
                Utc.with_ymd_and_hms(1977, 1, 9, 1, 30, 0).unwrap(),
                vec![],
            )];

            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }
        // Hitしないパターン
        {
            let rule_str = create_std_rule("count(EventID) >= 4", "1d");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);

            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // 1:30-4:30までEventIDが4種類あって、2:30-5:30までEventIDが4種類あるが、
    // 1:30-4:30までで4種類あったら、今度は5:30から数え始めていることを確認
    #[test]
    fn test_count_timeframe_reset() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T04:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T05:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T06:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T07:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T08:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T09:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T10:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T11:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T12:30:00Z"),
        ];

        {
            let rule_str = create_std_rule("count(EventID) >= 4", "3h");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), recs.len() as i32);

            let expected_agg_result: Vec<AggResult> = vec![
                AggResult::new(
                    4,
                    "_".to_owned(),
                    vec![
                        "1".to_owned(),
                        "2".to_owned(),
                        "3".to_owned(),
                        "4".to_owned(),
                    ],
                    Utc.with_ymd_and_hms(1977, 1, 9, 1, 30, 0).unwrap(),
                    vec![],
                ),
                AggResult::new(
                    4,
                    "_".to_owned(),
                    vec![
                        "1".to_owned(),
                        "2".to_owned(),
                        "3".to_owned(),
                        "4".to_owned(),
                    ],
                    Utc.with_ymd_and_hms(1977, 1, 9, 5, 30, 0).unwrap(),
                    vec![],
                ),
                AggResult::new(
                    4,
                    "_".to_owned(),
                    vec![
                        "1".to_owned(),
                        "2".to_owned(),
                        "3".to_owned(),
                        "4".to_owned(),
                    ],
                    Utc.with_ymd_and_hms(1977, 1, 9, 9, 30, 0).unwrap(),
                    vec![],
                ),
            ];

            check_count(&rule_str, &recs, expected_count, expected_agg_result);
        }
    }

    // timeframeの検査
    // timeframe=2hで、パイプ以降はcount(EventID) >= 3とする。
    //
    // test_count_timeframe()のパターンが2回続く場合
    #[test]
    fn test_count_timeframe_twice() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T03:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T04:30:00Z"),
            test_create_recstr_std("4", "1977-01-09T05:30:00Z"),
            test_create_recstr_std("1", "1977-01-09T19:00:00Z"),
            test_create_recstr_std("1", "1977-01-09T20:00:00Z"),
            test_create_recstr_std("3", "1977-01-09T21:00:00Z"),
            test_create_recstr_std("4", "1977-01-09T21:30:00Z"),
            test_create_recstr_std("5", "1977-01-09T22:00:00Z"),
        ];

        let rule_str = create_std_rule("count(EventID) >= 3", "2h");

        let mut expected_count = HashMap::new();
        expected_count.insert("_".to_owned(), 11);
        let expected_agg_result: Vec<AggResult> = vec![
            AggResult::new(
                3,
                "_".to_owned(),
                vec!["2".to_owned(), "3".to_owned(), "4".to_owned()],
                Utc.with_ymd_and_hms(1977, 1, 9, 3, 30, 0).unwrap(),
                vec![],
            ),
            AggResult::new(
                4,
                "_".to_owned(),
                vec![
                    "1".to_owned(),
                    "3".to_owned(),
                    "4".to_owned(),
                    "5".to_owned(),
                ],
                Utc.with_ymd_and_hms(1977, 1, 9, 20, 00, 0).unwrap(),
                vec![],
            ),
        ];
        check_count(&rule_str, &recs, expected_count, expected_agg_result);
    }

    fn test_create_recstr_std(event_id: &str, time: &str) -> String {
        test_create_recstr(event_id, time, "Windows Event Log")
    }

    fn test_create_recstr(event_id: &str, time: &str, param1: &str) -> String {
        let template: &str = r#"
    {
      "Event": {
        "System": {
          "EventID": ${EVENT_ID},
          "TimeCreated_attributes": {
            "SystemTime": "${TIME}"
          }
        },
        "EventData": {
          "param1": "${PARAM1}"
        }
      }
    }"#;
        template
            .replace("${EVENT_ID}", event_id)
            .replace("${TIME}", time)
            .replace("${PARAM1}", param1)
    }

    fn create_std_rule(count: &str, timeframe: &str) -> String {
        let template = r#"
    enabled: true
    detection:
        selection1:
            param1: 'Windows Event Log'
        condition: selection1 | ${COUNT}
        timeframe: ${TIME_FRAME}
    details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
    "#;
        template
            .replace("${COUNT}", count)
            .replace("${TIME_FRAME}", timeframe)
    }

    /// countで対象の数値確認を行うためのテスト用関数
    fn check_count(
        rule_str: &str,
        records_str: &[String],
        expected_counts: HashMap<String, i32>,
        expect_agg_results: Vec<AggResult>,
    ) {
        let mut rule_yaml = YamlLoader::load_from_str(rule_str).unwrap().into_iter();
        let test = rule_yaml.next().unwrap();
        let mut rule_node = create_rule("testpath".to_string(), test);
        let error_checker = rule_node.init(&create_dummy_stored_static());
        if error_checker.is_err() {
            panic!("Failed to init rulenode");
        }
        let dummy_stored_static = create_dummy_stored_static();
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());

        for record_str in records_str {
            match serde_json::from_str(record_str) {
                Ok(record) => {
                    let keys = detections::rule::get_detection_keys(&rule_node);
                    let recinfo = utils::create_rec_info(
                        record,
                        "testpath".to_owned(),
                        &keys,
                        &false,
                        &false,
                    );
                    let result = &rule_node.select(
                        &recinfo,
                        dummy_stored_static.verbose_flag,
                        dummy_stored_static.quiet_errors_flag,
                        dummy_stored_static.json_input_flag,
                        &dummy_stored_static.eventkey_alias,
                    );
                    assert_eq!(result, &true);
                }
                Err(_rec) => {
                    panic!("Failed to parse json record.");
                }
            }
        }
        let agg_results = &rule_node.judge_satisfy_aggcondition(&dummy_stored_static);
        assert_eq!(agg_results.len(), expect_agg_results.len());

        let mut expect_data = vec![];
        let mut expect_key = vec![];
        let mut expect_field_values = vec![];
        let mut expect_start_timedate = vec![];
        for expect_agg in expect_agg_results {
            let expect_count = expected_counts.get(&expect_agg.key).unwrap_or(&-1);
            //countupの関数が機能しているかを確認
            assert_eq!(
                rule_node.countdata.get(&expect_agg.key).unwrap().len() as i32,
                *expect_count
            );
            expect_data.push(expect_agg.data);
            expect_key.push(expect_agg.key);
            expect_field_values.push(expect_agg.field_values);
            expect_start_timedate.push(expect_agg.start_timedate);
        }
        for agg_result in agg_results {
            println!("{}", &agg_result.start_timedate);
            //ここですでにstart_timedateの格納を確認済み
            let index = expect_start_timedate
                .binary_search(&agg_result.start_timedate)
                .unwrap();
            assert_eq!(agg_result.data, expect_data[index]);
            assert_eq!(agg_result.key, expect_key[index]);
            assert!(agg_result.field_values.len() == expect_field_values[index].len());
            for expect_field_value in &expect_field_values[index] {
                // テストによってはtimeframeの値と各fieldの値で配列の順番が想定したものと変化してしまう可能性があるため配列の長さを確認したうえで期待した各要素が存在するかを確認する。
                // field`要素の順番については以降の処理で関連しない
                assert!(agg_result.field_values.contains(expect_field_value));
            }
        }
    }
}

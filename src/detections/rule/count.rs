use crate::detections::configs::EventKeyAliasConfig;
use crate::detections::configs::STORED_EKEY_ALIAS;
use crate::detections::configs::StoredStatic;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message;
use crate::detections::message::AlertMessage;
use crate::detections::message::ERROR_LOG_STACK;
use crate::detections::rule::AggResult;
use crate::detections::rule::RuleNode;
use crate::detections::rule::aggregation_parser::AggregationConditionToken;
use chrono::{DateTime, TimeZone, Utc};
use hashbrown::HashMap;
use serde_json::Value;
use std::num::ParseIntError;
use std::path::Path;

use crate::detections::utils;

/// Function to insert count information when a detection occurs.
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

/// Function to increment the count of detected records matching the count by condition.
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

/// Function to get the value in the target record from the given alias and remove double quotes.
///  The reason for removing double quotes is to prevent extra double quotes from appearing in the result display.
/// is_by_alias is bool because when calling this function, it is either the by value or the field value of count.
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
                    utils::get_event_value(&utils::get_event_id_key(), record, eventkey_alias)
                        .unwrap()
                ),
                false => format!(
                    "count field clause alias value not found in count process. rule file:{} EventID:{}",
                    Path::new(&rule.rulepath)
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    utils::get_event_value(&utils::get_event_id_key(), record, eventkey_alias)
                        .unwrap()
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

/// Function to create hashmap keys for grouping information such as groupby in count.
/// Returns empty string in the following cases:
/// If groupby is not specified, or the alias specified by groupby does not exist in the record, use only "_". An empty string could not be used to retrieve data by key.
pub fn create_count_key(
    rule: &RuleNode,
    record: &Value,
    verbose_flag: bool,
    quiet_errors_flag: bool,
    eventkey_alias: &EventKeyAliasConfig,
) -> String {
    let agg_condition = rule.get_agg_condition().unwrap();
    if let Some(_by_field_name) = agg_condition._by_field_name.as_ref() {
        let by_field_key = _by_field_name;
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

/// Function to determine whether the current state of the record matches the condition expression.
pub fn aggregation_condition_select(
    rule: &RuleNode,
    stored_static: &StoredStatic,
) -> Vec<AggResult> {
    // Assumes that aliases are registered in the record.
    let value_map = &rule.countdata;
    let mut ret = Vec::new();
    for (key, value) in value_map {
        ret.append(&mut judge_timeframe(rule, value, key, stored_static));
    }
    ret
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// Struct holding information inside the parentheses of count and record information.
pub struct AggRecordTimeInfo {
    pub field_value: String,
    pub time: DateTime<Utc>,
    pub event_id: String,
    pub computer: String,
    pub channel: String,
    pub evtx_file_path: String,
}

#[derive(Debug)]
/// Information set in timeframe. A struct that stores only the type and number, since there were no SIGMA rules with multiple units (days, hours, minutes, seconds) combined in timeframe.
pub struct TimeFrameInfo {
    pub timetype: String,
    pub timenum: Result<i64, ParseIntError>,
}

impl TimeFrameInfo {
    /// Function to parse the timeframe string and return a struct.
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

/// Function that returns the result of converting the timeframe value stored in TimeFrameInfo to seconds.
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
/// Function to evaluate whether the condition is satisfied by checking AggregationParseInfo for the processing after the pipe in condition.
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

/// Generics for if-let that returns the same type depending on the branch of condition.
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
 * Trait to absorb differences in how count() counts.
 */
trait CountStrategy {
    /**
     * Adds the data of datas[idx] to the timeframe.
     */
    fn add_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], rule: &RuleNode);
    /**
     * Removes the data of datas[idx] from the timeframe.
     */
    fn remove_data(&mut self, idx: i64, datas: &[AggRecordTimeInfo], rule: &RuleNode);
    /**
     * Returns the value of count().
     */
    fn count(&mut self) -> i64;
    /**
     * Creates an AggResult.
     */
    fn create_agg_result(&mut self, datas: &[AggRecordTimeInfo], cnt: i64, key: &str) -> AggResult;
}

/**
 * Struct representing the calculation method of judge when a field is specified in count.
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
            // If the value becomes 0, delete the key itself.
            self.value_2_cnt.remove(record_value);
        } else {
            *val += -1; // Decrease the count.
        }
    }

    fn count(&mut self) -> i64 {
        self.value_2_cnt.keys().len() as i64
    }

    fn create_agg_result(
        &mut self,
        datas: &[AggRecordTimeInfo],
        _cnt: i64,
        key: &str,
    ) -> AggResult {
        let values: Vec<String> = self.value_2_cnt.drain().map(|(key, _)| key).collect(); // Initialize with drain.
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
 * Struct representing the calculation method of judge when no field is specified in count.
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
        self.cnt = 0; // Initialize cnt.
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

// Determine whether data from data[left] to data[right-1] fits within the timeframe.
fn _is_in_timeframe(left: i64, right: i64, frame: i64, datas: &[AggRecordTimeInfo]) -> bool {
    let left_time = _get_timestamp(left, datas);
    let left_time_nano = _get_timestamp_subsec_nano(left, datas);
    // evtx SystemTime is recorded with up to 7 decimal places of seconds, so this is taken into account.
    let mut right_time = _get_timestamp(right, datas);
    let right_time_nano = _get_timestamp_subsec_nano(right, datas);
    if right_time_nano > left_time_nano {
        right_time += 1;
    }
    right_time - left_time <= frame
}

/// Function that returns as an array the AggResults where records satisfying the select condition within the timeframe in the counted data meet the count condition per timeframe.
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

    // Proceed with processing assuming AggRecordTimeInfo is sorted in time order.
    let mut datas = time_datas.to_owned();
    datas.sort_by_key(|a| a.time);

    // If the timeframe setting is not in the rule, set the time difference between the first and last elements as the timeframe.
    let def_frame =
        datas.last().unwrap().time.timestamp() - datas.first().unwrap().time.timestamp();
    let frame = get_sec_timeframe(rule, stored_static).unwrap_or(def_frame);

    // Consider data[i] in the range left <= i < right to be data within the timeframe.
    let mut left: i64 = 0;
    let mut right: i64 = 0;
    let mut counter = _create_counter(rule);
    let data_len = datas.len() as i64;
    // right is an open interval, so +1.
    while left < data_len && right < data_len + 1 {
        // Increment right as long as it is within the timeframe range.
        while right < data_len && _is_in_timeframe(left, right, frame, &datas) {
            counter.add_data(right, &datas, rule);
            right += 1;
        }

        let cnt = counter.count();
        if select_aggcon(cnt, rule) {
            // A timeframe satisfying the condition was found.
            ret.push(counter.create_agg_result(&datas[left as usize..right as usize], cnt, key));
            left = right;
        } else {
            // The condition was not satisfied, so shift right and left by +1.
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
    use crate::detections;
    use crate::detections::configs::Action;
    use crate::detections::configs::Config;
    use crate::detections::configs::CsvOutputOption;
    use crate::detections::configs::OutputOption;
    use crate::detections::configs::STORED_EKEY_ALIAS;
    use crate::detections::configs::StoredStatic;
    use crate::detections::rule::AggResult;
    use crate::detections::rule::create_rule;
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
                    min_level: "informational".to_string(),
                    no_wizard: true,
                    ..Default::default()
                },
                ..Default::default()
            })),
            ..Default::default()
        }))
    }

    #[test]
    /// Test that detection by rule works when there is no description inside count parentheses and no count by description (without timeframe).
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
    /// Test that detection by rule works when there is no description inside count parentheses and no count by description (with timeframe).
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
    /// Verify that count detection by rule works when there is a description inside the count parentheses.
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
    /// Verify that count detection by rule works when both a description inside parentheses and a by description are present.
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
    /// Verify that count is executed separately for each combination of values when both a description in parentheses and a by description are present in count (when the values specified inside parentheses differ across multiple records).
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
    /// Verify that an empty array is returned when the count condition of the rule is not satisfied due to the timeframe condition.
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
        // Verify that the countup function is working.
        assert_eq!(
            rule_node.countdata.get(&"_".to_owned()).unwrap().len() as i32,
            2
        );
        let judge_result = rule_node.judge_satisfy_aggcondition(&dummy_stored_static);
        assert_eq!(judge_result.len(), 0);
    }
    #[test]
    /// Verify that count detection by rule works when both a description inside parentheses and a by description are present and exist within the timeframe.
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
    /// Verify that count detection by rule works when both a description inside parentheses and a by description are present and exist within the timeframe (when the items inside the count parentheses differ).
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

    // Verify that timeframe seconds work.
    #[test]
    fn test_count_timeframe_seconds() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T00:30:10Z"),
            test_create_recstr_std("3", "1977-01-09T00:30:20Z"),
        ];

        // timeframe=20s is a just-barely-hit.
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

        // timeframe=19s just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "19s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Verify that timeframe minutes work.
    #[test]
    fn test_count_timeframe_minitues() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T00:40:00Z"),
            test_create_recstr_std("3", "1977-01-09T00:50:00Z"),
        ];

        // timeframe=20m is a just-barely-hit.
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

        // timeframe=19m just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "19m");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Verify that timeframe hours work.
    #[test]
    fn test_count_timeframe_hour() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T02:30:00Z"),
        ];

        // timeframe=3h hits.
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

        // timeframe=2h is a just-barely-hit.
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

        // timeframe=1h just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "1h");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }

        // timeframe=120min is a just-barely-hit.
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

        // timeframe=119min just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "119m");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Verify that timeframe days work.
    #[test]
    fn test_count_timeframe_day() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
            test_create_recstr_std("2", "1977-01-13T00:30:00Z"),
            test_create_recstr_std("3", "1977-01-20T00:30:00Z"),
        ];

        // timeframe=11d is a just-barely-hit.
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

        // timeframe=10d just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10d");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // In evtx, seconds with decimal points may be specified, so verify that this is correctly handled.
    #[test]
    fn test_count_timeframe_milsecs() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0003000Z"),
        ];

        // timeframe=11sec is a just-barely-hit.
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

        // timeframe=10d just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // In evtx, seconds with decimal points may be specified, so verify that this is correctly handled.
    #[test]
    fn test_count_timeframe_milsecs2() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0400000Z"),
        ];

        // timeframe=10sec is a just-barely-hit.
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

        // timeframe=10d just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "9s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // In evtx, seconds with decimal points may be specified, so verify that this is correctly handled.
    #[test]
    fn test_count_timeframe_milsecs3() {
        let recs = vec![
            test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
            test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
            test_create_recstr_std("3", "2021-12-21T10:40:10.0600000Z"),
        ];

        // timeframe=11sec is a just-barely-hit.
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

        // timeframe=10d just barely does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Test when there are no hit records.
    #[test]
    fn test_count_norecord() {
        let recs = vec![];

        {
            let rule_str = create_std_rule("count(EventID) >= 3", "10s");
            let expected_count = HashMap::new();
            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // Verify that detection works correctly with 1 record.
    #[test]
    fn test_count_onerecord() {
        let recs = vec![test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z")];

        // Without by.
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

        // With by.
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

    // Inspection of timeframe.
    // timeframe=2h, and after the pipe: count(EventID) >= 3.
    //
    // In this case, the first 3 rows should not be detected, but rows 2 through 4 should be detected.
    // Check patterns that detect starting from the middle rather than from the first row.
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

    // Never quite detects.
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

    // Can correctly count even when records have the same timestamp.
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

    // No sentinel is placed in the count implementation; check that it works correctly.
    // Check that no error occurs when the timeframe of all hit records is narrower than the condition timeframe.
    #[test]
    fn test_count_sentinel() {
        let recs = vec![
            test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
            test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
            test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
        ];

        // Pattern that hits.
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
        // Pattern that does not hit.
        {
            let rule_str = create_std_rule("count(EventID) >= 4", "1d");
            let mut expected_count = HashMap::new();
            expected_count.insert("_".to_owned(), 3);

            check_count(&rule_str, &recs, expected_count, Vec::new());
        }
    }

    // There are 4 types of EventIDs from 1:30 to 4:30, and 4 types from 2:30 to 5:30,
    // Verify that once 4 types are found from 1:30 to 4:30, counting restarts from 5:30.
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

    // Inspection of timeframe.
    // timeframe=2h, and after the pipe: count(EventID) >= 3.
    //
    // When the test_count_timeframe() pattern repeats twice.
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

    /// Test function to verify target numbers for count.
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
            // Verify that the countup function is working.
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
            // Storage of start_timedate has already been verified here.
            let index = expect_start_timedate
                .binary_search(&agg_result.start_timedate)
                .unwrap();
            assert_eq!(agg_result.data, expect_data[index]);
            assert_eq!(agg_result.key, expect_key[index]);
            assert!(agg_result.field_values.len() == expect_field_values[index].len());
            for expect_field_value in &expect_field_values[index] {
                // Depending on the test, the array order may differ from expected due to timeframe values and field values, so verify the array length and then check whether each expected element exists.
                // The order of field elements is not relevant for subsequent processing.
                assert!(agg_result.field_values.contains(expect_field_value));
            }
        }
    }
}

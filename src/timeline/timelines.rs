use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use crate::detections::configs::{Action, EventInfoConfig, StoredStatic};
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::AlertMessage;
use crate::detections::utils::{self, write_color_buffer};
use crate::timeline::search::search_result_dsp_msg;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use compact_str::CompactString;
use csv::WriterBuilder;
use downcast_rs::__std::process;
use nested::Nested;
use termcolor::{BufferWriter, Color, ColorChoice};

use super::metrics::EventMetrics;
use super::search::EventSearch;
use hashbrown::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Timeline {
    pub stats: EventMetrics,
    pub event_search: EventSearch,
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Timeline {
    pub fn new() -> Timeline {
        let totalcnt = 0;
        let filepath = CompactString::default();
        let statslst = HashMap::new();
        let statsloginlst = HashMap::new();
        let search_result = HashSet::new();

        let statistic = EventMetrics::new(
            totalcnt,
            filepath.clone(),
            None,
            None,
            statslst,
            statsloginlst,
        );
        let search = EventSearch::new(filepath, search_result);
        Timeline {
            stats: statistic,
            event_search: search,
        }
    }

    pub fn start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        self.stats.evt_stats_start(records, stored_static);
        self.stats.logon_stats_start(
            records,
            stored_static.logon_summary_flag,
            &stored_static.eventkey_alias,
        );

        if stored_static.search_flag {
            self.event_search.search_start(
                records,
                stored_static
                    .search_option
                    .as_ref()
                    .unwrap()
                    .keywords
                    .as_ref()
                    .unwrap_or(&vec![]),
                &stored_static.search_option.as_ref().unwrap().regex,
                &stored_static.search_option.as_ref().unwrap().filter,
                &stored_static.eventkey_alias,
                stored_static,
            );
        }
    }

    pub fn tm_stats_dsp_msg(
        &mut self,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) {
        // 出力メッセージ作成
        let mut sammsges: Nested<String> = Nested::new();
        let total_event_record = format!("\n\nTotal Event Records: {}\n", self.stats.total);
        let mut wtr;
        let target;

        match &stored_static.config.action.as_ref().unwrap() {
            Action::Metrics(option) => {
                if option.input_args.filepath.is_some() {
                    sammsges.push(format!("Evtx File Path: {}", self.stats.filepath));
                }
                sammsges.push(total_event_record);
                if self.stats.start_time.is_some() {
                    sammsges.push(format!(
                        "First Timestamp: {}",
                        utils::format_time(
                            &self.stats.start_time.unwrap(),
                            false,
                            stored_static.output_option.as_ref().unwrap()
                        )
                    ));
                }
                if self.stats.end_time.is_some() {
                    sammsges.push(format!(
                        "Last Timestamp: {}\n",
                        utils::format_time(
                            &self.stats.end_time.unwrap(),
                            false,
                            stored_static.output_option.as_ref().unwrap()
                        )
                    ));
                }
                wtr = if let Some(csv_path) = option.output.as_ref() {
                    // output to file
                    match File::create(csv_path) {
                        Ok(file) => {
                            target = Box::new(BufWriter::new(file));
                            Some(WriterBuilder::new().from_writer(target))
                        }
                        Err(err) => {
                            AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                            process::exit(1);
                        }
                    }
                } else {
                    None
                };
            }
            _ => {
                return;
            }
        }

        let header = vec!["Count", "Percent", "Channel", "ID", "Event"];
        if let Some(ref mut w) = wtr {
            w.write_record(&header).ok();
        }

        let mut stats_tb = Table::new();
        stats_tb
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        stats_tb.set_header(header);

        // 集計件数でソート
        let mut mapsorted: Vec<_> = self.stats.stats_list.iter().collect();
        mapsorted.sort_by(|x, y| y.1.cmp(x.1));

        // イベントID毎の出力メッセージ生成
        let stats_msges: Nested<Vec<CompactString>> =
            self.tm_stats_set_msg(mapsorted, event_timeline_config, stored_static);

        for msgprint in sammsges.iter() {
            println!("{msgprint}");
        }
        if wtr.is_some() {
            for msg in stats_msges.iter() {
                if let Some(ref mut w) = wtr {
                    w.write_record(msg.iter().map(|x| x.as_str())).ok();
                }
            }
        }
        stats_tb.add_rows(stats_msges.iter());
        println!("{stats_tb}");
    }

    pub fn tm_logon_stats_dsp_msg(&mut self, stored_static: &StoredStatic) {
        // 出力メッセージ作成
        let mut sammsges: Vec<String> = Vec::new();
        let total_event_record = format!("\n\nTotal Event Records: {}\n", self.stats.total);
        if let Action::LogonSummary(logon_summary_option) =
            &stored_static.config.action.as_ref().unwrap()
        {
            if logon_summary_option.input_args.filepath.is_some() {
                sammsges.push(format!("Evtx File Path: {}", self.stats.filepath));
            }
            sammsges.push(total_event_record);

            if self.stats.start_time.is_some() {
                sammsges.push(format!(
                    "First Timestamp: {}",
                    utils::format_time(
                        &self.stats.start_time.unwrap(),
                        false,
                        stored_static.output_option.as_ref().unwrap()
                    )
                ));
            }
            if self.stats.end_time.is_some() {
                sammsges.push(format!(
                    "Last Timestamp: {}\n",
                    utils::format_time(
                        &self.stats.end_time.unwrap(),
                        false,
                        stored_static.output_option.as_ref().unwrap()
                    )
                ));
            }

            for msgprint in sammsges.iter() {
                println!("{msgprint}");
            }

            self.tm_loginstats_tb_set_msg(&logon_summary_option.output);
        }
    }

    // イベントID毎の出力メッセージ生成
    fn tm_stats_set_msg(
        &self,
        mapsorted: Vec<(&(CompactString, CompactString), &usize)>,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) -> Nested<Vec<CompactString>> {
        let mut msges: Nested<Vec<CompactString>> = Nested::new();

        for ((event_id, channel), event_cnt) in mapsorted.iter() {
            // 件数の割合を算出
            let rate: f32 = **event_cnt as f32 / self.stats.total as f32;
            let fmted_channel = channel;

            // イベント情報取得(eventtitleなど)
            // channel_eid_info.txtに登録あるものは情報設定
            // 出力メッセージ1行作成
            let ch = stored_static.disp_abbr_generic.replace_all(
                stored_static
                    .ch_config
                    .get(fmted_channel.as_str())
                    .unwrap_or(fmted_channel)
                    .as_str(),
                &stored_static.disp_abbr_general_values,
            );

            if event_timeline_config
                .get_event_id(fmted_channel, event_id)
                .is_some()
            {
                msges.push(vec![
                    CompactString::from(format!("{event_cnt}")),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0).into(),
                    ch.trim().into(),
                    event_id.to_owned(),
                    CompactString::from(
                        event_timeline_config
                            .get_event_id(fmted_channel, event_id)
                            .unwrap()
                            .evttitle
                            .as_str(),
                    ),
                ]);
            } else {
                msges.push(vec![
                    CompactString::from(format!("{event_cnt}")),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0).into(),
                    ch.trim().into(),
                    event_id.replace('\"', "").into(),
                    CompactString::from("Unknown"),
                ]);
            }
        }
        msges
    }

    /// ユーザ毎のログイン統計情報出力メッセージ生成
    fn tm_loginstats_tb_set_msg(&self, output: &Option<PathBuf>) {
        println!("Logon Summary:\n");
        if self.stats.stats_login_list.is_empty() {
            let mut loginmsges: Vec<String> = Vec::new();
            loginmsges.push("-----------------------------------------".to_string());
            loginmsges.push("|     No logon events were detected.    |".to_string());
            loginmsges.push("-----------------------------------------\n".to_string());
            for msgprint in loginmsges.iter() {
                println!("{msgprint}");
            }
        } else {
            println!("Successful Logons:");
            self.tm_loginstats_tb_dsp_msg("Successful", output);
            println!("\n\nFailed Logons:");
            self.tm_loginstats_tb_dsp_msg("Failed", output);
        }
    }

    /// ユーザ毎のログイン統計情報出力
    fn tm_loginstats_tb_dsp_msg(&self, logon_res: &str, output: &Option<PathBuf>) {
        let header = vec![
            logon_res,
            "Target Account",
            "Target Computer",
            "Logon Type",
            "Source Computer",
            "Source IP Address",
        ];
        let target;
        let mut wtr = if let Some(csv_path) = output {
            let file_name = csv_path.as_path().display().to_string() + "-" + logon_res + ".csv";
            // output to file
            match File::create(file_name) {
                Ok(file) => {
                    target = Box::new(BufWriter::new(file));
                    Some(WriterBuilder::new().from_writer(target))
                }
                Err(err) => {
                    AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                    process::exit(1);
                }
            }
        } else {
            None
        };
        if let Some(ref mut w) = wtr {
            w.write_record(&header).ok();
        }

        let mut logins_stats_tb = Table::new();
        logins_stats_tb
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        logins_stats_tb.set_header(&header);
        // 集計するログオン結果を設定
        let vnum = match logon_res {
            "Successful" => 0,
            "Failed" => 1,
            &_ => 0,
        };
        // 集計件数でソート
        let mut mapsorted: Vec<_> = self.stats.stats_login_list.iter().collect();
        mapsorted.sort_by(|x, y| y.1[vnum].cmp(&x.1[vnum]));
        for ((username, hostname, logontype, source_computer, source_ip), values) in &mapsorted {
            // 件数が"0"件は表示しない
            if values[vnum] == 0 {
                continue;
            } else {
                let vnum_str = values[vnum].to_string();
                let record_data = vec![
                    vnum_str.as_str(),
                    username.as_str(),
                    hostname.as_str(),
                    logontype.as_str(),
                    source_computer.as_str(),
                    source_ip.as_str(),
                ];
                if let Some(ref mut w) = wtr {
                    w.write_record(&record_data).ok();
                }
                logins_stats_tb.add_row(record_data);
            }
        }
        // rowデータがない場合は、検出なしのメッセージを表示する
        if logins_stats_tb.row_iter().len() == 0 {
            println!(" No logon {logon_res} events were detected.");
        } else {
            println!("{logins_stats_tb}");
        }
    }

    /// Search結果出力
    pub fn search_dsp_msg(
        &mut self,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) {
        let mut sammsges: Vec<String> = Vec::new();
        if let Action::Search(search_summary_option) =
            &stored_static.config.action.as_ref().unwrap()
        {
            if self.event_search.search_result.is_empty() {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    Some(Color::Rgb(238, 102, 97)),
                    "\n\nNo matches found.",
                    true,
                )
                .ok();
            } else {
                sammsges.push(format!(
                    "\n\nTotal findings: {}\n",
                    self.event_search.search_result.len()
                ));
            }
            search_result_dsp_msg(
                &mut self.event_search.search_result,
                event_timeline_config,
                &search_summary_option.output,
                stored_static,
            );
            for msgprint in sammsges.iter() {
                println!("{}", msgprint);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::{DateTime, NaiveDateTime, Utc};
    use compact_str::CompactString;
    use hashbrown::HashMap;
    use nested::Nested;

    use crate::{
        detections::{
            configs::{
                Action, CommonOptions, Config, DetectCommonOption, InputOption, LogonSummaryOption,
                StoredStatic, STORED_EKEY_ALIAS,
            },
            utils::create_rec_info,
        },
        timeline::timelines::Timeline,
    };

    fn create_dummy_stored_static(action: Action) -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(action),
            debug: false,
        }))
    }

    /// メトリクスコマンドの統計情報集計のテスト。 Testing of statistics aggregation for metrics commands.
    #[test]
    pub fn test_evt_logon_stats() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::LogonSummary(LogonSummaryOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                },
                detect_common_options: DetectCommonOption {
                    json_input: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                output: None,
            }));
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());
        let mut timeline = Timeline::default();

        // レコード情報がないときにはstats_time_cntは何も行わないことをテスト
        timeline
            .stats
            .logon_stats_start(&[], true, &dummy_stored_static.eventkey_alias);

        // テスト1: 対象となるTimestamp情報がない場合
        let no_timestamp_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Dummy",
                    "Computer":"HAYABUSA-DESKTOP"
                }
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let mut input_datas = vec![];
        let alias_ch_record = serde_json::from_str(no_timestamp_record_str).unwrap();
        input_datas.push(create_rec_info(
            alias_ch_record,
            "testpath".to_string(),
            &Nested::<String>::new(),
        ));
        timeline
            .stats
            .logon_stats_start(&input_datas, true, &dummy_stored_static.eventkey_alias);
        assert!(timeline.stats.start_time.is_none());
        assert!(timeline.stats.end_time.is_none());

        // テスト2: Event.System.TimeCreated_attributes.SystemTimeにタイムスタンプが含まれる場合
        let tcreated_attribe_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": "4624",
                    "Channel": "Security",
                    "Computer":"HAYABUSA-DESKTOP",
                    "TimeCreated_attributes": {
                        "SystemTime": "2021-12-23T00:00:00.000Z"
                    }
                },
                "EventData": {
                    "WorkstationName": "HAYABUSA",
                    "IpAddress": "192.168.100.200",
                    "TargetUserName": "testuser",
                    "LogonType": "3"
                }
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

        let include_tcreated_attribe_record =
            serde_json::from_str(tcreated_attribe_record_str).unwrap();
        input_datas.clear();
        input_datas.push(create_rec_info(
            include_tcreated_attribe_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
        ));

        // テスト3: Event.System.@timestampにタイムスタンプが含まれる場合
        let timestamp_attribe_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security",
                    "Computer":"HAYABUSA-DESKTOP",
                    "@timestamp": "2022-12-23T00:00:00.000Z"
                },
                "EventData": {
                    "TargetUserName": "testuser",
                    "LogonType": "0"
                }
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let include_timestamp_record = serde_json::from_str(timestamp_attribe_record_str).unwrap();
        input_datas.push(create_rec_info(
            include_timestamp_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
        ));

        let mut expect: HashMap<
            (
                CompactString,
                CompactString,
                CompactString,
                CompactString,
                CompactString,
            ),
            [usize; 2],
        > = HashMap::new();
        expect.insert(
            (
                "testuser".into(),
                "HAYABUSA-DESKTOP".into(),
                "3 - Network".into(),
                "HAYABUSA".into(),
                "192.168.100.200".into(),
            ),
            [1, 0],
        );
        expect.insert(
            (
                "testuser".into(),
                "HAYABUSA-DESKTOP".into(),
                "0 - System".into(),
                "n/a".into(),
                "n/a".into(),
            ),
            [0, 1],
        );

        timeline
            .stats
            .logon_stats_start(&input_datas, true, &dummy_stored_static.eventkey_alias);
        assert_eq!(
            timeline.stats.start_time,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::parse_from_str("2021-12-23T00:00:00.000Z", "%Y-%m-%dT%H:%M:%S%.3fZ")
                    .unwrap(),
                Utc
            ))
        );
        assert_eq!(
            timeline.stats.end_time,
            Some(DateTime::<Utc>::from_utc(
                NaiveDateTime::parse_from_str("2022-12-23T00:00:00.000Z", "%Y-%m-%dT%H:%M:%S%.3fZ")
                    .unwrap(),
                Utc
            ))
        );

        assert_eq!(timeline.stats.total, 3);

        for (k, v) in timeline.stats.stats_login_list.iter() {
            assert!(expect.contains_key(k));
            assert_eq!(expect.get(k).unwrap(), v);
        }
    }
}

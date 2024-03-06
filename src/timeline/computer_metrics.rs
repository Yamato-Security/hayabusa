use crate::detections::configs::EventKeyAliasConfig;
use crate::detections::message::AlertMessage;
use crate::detections::utils;
use crate::timeline::timelines::Timeline;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use compact_str::CompactString;
use csv::{QuoteStyle, WriterBuilder};
use downcast_rs::__std::process;
use hashbrown::HashMap;
use itertools::Itertools;
use num::FromPrimitive;
use num_format::{Locale, ToFormattedString};
use serde_json::Value;
use std::cmp::Ordering;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

pub fn countup_event_by_computer(
    record: &Value,
    eventkey_alias: &EventKeyAliasConfig,
    tl: &mut Timeline,
) {
    if let Some(computer_name) =
        utils::get_event_value("Event.System.Computer", record, eventkey_alias)
    {
        let count = tl
            .stats
            .stats_list
            .entry((
                computer_name.to_string().replace('\"', "").into(),
                CompactString::default(),
            ))
            .or_insert(0);
        *count += 1;
    }
}

/// レコード内のコンピュータ名を降順で画面出力もしくはcsvに出力する関数
pub fn computer_metrics_dsp_msg(
    result_list: &HashMap<(CompactString, CompactString), usize>,
    output: &Option<PathBuf>,
) {
    let mut file_wtr = None;
    if let Some(path) = output {
        match File::create(path) {
            Ok(file) => {
                file_wtr = Some(
                    WriterBuilder::new()
                        .delimiter(b',')
                        .quote_style(QuoteStyle::NonNumeric)
                        .from_writer(BufWriter::new(file)),
                )
            }
            Err(err) => {
                AlertMessage::alert(&format!("Failed to open file. {err}")).ok();
                process::exit(1)
            }
        }
    };

    // Write header
    let header = vec!["Computer", "Events"];
    let mut stats_tb = Table::new();
    stats_tb
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    if output.is_some() {
        file_wtr.as_mut().unwrap().write_record(&header).ok();
    } else if output.is_none() && !result_list.is_empty() {
        stats_tb.set_header(&header);
    }

    // Write contents
    for ((computer_name, _), count) in result_list.into_iter().sorted_unstable_by(|a, b| {
        let count_cmp = Ord::cmp(
            &-i64::from_usize(*a.1).unwrap_or_default(),
            &-i64::from_usize(*b.1).unwrap_or_default(),
        );
        if count_cmp != Ordering::Equal {
            return count_cmp;
        }

        a.0.cmp(b.0)
    }) {
        let count_str = if output.is_some() {
            format!("{count}")
        } else {
            count.to_formatted_string(&Locale::en)
        };
        let record_data = vec![computer_name.as_str(), &count_str];
        if output.is_some() {
            file_wtr.as_mut().unwrap().write_record(&record_data).ok();
        } else {
            stats_tb.add_row(record_data);
        }
    }
    if output.is_none() {
        println!();
        println!("{stats_tb}");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{read_to_string, remove_file},
        path::Path,
    };

    use crate::{
        detections::configs::{
            Action, CommonOptions, ComputerMetricsOption, Config, InputOption, StoredStatic,
            STORED_EKEY_ALIAS, STORED_STATIC,
        },
        timeline::{
            computer_metrics::{computer_metrics_dsp_msg, countup_event_by_computer},
            timelines::Timeline,
        },
    };

    #[test]
    pub fn test_computer_metrics_dsp_msg() {
        fn create_dummy_stored_static(action: Action) -> StoredStatic {
            StoredStatic::create_static_data(Some(Config {
                action: Some(action),
                debug: false,
            }))
        }
        let output = Some(Path::new("./test_computer_metrics.csv").to_path_buf());
        let dummy_stored_static =
            create_dummy_stored_static(Action::ComputerMetrics(ComputerMetricsOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("./dummy.evtx").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    timeline_offset: None,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                json_input: false,
                evtx_file_ext: None,
                thread_number: None,
                quiet_errors: false,
                config: Path::new("./rules/config").to_path_buf(),
                verbose: false,
                output: output.clone(),
                clobber: true,
            }));
        *STORED_EKEY_ALIAS.write().unwrap() = Some(dummy_stored_static.eventkey_alias.clone());
        let mut timeline = Timeline::default();
        let first_test_record_str = r#"{
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
        let first_test_record = serde_json::from_str(first_test_record_str).unwrap();
        countup_event_by_computer(
            &first_test_record,
            &dummy_stored_static.eventkey_alias,
            &mut timeline,
        );

        *STORED_STATIC.write().unwrap() = Some(dummy_stored_static.clone());

        let second_test_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security",
                    "Computer":"FALCON",
                    "@timestamp": "2022-12-23T00:00:00.000Z"
                },
                "EventData": {
                    "TargetUserName": "testuser",
                    "LogonType": "0"
                }
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let second_test_record = serde_json::from_str(second_test_record_str).unwrap();
        countup_event_by_computer(
            &second_test_record,
            &dummy_stored_static.eventkey_alias,
            &mut timeline,
        );

        computer_metrics_dsp_msg(&timeline.stats.stats_list, &output);

        let header = ["\"Computer\"", "\"Events\""];

        let expect = [vec!["\"FALCON\"", "1"], vec!["\"HAYABUSA-DESKTOP\"", "1"]];
        let expect_str =
            header.join(",") + "\n" + &expect.join(&"\n").join(",").replace(",\n,", "\n") + "\n";
        match read_to_string("./test_computer_metrics.csv") {
            Err(_) => panic!("Failed to open file."),
            Ok(s) => {
                assert_eq!(s, expect_str);
            }
        };

        //テスト終了後にファイルを削除する
        assert!(remove_file("./test_computer_metrics.csv").is_ok());
    }
}

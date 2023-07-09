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
use serde_json::Value;
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
    for ((computer_name, _), count) in result_list
        .into_iter()
        .sorted_unstable_by(|a, b| Ord::cmp(&a.1, &b.1))
    {
        let count_str = &format!("{count}");
        let record_data = vec![computer_name.as_str(), count_str];
        if output.is_some() {
            file_wtr.as_mut().unwrap().write_record(&record_data).ok();
        } else {
            stats_tb.add_row(record_data);
        }
    }
    if output.is_none() {
        println!("{stats_tb}");
    }
}

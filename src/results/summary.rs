use std::cmp::{self, min};
use std::io::Write;
use std::str::FromStr;

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use compact_str::CompactString;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use krapslog::{build_sparkline, build_time_markers};
use nested::Nested;
use num_format::{Locale, ToFormattedString};
use strum::IntoEnumIterator;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use terminal_size::Width;
use terminal_size::terminal_size;

use crate::detections::configs::{CURRENT_EXE_PATH, StoredStatic};
use crate::detections::message::DetectInfo;
use crate::detections::utils::{
    self, check_setting_path, format_time, get_writable_color, output_and_data_stack_for_html,
    write_color_buffer,
};
use crate::level::{_get_output_color, LEVEL, create_output_color_map};
use crate::options::htmlreport;

use super::html_stock::_output_html_computer_by_mitre_attck;
use super::{Colors, OutputWriter, ResultOutputState, html_escape_value};

/// Folds a batch of detections into `result_state`: records the detection timestamps and the
/// IDs of detected records, and (unless no-summary is set) updates the per-level counts by
/// date, computer, and rule, plus the rule author statistics used by the results summary.
pub(crate) fn calc_statistic_info(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    result_state: &mut ResultOutputState,
    stored_static: &StoredStatic,
) {
    let output_option = stored_static.output_option.as_ref().unwrap();
    for (i, detect_info) in detect_infos.iter().enumerate() {
        if duplicate_indices.contains(&i) {
            continue;
        }
        result_state
            .timestamps
            .push(detect_info.detected_time.timestamp());
        match &detect_info.agg_result {
            None => {
                result_state
                    .detected_record_idset
                    .insert(CompactString::from(format!(
                        "{}_{}",
                        detect_info.detected_time, detect_info.eventid
                    )));
            }
            Some(agg_result) => {
                agg_result.agg_record_time_info.iter().for_each(|a| {
                    result_state
                        .detected_record_idset
                        .insert(CompactString::from(format!("{}_{}", a.time, a.event_id)));
                });
            }
        }
        if !output_option.no_summary {
            let level_index = detect_info.level.index();
            let author_list = extract_author_name(&detect_info.ruleauthor);
            let author_str = author_list.iter().join(", ");
            result_state.detect_rule_authors.insert(
                detect_info.rule_path.to_owned(),
                author_str.to_string().into(),
            );

            if author_str != "-"
                && !result_state
                    .detected_rule_files
                    .contains(&detect_info.rule_path)
            {
                result_state
                    .detected_rule_files
                    .insert(detect_info.rule_path.to_owned());
                for author in author_list.iter() {
                    *result_state
                        .rule_author_counter
                        .entry(CompactString::from(author))
                        .or_insert(0) += 1;
                }
            }
            if !result_state.detected_rule_ids.contains(&detect_info.ruleid) {
                result_state
                    .detected_rule_ids
                    .insert(detect_info.ruleid.to_owned());
                result_state.unique_detect_counts_by_level[level_index] += 1;
            }
            let computer_names = match &detect_info.agg_result {
                None => vec![detect_info.computername.clone()],
                Some(agg) => agg
                    .agg_record_time_info
                    .iter()
                    .map(|a| CompactString::from(a.computer.clone()))
                    .collect::<std::collections::HashSet<_>>() // Convert to HashSet to remove duplicates
                    .into_iter()
                    .sorted()
                    .collect(),
            };
            for computername in &computer_names {
                let computer_rule_check_key =
                    CompactString::from(format!("{}|{}", computername, &detect_info.rule_path));
                if !result_state
                    .detected_computer_and_rule_names
                    .contains(&computer_rule_check_key)
                {
                    result_state
                        .detected_computer_and_rule_names
                        .insert(computer_rule_check_key);
                    countup_aggregation(
                        &mut result_state.detect_counts_by_computer_and_level,
                        &detect_info.level,
                        computername,
                    );
                }
            }
            result_state.rule_title_path_map.insert(
                detect_info.ruletitle.to_owned(),
                detect_info.rule_path.to_owned(),
            );

            countup_aggregation(
                &mut result_state.detect_counts_by_date_and_level,
                &detect_info.level,
                &format_time(
                    &detect_info.detected_time,
                    true,
                    &output_option.time_format_options,
                ),
            );
            countup_aggregation(
                &mut result_state.detect_counts_by_rule_and_level,
                &detect_info.level,
                &detect_info.ruletitle,
            );
            let level_index = detect_info.level.index();
            result_state.total_detect_counts_by_level[level_index] += 1;
        }
    }
}
/// Prints everything that follows the timeline itself: the rule author table, the detection
/// frequency timeline (if requested), and the results summary (event counts, detection counts
/// per level/date/computer/rule). Also accumulates the same content for the HTML report if enabled.
pub fn output_result_summary(
    stored_static: &StoredStatic,
    output_writer: &mut OutputWriter,
    result_state: &ResultOutputState,
) {
    if output_writer.display_flag {
        println!();
    }

    let terminal_width = match terminal_size() {
        Some((Width(w), _)) => w as usize,
        None => 100,
    };

    let output_option = stored_static.output_option.as_ref().unwrap();
    if !output_option.no_summary && !result_state.rule_author_counter.is_empty() {
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Rule Authors:",
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " ",
            true,
        )
        .ok();

        println!();
        let table_column_num = if terminal_width <= 105 {
            2
        } else if terminal_width < 140 {
            3
        } else if terminal_width < 175 {
            4
        } else if terminal_width <= 210 {
            5
        } else {
            6
        };
        output_detected_rule_authors(&result_state.rule_author_counter, table_column_num);
    }

    println!();
    if output_option.visualize_timeline {
        _print_timeline_hist(&result_state.timestamps, terminal_width, 3);
        println!();
    }

    let mut html_output_stock = Nested::<String>::new();
    if !output_option.no_summary {
        output_writer.disp_wtr_buf.clear();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Results Summary:",
            false,
        )
        .ok();

        if let Some(timeline_start_time) = result_state.timeline_start_time {
            output_and_data_stack_for_html(
                &format!(
                    "First timestamp: {}",
                    utils::format_time(
                        &timeline_start_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
        }
        if let Some(timeline_end_time) = result_state.timeline_end_time {
            output_and_data_stack_for_html(
                &format!(
                    "Last timestamp: {}",
                    utils::format_time(
                        &timeline_end_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
            println!();
        }
        if let Some(detect_starttime) = result_state.detect_starttime {
            output_and_data_stack_for_html(
                &format!(
                    "First detection: {}",
                    utils::format_time(
                        &detect_starttime,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
        }
        if let Some(detect_endtime) = result_state.detect_endtime {
            output_and_data_stack_for_html(
                &format!(
                    "Last detection: {}",
                    utils::format_time(
                        &detect_endtime,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ),
                "Results Summary {#results_summary}",
                &stored_static.html_report_flag,
            );
            println!();
        }

        let reduced_record_cnt: u128 =
            result_state.record_cnt - result_state.detected_record_idset.len() as u128;
        let reduced_percent = if result_state.record_cnt == 0 {
            0 as f64
        } else {
            (reduced_record_cnt as f64) / (result_state.record_cnt as f64) * 100.0
        };
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            "Events with hits",
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            "Total events",
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            ": ",
            false,
        )
        .ok();
        let saved_alerts_output =
            (result_state.record_cnt - reduced_record_cnt).to_formatted_string(&Locale::en);
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(255, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &saved_alerts_output,
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " / ",
            false,
        )
        .ok();

        let all_record_output = result_state.record_cnt.to_formatted_string(&Locale::en);
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 255)),
                stored_static.common_options.no_color,
            ),
            &all_record_output,
            false,
        )
        .ok();
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            " (",
            false,
        )
        .ok();
        let reduction_output = format!(
            "Data reduction: {} events ({:.2}%)",
            reduced_record_cnt.to_formatted_string(&Locale::en),
            reduced_percent
        );
        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(
                Some(Color::Rgb(0, 255, 0)),
                stored_static.common_options.no_color,
            ),
            &reduction_output,
            false,
        )
        .ok();

        write_color_buffer(
            &output_writer.display_writer,
            get_writable_color(None, stored_static.common_options.no_color),
            ")",
            true,
        )
        .ok();
        if stored_static.enable_recover_records {
            write_color_buffer(
                &output_writer.display_writer,
                get_writable_color(
                    Some(Color::Rgb(0, 255, 255)),
                    stored_static.common_options.no_color,
                ),
                "Recovered records",
                false,
            )
            .ok();
            write_color_buffer(
                &output_writer.display_writer,
                get_writable_color(None, stored_static.common_options.no_color),
                ": ",
                false,
            )
            .ok();
            let recovered_record_output = result_state
                .recover_record_cnt
                .to_formatted_string(&Locale::en);
            write_color_buffer(
                &output_writer.display_writer,
                get_writable_color(
                    Some(Color::Rgb(0, 255, 255)),
                    stored_static.common_options.no_color,
                ),
                &recovered_record_output,
                true,
            )
            .ok();
        }
        println!();

        if stored_static.html_report_flag {
            html_output_stock.push(format!("- Events with hits: {}", &saved_alerts_output));
            html_output_stock.push(format!("- Total events analyzed: {}", &all_record_output));
            html_output_stock.push(format!("- {reduction_output}"));
            html_output_stock.push(format!(
                "- Recovered events analyzed: {}",
                &result_state
                    .recover_record_cnt
                    .to_formatted_string(&Locale::en)
            ));
        }

        let color_map = create_output_color_map(stored_static.common_options.no_color);
        _print_unique_results(
            &result_state.total_detect_counts_by_level,
            &result_state.unique_detect_counts_by_level,
            (
                CompactString::from("Total | Unique"),
                CompactString::from("detections"),
            ),
            &color_map,
            &mut html_output_stock,
            stored_static.html_report_flag,
        );
        println!();
        if let Some(timeline_start_time) = result_state.timeline_start_time {
            let ts = format!(
                "First timestamp: {}",
                format_time(
                    &timeline_start_time,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
        }
        if let Some(timeline_end_time) = result_state.timeline_end_time {
            let ts = format!(
                "Last timestamp: {}",
                format_time(
                    &timeline_end_time,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
            println!();
        }
        if let Some(detect_starttime) = result_state.detect_starttime {
            let ts = format!(
                "First detection: {}",
                format_time(
                    &detect_starttime,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
        }
        if let Some(detect_endtime) = result_state.detect_endtime {
            let ts = format!(
                "Last detection: {}",
                format_time(
                    &detect_endtime,
                    false,
                    &stored_static
                        .output_option
                        .as_ref()
                        .unwrap()
                        .time_format_options
                )
            );
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                ts.as_str(),
                true,
            )
            .ok();
            println!();
        }

        _print_detection_summary_by_date(
            &result_state.detect_counts_by_date_and_level,
            &color_map,
            &mut html_output_stock,
            stored_static,
        );
        println!();
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }

        _print_detection_summary_by_computer(
            &result_state.detect_counts_by_computer_and_level,
            &color_map,
            &mut html_output_stock,
            stored_static,
        );
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }

        _print_detection_summary_tables(
            &result_state.detect_counts_by_rule_and_level,
            &color_map,
            (
                &result_state.rule_title_path_map,
                &result_state.detect_rule_authors,
            ),
            &mut html_output_stock,
            stored_static,
            cmp::min((terminal_width / 2) - 15, 200),
        );
        println!();
        if stored_static.html_report_flag {
            html_output_stock.push("");
        }
    }
    if stored_static.html_report_flag {
        _output_html_computer_by_mitre_attck(&mut html_output_stock);
        htmlreport::add_md_data("Results Summary {#results_summary}", html_output_stock);
    }
}
fn _get_table_color(
    color_map: &HashMap<LEVEL, Colors>,
    level: &LEVEL,
) -> Option<comfy_table::Color> {
    let mut color = None;
    if let Some(c) = color_map.get(level) {
        color = Some(c.table_color);
    }
    color
}
/// Prints the detection frequency timeline (a sparkline histogram of detection timestamps with
/// time markers) to stdout. Requires at least 5 events to render.
fn _print_timeline_hist(timestamps: &[i64], length: usize, side_margin_size: usize) {
    if timestamps.is_empty() {
        return;
    }

    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    if timestamps.len() < 5 {
        writeln!(
            wtr,
            "Detection Frequency Timeline could not be displayed as there needs to be more than 5 events.",
        )
        .ok();
        buf_wtr.print(&wtr).ok();
        return;
    }

    let title = "Detection Frequency Timeline";
    let header_row_space = (length - title.len()) / 2;
    writeln!(wtr, "{}{}", " ".repeat(header_row_space), title).ok();
    println!();

    let timestamp_marker_max = if timestamps.len() < 2 {
        0
    } else {
        timestamps.len() - 2
    };
    let marker_num = min(timestamp_marker_max, 18);

    let (header_raw, footer_raw) =
        build_time_markers(timestamps, marker_num, length - (side_margin_size * 2));
    let sparkline = build_sparkline(timestamps, length - (side_margin_size * 2), 5_usize);
    for header_str in header_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), header_str).ok();
    }
    for line in sparkline.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), line).ok();
    }
    for footer_str in footer_raw.lines() {
        writeln!(wtr, "{}{}", " ".repeat(side_margin_size - 1), footer_str).ok();
    }

    buf_wtr.print(&wtr).ok();
}
/// Increments the counter for `entry_key` in the inner map for `level`, falling back to the
/// UNDEFINED level's map if the level has no entry.
fn countup_aggregation(
    count_map: &mut HashMap<LEVEL, HashMap<CompactString, i128>>,
    level: &LEVEL,
    entry_key: &str,
) {
    let mut detect_counts_by_rules = count_map
        .get(level)
        .unwrap_or_else(|| count_map.get(&LEVEL::UNDEFINED).unwrap())
        .to_owned();
    *detect_counts_by_rules.entry(entry_key.into()).or_insert(0) += 1;
    count_map.insert(level.clone(), detect_counts_by_rules);
}
/// Prints the total and unique detection counts (overall and per level, with percentages) to
/// stdout, and accumulates the same information for the HTML report when enabled.
pub(crate) fn _print_unique_results(
    counts_by_level: &[u128],
    unique_counts_by_level: &[u128],
    head_and_tail_word: (CompactString, CompactString),
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    html_output_flag: bool,
) {
    // The counts are stored in ascending level order, but levels are displayed from highest to
    // lowest, so iterate over them in reverse.
    let mut counts_by_level_rev = counts_by_level.iter().rev();
    let mut unique_counts_by_level_rev = unique_counts_by_level.iter().rev();

    let total_count = counts_by_level.iter().sum::<u128>();
    let unique_total_count = unique_counts_by_level.iter().sum::<u128>();
    // Output the totals across all levels first.
    write_color_buffer(
        &BufferWriter::stdout(ColorChoice::Always),
        None,
        &format!(
            "{} {}: {} | {}",
            head_and_tail_word.0,
            head_and_tail_word.1,
            total_count.to_formatted_string(&Locale::en),
            unique_total_count.to_formatted_string(&Locale::en)
        ),
        true,
    )
    .ok();

    let mut total_detect_md = vec!["- Total detections:".to_string()];
    let mut unique_detect_md = vec!["- Unique detections:".to_string()];

    for level_name in LEVEL::iter().rev() {
        if level_name == LEVEL::UNDEFINED {
            continue;
        }
        let count_by_level = *counts_by_level_rev.next().unwrap();
        let unique_count_by_level = *unique_counts_by_level_rev.next().unwrap();
        let percent = if total_count == 0 {
            0 as f64
        } else {
            (count_by_level as f64) / (total_count as f64) * 100.0
        };
        let unique_percent = if unique_total_count == 0 {
            0 as f64
        } else {
            (unique_count_by_level as f64) / (unique_total_count as f64) * 100.0
        };
        if html_output_flag {
            total_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name.to_full(),
                count_by_level.to_formatted_string(&Locale::en),
                percent
            ));
            unique_detect_md.push(format!(
                "    - {}: {} ({:.2}%)",
                level_name.to_full(),
                unique_count_by_level.to_formatted_string(&Locale::en),
                unique_percent
            ));
        }
        let output_raw_str = format!(
            "{} {} {}: {} ({:.2}%) | {} ({:.2}%)",
            head_and_tail_word.0,
            level_name.to_full(),
            head_and_tail_word.1,
            count_by_level.to_formatted_string(&Locale::en),
            percent,
            unique_count_by_level.to_formatted_string(&Locale::en),
            unique_percent
        );
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            _get_output_color(color_map, &level_name),
            &output_raw_str,
            true,
        )
        .ok();
    }
    if html_output_flag {
        html_output_stock.extend(total_detect_md.iter());
        html_output_stock.extend(unique_detect_md.iter());
    }
}
/// Output the date with the highest detection count for each level.
fn _print_detection_summary_by_date(
    detect_counts_by_date: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let output_header = "Dates with most total detections:";
    write_color_buffer(&buf_wtr, None, output_header, true).ok();

    if stored_static.html_report_flag {
        html_output_stock.push(format!("- {output_header}"));
    }
    for (i, level) in LEVEL::iter().rev().enumerate() {
        if level == LEVEL::UNDEFINED {
            continue;
        }
        // An inner map was inserted for every level when ResultOutputState was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_day = detect_counts_by_date.get(&level).unwrap();
        let mut max_detect_str = CompactString::default();
        let mut max_date: Option<&CompactString> = None;
        let mut tmp_cnt: i128 = 0;
        let mut exist_max_data = false;
        for (date, cnt) in detections_by_day {
            // On a tie, pick the lexicographically-smallest date string so the
            // choice is deterministic rather than HashMap-iteration-dependent.
            // (The key is the already-formatted date, so this is lexical, not
            // necessarily chronological under non-ISO date formats — fine, since
            // only determinism matters here.)
            if *cnt > tmp_cnt || (*cnt == tmp_cnt && exist_max_data && Some(date) < max_date) {
                exist_max_data = true;
                max_date = Some(date);
                tmp_cnt = *cnt;
            }
        }
        if let Some(date) = max_date {
            max_detect_str =
                format!("{} ({})", date, tmp_cnt.to_formatted_string(&Locale::en)).into();
        }
        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, &level)))
            .ok();
        if !exist_max_data {
            max_detect_str = "n/a".into();
        }
        let output_str = format!("{}: {}", level.to_full(), &max_detect_str);
        write!(wtr, "{output_str}").ok();
        // Print a ", " separator after every level except the last displayed one (count() - 2
        // because UNDEFINED, the final item of the reversed iteration, is skipped).
        if i != LEVEL::iter().count() - 2 {
            wtr.set_color(ColorSpec::new().set_fg(None)).ok();
            write!(wtr, ", ").ok();
        }
        if stored_static.html_report_flag {
            html_output_stock.push(format!("    - {output_str}"));
        }
    }
    buf_wtr.print(&wtr).ok();
}
/// Output the top 5 computers with the most unique detections for each level (the HTML report
/// gets the full list).
fn _print_detection_summary_by_computer(
    detect_counts_by_computer: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();

    writeln!(wtr, "Top 5 computers with most unique detections:").ok();
    for level in LEVEL::iter().rev() {
        if level == LEVEL::UNDEFINED {
            continue;
        }
        // An inner map was inserted for every level when ResultOutputState was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_computer = detect_counts_by_computer.get(&level).unwrap();
        let mut result_vec = Nested::<String>::new();
        // Exclude entries where the computer name is "-" from the aggregation.
        let mut sorted_detections: Vec<(&CompactString, &i128)> = detections_by_computer
            .iter()
            .filter(|a| a.0.as_str() != "-")
            .collect();

        // Sort by count descending, then by name ascending so equal-count
        // entries have a deterministic (rather than HashMap-iteration-dependent)
        // order.
        sorted_detections.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        // For HTML output, display all computer names.
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### Computers with most unique {} detections: {{#computers_with_most_unique_{}_detections}}",
                level.to_full(),
                level.to_full(),
            ));
            for x in sorted_detections.iter() {
                html_output_stock.push(format!(
                    "- {} ({})",
                    html_escape_value(x.0),
                    x.1.to_formatted_string(&Locale::en)
                ));
            }
            html_output_stock.push("");
        }
        for x in sorted_detections.iter().take(5) {
            result_vec.push(format!(
                "{} ({})",
                x.0,
                x.1.to_formatted_string(&Locale::en)
            ));
        }
        let result_str = if result_vec.is_empty() {
            "n/a".to_string()
        } else {
            result_vec.iter().collect::<Vec<_>>().join(", ")
        };

        wtr.set_color(ColorSpec::new().set_fg(_get_output_color(color_map, &level)))
            .ok();
        writeln!(wtr, "{}: {}", level.to_full(), &result_str).ok();
    }
    buf_wtr.print(&wtr).ok();
}
/// Output the rules with the most detections for each level in table format (top 5 per level;
/// the HTML report gets the full list). Rule titles longer than `limit_num` characters are
/// truncated with "...".
fn _print_detection_summary_tables(
    detect_counts_by_rule_and_level: &HashMap<LEVEL, HashMap<CompactString, i128>>,
    color_map: &HashMap<LEVEL, Colors>,
    (rule_title_path_map, rule_detect_author_map): (
        &HashMap<CompactString, CompactString>,
        &HashMap<CompactString, CompactString>,
    ),
    html_output_stock: &mut Nested<String>,
    stored_static: &StoredStatic,
    limit_num: usize,
) {
    let buf_wtr = BufferWriter::stdout(ColorChoice::Always);
    let mut wtr = buf_wtr.buffer();
    wtr.set_color(ColorSpec::new().set_fg(None)).ok();
    let mut output = vec![];
    let mut col_color = vec![];
    for level in LEVEL::iter().rev() {
        if level == LEVEL::UNDEFINED {
            continue;
        }

        let mut col_output: Nested<String> = Nested::<String>::new();
        col_output.push(format!("Top {} alerts:", level.to_full()));

        col_color.push(_get_table_color(color_map, &level));

        // An inner map was inserted for every level when ResultOutputState was initialized, so the
        // lookup is guaranteed to be Some and unwrap is called directly.
        let detections_by_computer = detect_counts_by_rule_and_level.get(&level).unwrap();
        let mut sorted_detections: Vec<(&CompactString, &i128)> =
            detections_by_computer.iter().collect();

        // Sort by count descending, then by name ascending so equal-count
        // entries have a deterministic (rather than HashMap-iteration-dependent)
        // order.
        sorted_detections.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        // For HTML output, list every rule rather than only the top five.
        if stored_static.html_report_flag {
            html_output_stock.push(format!(
                "### All {} alerts: {{#all_{}_alerts}}",
                level.to_full(),
                level.to_full()
            ));
            let rule_path = stored_static.output_option.as_ref().unwrap().rules.clone();
            let rule_encoded =
                check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "encoded_rules.yml", true)
                    .unwrap();
            let is_encoded_rule = rule_encoded.exists() && rule_encoded.to_path_buf() == rule_path;
            for x in sorted_detections.iter() {
                let not_found_str = CompactString::from_str("<Not Found Path>").unwrap();
                let rule_path = rule_title_path_map.get(x.0).unwrap_or(&not_found_str);
                if is_encoded_rule {
                    html_output_stock.push(format!(
                        "- {} ({}) - {}",
                        html_escape_value(x.0),
                        x.1.to_formatted_string(&Locale::en),
                        html_escape_value(
                            rule_detect_author_map
                                .get(rule_path)
                                .unwrap_or(&not_found_str)
                        )
                    ));
                } else {
                    html_output_stock.push(format!(
                        "- [{}]({}) ({}) - {}",
                        html_escape_value(x.0),
                        &rule_path.replace('\\', "/"),
                        x.1.to_formatted_string(&Locale::en),
                        html_escape_value(
                            rule_detect_author_map
                                .get(rule_path)
                                .unwrap_or(&not_found_str)
                        )
                    ));
                }
            }
            html_output_stock.push("");
        }

        let take_cnt = 5;
        for x in sorted_detections.iter().take(take_cnt) {
            let output_title = if x.0.len() > limit_num - 3 {
                format!("{}...", &x.0[..(limit_num - 3)])
            } else {
                x.0.to_string()
            };
            col_output.push(format!(
                "{output_title} ({})",
                x.1.to_formatted_string(&Locale::en)
            ));
        }
        let na_cnt = if sorted_detections.len() > take_cnt {
            0
        } else {
            take_cnt - sorted_detections.len()
        };
        for _x in 0..na_cnt {
            col_output.push("n/a");
        }
        output.push(col_output);
    }

    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    let horizontal_line_char = tb.style(TableComponent::HorizontalLines).unwrap();
    let top_border_char = tb.style(TableComponent::TopBorder).unwrap();
    for x in 0..output.len() / 2 {
        tb.add_row(vec![
            Cell::new(&output[2 * x][0]).fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(&output[2 * x + 1][0])
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ])
        .set_style(TableComponent::MiddleIntersections, horizontal_line_char)
        .set_style(TableComponent::TopBorderIntersections, top_border_char)
        .set_style(
            TableComponent::BottomBorderIntersections,
            horizontal_line_char,
        );
        tb.add_row(vec![
            Cell::new(output[2 * x].iter().skip(1).join("\n"))
                .fg(col_color[2 * x].unwrap_or(comfy_table::Color::Reset)),
            Cell::new(output[2 * x + 1].iter().skip(1).join("\n"))
                .fg(col_color[2 * x + 1].unwrap_or(comfy_table::Color::Reset)),
        ]);
    }
    println!("{tb}");
}
/// Prints a table of the detected rule authors and the number of their rules that produced
/// detections, laid out over `table_column_num` columns.
fn output_detected_rule_authors(
    rule_author_counter: &HashMap<CompactString, i128>,
    table_column_num: usize,
) {
    let mut sorted_authors: Vec<(&CompactString, &i128)> = rule_author_counter.iter().collect();

    // Count descending, then author name ascending for a deterministic order
    // among equal-count authors.
    sorted_authors.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let authors_num = sorted_authors.len();
    let div = if authors_num <= table_column_num {
        1
    } else if !authors_num.is_multiple_of(4) {
        authors_num / table_column_num + 1
    } else {
        authors_num / table_column_num
    };
    let mut tb = Table::new();
    tb.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_style(TableComponent::VerticalLines, ' ');
    let mut stored_by_column = vec![];
    let horizontal_line_char = tb.style(TableComponent::HorizontalLines).unwrap();
    let top_border_char = tb.style(TableComponent::TopBorder).unwrap();
    for x in 0..table_column_num {
        let mut tmp = Vec::new();
        for y in 0..div {
            if y * table_column_num + x < sorted_authors.len() {
                // Limit length to 27 to prevent the table from wrapping
                let filter_author = if sorted_authors[y * table_column_num + x].0.len() <= 27 {
                    sorted_authors[y * table_column_num + x].0.to_string()
                } else {
                    format!("{}...", &sorted_authors[y * table_column_num + x].0[0..24])
                };
                tmp.push(format!(
                    "{} ({})",
                    filter_author,
                    sorted_authors[y * table_column_num + x].1
                ));
            }
        }
        if !tmp.is_empty() {
            stored_by_column.push(tmp);
        }
    }
    let mut output = vec![];
    for col_data in stored_by_column {
        output.push(col_data.join("\n"));
    }
    if !output.is_empty() {
        tb.add_row(output)
            .set_style(TableComponent::MiddleIntersections, horizontal_line_char)
            .set_style(TableComponent::TopBorderIntersections, top_border_char)
            .set_style(
                TableComponent::BottomBorderIntersections,
                horizontal_line_char,
            );
    }
    println!("{tb}");
}
/// Extracts the individual author names from a rule's author string and returns them as an
/// array.
fn extract_author_name(author: &str) -> Nested<String> {
    let mut ret = Nested::<String>::new();
    for author in author.split(',').map(|s| {
        // Keep only the part before '(': a parenthesized remark after a name is a description,
        // not part of the name. Double and single quotes are stripped from the names below.
        s.split('(').next().unwrap_or_default().to_string()
    }) {
        ret.extend(author.split(';'));
    }

    ret.iter()
        .map(|r| {
            r.split('/')
                .map(|p| p.trim().replace(['"', '\''], ""))
                .collect::<String>()
        })
        .collect()
}

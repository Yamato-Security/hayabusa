use crate::detections::configs::{Action, EventInfoConfig, StoredStatic};
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::AlertMessage;
use crate::detections::utils::{
    self, get_writable_color, make_ascii_titlecase, write_color_buffer,
};
use crate::timeline::search::search_result_dsp_msg;
use comfy_table::ColumnConstraint::LowerBoundary;
use comfy_table::ColumnConstraint::UpperBoundary;
use comfy_table::Width::Fixed;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use compact_str::CompactString;
use csv::WriterBuilder;
use downcast_rs::__std::process;
use nested::Nested;
use num_format::{Locale, ToFormattedString};
use std::cmp;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use termcolor::{BufferWriter, Color, ColorChoice};
use terminal_size::Width;
use terminal_size::terminal_size;

use super::computer_metrics;
use super::metrics::EventMetrics;
use super::search::EventSearch;
use crate::timeline::config_critical_systems::ConfigCriticalSystems;
use crate::timeline::extract_base64::{output_all, process_evtx_record_infos};
use crate::timeline::log_metrics::LogMetrics;
use hashbrown::HashSet;
use itertools::Itertools;

/// Maximum width of the "Event" column in the `eid-metrics` table. Uses saturating subtraction so a
/// terminal narrower than 55 columns does not underflow `terminal_width - 55`: previously that
/// panicked with "attempt to subtract with overflow" in overflow-checked (dev/test) builds and
/// silently wrapped to a huge value in release builds, defeating the 45-character floor and letting
/// the table overflow the very narrow terminals the floor was meant to handle. (#1817)
fn eid_metrics_event_col_width(terminal_width: u16) -> u16 {
    cmp::max(terminal_width.saturating_sub(55), 45)
}

/// Aggregated state for the non-detection commands (eid-metrics, logon-summary, log-metrics,
/// search, extract-base64, config-critical-systems, computer-metrics). Records are fed in
/// incrementally via `start()` (except for computer-metrics, which fills `stats.stats_computer`
/// via `computer_metrics::countup_event_by_computer()`) and the collected results are rendered
/// later by the `*_dsp_msg` methods. The detection commands csv-timeline/json-timeline also use
/// this struct to track the total record count and the first/last event timestamps.
#[derive(Debug, Clone)]
pub struct Timeline {
    pub total_record_cnt: usize,
    pub stats: EventMetrics,
    pub event_search: EventSearch,
    pub extracted_base64_records: Vec<Vec<String>>,
    pub config_critical_systems: ConfigCriticalSystems,
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Timeline {
    pub fn new() -> Timeline {
        let statistic = EventMetrics::default();
        let search = EventSearch::new(CompactString::default(), HashSet::new());
        let config_critical_systems = ConfigCriticalSystems::new();
        Timeline {
            total_record_cnt: 0,
            stats: statistic,
            event_search: search,
            extracted_base64_records: vec![],
            config_critical_systems,
        }
    }

    /// Dispatches a batch of loaded event records to the aggregator that matches the currently
    /// running command. Called once per record chunk while the log files are being read; the
    /// accumulated results are output afterwards by the corresponding `*_dsp_msg` method.
    pub fn start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        if stored_static.metrics_flag {
            self.stats.evt_stats_start(
                records,
                stored_static,
                (
                    &stored_static.include_computer,
                    &stored_static.exclude_computer,
                ),
            );
        } else if stored_static.logon_summary_flag {
            self.stats.logon_stats_start(records, stored_static);
        } else if stored_static.log_metrics_flag {
            self.stats.logfile_stats_start(records, stored_static);
        } else if stored_static.search_flag {
            self.event_search.search_start(records, stored_static);
        } else if stored_static.extract_base64_flag {
            if let Action::ExtractBase64(opt) = &stored_static.config.action.as_ref().unwrap() {
                let records = process_evtx_record_infos(records, &opt.time_format_options);
                self.extracted_base64_records.extend(records);
            }
        } else if let Action::ConfigCriticalSystems(_) =
            &stored_static.config.action.as_ref().unwrap()
        {
            self.config_critical_systems.process(records);
        } else if matches!(
            stored_static.config.action.as_ref().unwrap(),
            Action::DfirTimeline(_)
        ) {
            self.stats.stats_time_cnt(records, stored_static);
        }
    }

    /// Output the computers found by the config-critical-systems command, grouped by system type.
    pub fn config_critical_systems_dsp_msg(&mut self, no_color: bool) {
        self.config_critical_systems.output_computers(no_color);
    }

    /// Function to output the statistics message for the eid-metrics command.
    pub fn tm_stats_dsp_msg(
        &mut self,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) {
        // Create the output message.
        let mut summary_msgs: Nested<String> = Nested::new();
        let total_event_record = format!(
            "\n\nTotal Event Records: {}\n",
            self.total_record_cnt.to_formatted_string(&Locale::en)
        );
        let mut wtr;
        let target;

        match &stored_static.config.action.as_ref().unwrap() {
            Action::EidMetrics(option) => {
                if option.input_args.filepath.is_some() {
                    summary_msgs.push(format!("Evtx File Path: {}", self.stats.filepath));
                }
                summary_msgs.push(total_event_record);
                if let Some(start_time) = self.stats.start_time {
                    summary_msgs.push(format!(
                        "First Timestamp: {}",
                        utils::format_time(
                            &start_time,
                            false,
                            &stored_static
                                .output_option
                                .as_ref()
                                .unwrap()
                                .time_format_options
                        )
                    ));
                }
                if let Some(end_time) = self.stats.end_time {
                    summary_msgs.push(format!(
                        "Last Timestamp: {}\n",
                        utils::format_time(
                            &end_time,
                            false,
                            &stored_static
                                .output_option
                                .as_ref()
                                .unwrap()
                                .time_format_options
                        )
                    ));
                }
                wtr = if let Some(csv_path) = option.output.as_ref() {
                    // Output to file.
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

        let header = vec!["Total", "%", "Channel", "ID", "Event"];
        let mut header_cells = vec![];
        for header_str in &header {
            header_cells.push(Cell::new(header_str).set_alignment(CellAlignment::Center));
        }
        if let Some(ref mut writer) = wtr {
            writer.write_record(&header).ok();
        }

        let mut stats_tb = Table::new();
        stats_tb
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);

        stats_tb.set_header(header_cells);

        // Sort by aggregated count in descending order.
        let mut sorted_entries: Vec<_> = self.stats.stats_list.iter().collect();
        sorted_entries.sort_by(|x, y| y.1.cmp(x.1));

        // Generate an output message for each Event ID.
        let stats_msgs: Nested<Vec<CompactString>> =
            self.tm_stats_set_msg(sorted_entries, event_timeline_config, stored_static);

        for msg_line in summary_msgs.iter() {
            let mut parts = msg_line.splitn(2, ':');
            let first_part = parts.next().unwrap_or_default();
            let second_part = format!(": {}", parts.next().unwrap_or_default());
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(
                    Some(Color::Rgb(0, 255, 0)),
                    stored_static.common_options.no_color,
                ),
                first_part,
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                second_part.as_str(),
                true,
            )
            .ok();
        }
        if wtr.is_some() {
            for msg in stats_msgs.iter() {
                if let Some(ref mut writer) = wtr {
                    writer.write_record(msg.iter().map(|x| x.as_str())).ok();
                }
            }
        }
        stats_tb.add_rows(stats_msgs.iter());
        let terminal_width = match terminal_size() {
            Some((Width(width), _)) => width,
            None => 100,
        };

        let constraints = [
            LowerBoundary(Fixed(7)),  // Minimum number of characters for "Total"
            UpperBoundary(Fixed(9)),  // Maximum number of characters for "percent"
            UpperBoundary(Fixed(20)), // Maximum number of characters for "Channel"
            UpperBoundary(Fixed(12)), // Maximum number of characters for "ID"
            UpperBoundary(Fixed(eid_metrics_event_col_width(terminal_width))), // Maximum number of characters for "Event"
        ];
        for (column_index, column) in stats_tb.column_iter_mut().enumerate() {
            let constraint = constraints.get(column_index).unwrap();
            column.set_constraint(*constraint);
        }
        if wtr.is_none() {
            println!("{stats_tb}");
        }
    }

    /// Function to output the logon statistics message.
    pub fn tm_logon_stats_dsp_msg(&mut self, stored_static: &StoredStatic) {
        // Create the output message.
        let mut summary_msgs: Vec<String> = Vec::new();
        let total_event_record = format!(
            "\n\nTotal Event Records: {}\n",
            self.total_record_cnt.to_formatted_string(&Locale::en)
        );
        if let Action::LogonSummary(logon_summary_option) =
            &stored_static.config.action.as_ref().unwrap()
        {
            if logon_summary_option.input_args.filepath.is_some() {
                summary_msgs.push(format!("Evtx File Path: {}", self.stats.filepath));
            }
            summary_msgs.push(total_event_record);

            if let Some(start_time) = self.stats.start_time {
                summary_msgs.push(format!(
                    "First Timestamp: {}",
                    utils::format_time(
                        &start_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ));
            }
            if let Some(end_time) = self.stats.end_time {
                summary_msgs.push(format!(
                    "Last Timestamp: {}\n",
                    utils::format_time(
                        &end_time,
                        false,
                        &stored_static
                            .output_option
                            .as_ref()
                            .unwrap()
                            .time_format_options
                    )
                ));
            }

            for msg_line in summary_msgs.iter() {
                let mut parts = msg_line.splitn(2, ':');
                let first_part = parts.next().unwrap_or_default();
                let second_part = format!(": {}", parts.next().unwrap_or_default());
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    get_writable_color(
                        Some(Color::Rgb(0, 255, 0)),
                        stored_static.common_options.no_color,
                    ),
                    first_part,
                    false,
                )
                .ok();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    second_part.as_str(),
                    true,
                )
                .ok();
            }

            self.tm_loginstats_tb_set_msg(
                &logon_summary_option.output,
                stored_static.common_options.no_color,
                stored_static,
            );
        }
    }

    /// Generates one output row per (event ID, channel) pair: count, percentage, abbreviated
    /// channel, event ID and event title.
    fn tm_stats_set_msg(
        &self,
        sorted_entries: Vec<(&(CompactString, CompactString), &usize)>,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) -> Nested<Vec<CompactString>> {
        let mut msgs: Nested<Vec<CompactString>> = Nested::new();

        for ((event_id, channel), event_cnt) in sorted_entries.iter() {
            // Calculate the percentage of counts.
            let rate: f32 = **event_cnt as f32 / self.stats.total as f32;
            let fmted_channel = channel;

            // Create one line of the output message. The event title is only known for
            // channel/event-ID pairs registered in channel_eid_info.txt; everything else is
            // reported as "Unknown".
            let ch = replace_channel_abbr(stored_static, fmted_channel);

            if event_timeline_config
                .get_event_id(fmted_channel, event_id)
                .is_some()
            {
                msgs.push(vec![
                    CompactString::from(format!("{event_cnt}")),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0).into(),
                    ch.trim().into(),
                    event_id.to_owned(),
                    CompactString::from(
                        &event_timeline_config
                            .get_event_id(fmted_channel, event_id)
                            .unwrap()
                            .event_title,
                    ),
                ]);
            } else {
                msgs.push(vec![
                    CompactString::from(format!("{event_cnt}")),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0).into(),
                    ch.trim().into(),
                    event_id.replace('\"', "").into(),
                    CompactString::from("Unknown"),
                ]);
            }
        }
        msgs
    }

    /// Generate output message for login statistics per user.
    fn tm_loginstats_tb_set_msg(
        &self,
        output: &Option<PathBuf>,
        no_color: bool,
        stored_static: &StoredStatic,
    ) {
        if output.is_none() {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(Some(Color::Rgb(0, 255, 0)), no_color),
                "Logon Summary:",
                true,
            )
            .ok();
            write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", false).ok();
        }
        if self.stats.stats_login_list.is_empty() {
            let mut login_msgs: Vec<String> = Vec::new();
            login_msgs.push("-----------------------------------------".to_string());
            login_msgs.push("|     No logon events were detected.    |".to_string());
            login_msgs.push("-----------------------------------------\n".to_string());
            for msg_line in login_msgs.iter() {
                println!("{msg_line}");
            }
        } else {
            self.tm_loginstats_tb_dsp_msg("successful", output, no_color, stored_static);
            if output.is_none() {
                println!("\n\n");
            }
            self.tm_loginstats_tb_dsp_msg("failed", output, no_color, stored_static);
        }
    }

    /// Output login statistics per user.
    fn tm_loginstats_tb_dsp_msg(
        &self,
        logon_res: &str,
        output: &Option<PathBuf>,
        no_color: bool,
        stored_static: &StoredStatic,
    ) {
        let header_column = make_ascii_titlecase(logon_res);
        // Successful logons show logon times; failed logons show attempt times.
        let (first_label, last_label) = if logon_res == "failed" {
            ("First Attempt", "Last Attempt")
        } else {
            ("First Logon", "Last Logon")
        };
        let header = vec![
            header_column.as_str(),
            first_label,
            last_label,
            "Event",
            "Target Account",
            "Target Domain",
            "Target Computer",
            "Logon Type",
            "Source Account",
            "Source Domain",
            "Source Computer",
            "Source IP Address",
        ];
        let target;
        if output.is_none() {
            let msg = format!("{} Logons:", make_ascii_titlecase(logon_res));
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(Some(Color::Rgb(0, 255, 0)), no_color),
                msg.as_str(),
                true,
            )
            .ok();
            write_color_buffer(&BufferWriter::stdout(ColorChoice::Always), None, "", false).ok();
        }
        let mut wtr = if let Some(csv_path) = output {
            let file_name = csv_path.as_path().display().to_string() + "-" + logon_res + ".csv";
            // Output to file.
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
        if let Some(ref mut writer) = wtr {
            writer.write_record(&header).ok();
        }

        let mut logins_stats_tb = Table::new();
        logins_stats_tb
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        // The terminal table only shows a subset of the columns (count, first/last time, event,
        // target account, target computer, source computer, source IP); the CSV has all of them.
        let header_ref = &header;
        logins_stats_tb.set_header([
            header_ref[0],
            header_ref[1],
            header_ref[2],
            header_ref[3],
            header_ref[4],
            header_ref[6],
            header_ref[10],
            header_ref[11],
        ]);
        // Index into the per-user [successful, failed] count/first/last arrays.
        let result_index = match logon_res {
            "successful" => 0,
            "failed" => 1,
            &_ => 0,
        };
        let tfo = &stored_static
            .output_option
            .as_ref()
            .unwrap()
            .time_format_options;
        // Sort by aggregated count in descending order.
        let mut sorted_entries: Vec<_> = self.stats.stats_login_list.iter().collect();
        sorted_entries.sort_by(|x, y| y.1.counts[result_index].cmp(&x.1.counts[result_index]));
        for (login_event, values) in &sorted_entries {
            // Do not display entries with a count of zero.
            if values.counts[result_index] == 0 {
                continue;
            } else {
                let vnum_str = values.counts[result_index].to_string();
                let first_str = match values.first[result_index] {
                    Some(timestamp) => utils::format_time(&timestamp, false, tfo).to_string(),
                    None => "-".to_string(),
                };
                let last_str = match values.last[result_index] {
                    Some(timestamp) => utils::format_time(&timestamp, false, tfo).to_string(),
                    None => "-".to_string(),
                };
                let record_data = vec![
                    vnum_str.as_str(),
                    first_str.as_str(),
                    last_str.as_str(),
                    login_event.channel.as_str(),
                    login_event.dst_user.as_str(),
                    login_event.dst_domain.as_str(),
                    login_event.hostname.as_str(),
                    login_event.logontype.as_str(),
                    login_event.src_user.as_str(),
                    login_event.src_domain.as_str(),
                    login_event.source_computer.as_str(),
                    login_event.source_ip.as_str(),
                ];
                if let Some(ref mut writer) = wtr {
                    writer.write_record(&record_data).ok();
                }
                let row = record_data;
                logins_stats_tb.add_row([
                    row[0], row[1], row[2], row[3], row[4], row[6], row[10], row[11],
                ]);
            }
        }
        // If there is no row data, display a message indicating no detections.
        if logins_stats_tb.row_iter().len() == 0 {
            println!(" No logon {logon_res} events were detected.");
        } else if output.is_none() {
            println!("{logins_stats_tb}");
        }
    }

    /// Output search results.
    pub fn search_dsp_msg(&mut self, stored_static: &StoredStatic) {
        if let Action::Search(search_summary_option) =
            &stored_static.config.action.as_ref().unwrap()
        {
            search_result_dsp_msg(&self.event_search, search_summary_option, stored_static);
        }
    }

    /// Output computer metrics results.
    pub fn computer_metrics_dsp_msg(&mut self, stored_static: &StoredStatic) {
        if let Action::ComputerMetrics(computer_metrics_option) =
            &stored_static.config.action.as_ref().unwrap()
        {
            if self.stats.stats_computer.is_empty() {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    Some(Color::Rgb(238, 102, 97)),
                    "\n\nNo matches found.",
                    true,
                )
                .ok();
            } else {
                println!();
                computer_metrics::computer_metrics_dsp_msg(
                    &self.stats.stats_computer,
                    &computer_metrics_option.output,
                );
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    get_writable_color(
                        Some(Color::Rgb(0, 255, 0)),
                        stored_static.common_options.no_color,
                    ),
                    "Total computers: ",
                    false,
                )
                .ok();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &self
                        .stats
                        .stats_computer
                        .len()
                        .to_formatted_string(&Locale::en),
                    true,
                )
                .ok();
            }
        }
    }

    /// Output the log-metrics results (one row per log file) as CSV or as a terminal table,
    /// sorted by event count in descending order.
    pub fn log_metrics_dsp_msg(&mut self, stored_static: &StoredStatic) {
        if let Action::LogMetrics(opt) = &stored_static.config.action.as_ref().unwrap() {
            let log_metrics = &mut self.stats.stats_logfile;
            log_metrics.sort_by(|a, b| a.event_count.cmp(&b.event_count).reverse());
            let header = vec![
                "Filename",
                "Computers",
                "Events",
                "First Timestamp",
                "Last Timestamp",
                "Channels",
                "Providers",
                "Size",
            ];
            if let Some(path) = &opt.output {
                let file = File::create(path).expect("Failed to create output file");
                let mut wrt = WriterBuilder::new().from_writer(file);
                let _ = wrt.write_record(header);
                for rec in &mut *log_metrics {
                    if let Some(row) = Self::create_record_array(rec, stored_static, " ¦") {
                        let _ = wrt.write_record(row);
                    }
                }
            } else {
                let mut tb = Table::new();
                tb.load_preset(UTF8_FULL)
                    .apply_modifier(UTF8_ROUND_CORNERS)
                    .set_content_arrangement(ContentArrangement::DynamicFullWidth)
                    .set_header(&header);
                for rec in &mut *log_metrics {
                    if let Some(row) = Self::create_record_array(rec, stored_static, "\n") {
                        tb.add_row(vec![
                            Cell::new(row[0].to_string()),
                            Cell::new(row[1].to_string()),
                            Cell::new(row[2].to_string()),
                            Cell::new(row[3].to_string()),
                            Cell::new(row[4].to_string()),
                            Cell::new(row[5].to_string()),
                            Cell::new(row[6].to_string()),
                            Cell::new(row[7].to_string()),
                        ]);
                    }
                }
                if log_metrics.is_empty() {
                    println!("No matches found.");
                } else {
                    println!("{tb}");
                }
            }
        }
    }

    /// Output the strings collected by the extract-base64 command. Output failures are reported
    /// according to the verbose/quiet-errors flags.
    pub fn extract_base64_dsp_msg(&mut self, stored_static: &StoredStatic) {
        match output_all(
            self.extracted_base64_records.clone(),
            stored_static.output_path.as_ref(),
            stored_static.common_options.no_color,
        ) {
            Ok(_) => {}
            Err(err) => {
                let errmsg = format!("Failed to output extracted base64 records. {err}");
                if stored_static.verbose_flag {
                    AlertMessage::alert(&errmsg).ok();
                }
                if !stored_static.quiet_errors_flag {
                    stored_static
                        .error_log_stack
                        .lock()
                        .unwrap()
                        .push(format!("[ERROR] {errmsg}"));
                }
            }
        }
    }

    /// Builds one log-metrics output row for a single log file. Returns `None` when the file's
    /// computers are dropped by the --include-computer / --exclude-computer filters. `sep` joins
    /// multi-value cells (computers, channels, providers) unless overridden by the multiline or
    /// tab-separator flags.
    fn create_record_array(
        rec: &LogMetrics,
        stored_static: &StoredStatic,
        sep: &str,
    ) -> Option<[String; 8]> {
        let include_computer = &stored_static.include_computer;
        let exclude_computer = &stored_static.exclude_computer;
        if !include_computer.is_empty()
            && rec
                .computers
                .iter()
                .all(|comp| !include_computer.contains(&CompactString::from(comp)))
        {
            return None;
        }
        if !exclude_computer.is_empty()
            && rec
                .computers
                .iter()
                .any(|comp| exclude_computer.contains(&CompactString::from(comp)))
        {
            return None;
        }
        let sep = if stored_static.multiline_flag {
            "\n"
        } else if stored_static.tab_separator_flag {
            "\t"
        } else {
            sep
        };
        let abbreviated_channels: Vec<String> = rec
            .channels
            .iter()
            .map(|ch| replace_channel_abbr(stored_static, &CompactString::from(ch)))
            .collect();
        let abbreviated_providers: Vec<String> = rec
            .providers
            .iter()
            .map(|ch| replace_provider_abbr(stored_static, &CompactString::from(ch)))
            .collect();
        Some([
            rec.filename.to_string(),
            rec.computers.iter().sorted().join(sep),
            rec.event_count.to_formatted_string(&Locale::en),
            utils::format_time(
                &rec.first_timestamp.unwrap_or_default(),
                false,
                &stored_static
                    .output_option
                    .as_ref()
                    .unwrap()
                    .time_format_options,
            )
            .into(),
            utils::format_time(
                &rec.last_timestamp.unwrap_or_default(),
                false,
                &stored_static
                    .output_option
                    .as_ref()
                    .unwrap()
                    .time_format_options,
            )
            .into(),
            abbreviated_channels.iter().sorted().join(sep),
            abbreviated_providers.iter().sorted().join(sep),
            rec.file_size.to_string(),
        ])
    }
}

/// Replaces a channel name with its abbreviation from channel_abbreviations.txt (looked up
/// case-insensitively, falling back to the original name), then shortens generic terms using
/// the abbreviations defined in generic_abbreviations.txt.
fn replace_channel_abbr(stored_static: &StoredStatic, fmted_channel: &CompactString) -> String {
    stored_static.generic_abbr_matcher.replace_all(
        stored_static
            .channel_abbr_config
            .get(&fmted_channel.to_ascii_lowercase())
            .unwrap_or(fmted_channel)
            .as_str(),
        &stored_static.generic_abbr_values,
    )
}

/// Replaces a provider name with its abbreviation from provider_abbreviations.txt (falling back
/// to the original name), then shortens generic terms using the abbreviations defined in
/// generic_abbreviations.txt.
fn replace_provider_abbr(stored_static: &StoredStatic, fmted_provider: &CompactString) -> String {
    stored_static.generic_abbr_matcher.replace_all(
        stored_static
            .provider_abbr_config
            .get(fmted_provider)
            .unwrap_or(fmted_provider),
        &stored_static.generic_abbr_values,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{read_to_string, remove_file},
        path::Path,
    };

    #[test]
    /// #1817: the eid-metrics "Event" column width must not underflow `terminal_width - 55` on a
    /// terminal narrower than 55 columns (previously panicked in debug builds and wrapped to a huge
    /// value in release, defeating the 45-character floor).
    fn test_eid_metrics_event_col_width() {
        assert_eq!(super::eid_metrics_event_col_width(0), 45); // would underflow with `- 55`
        assert_eq!(super::eid_metrics_event_col_width(40), 45); // narrow terminal
        assert_eq!(super::eid_metrics_event_col_width(100), 45); // 100-55=45, at the floor
        assert_eq!(super::eid_metrics_event_col_width(101), 46); // just above the floor
        assert_eq!(super::eid_metrics_event_col_width(200), 145);
    }

    use chrono::{DateTime, NaiveDateTime, Utc};
    use compact_str::CompactString;
    use hashbrown::{HashMap, HashSet};
    use nested::Nested;

    use crate::detections::configs::TimeFormatOptions;
    use crate::timeline::metrics::LoginEvent;
    use crate::{
        detections::{
            configs::{
                Action, ClobberOption, CommonOptions, Config, DetectCommonOption, EidMetricsOption,
                InputOption, LogonSummaryOption, StoredStatic, TimeRangeOption,
            },
            utils::create_rec_info,
        },
        timeline::timelines::Timeline,
    };

    fn create_dummy_stored_static(action: Action) -> StoredStatic {
        StoredStatic::create_static_data(Config {
            action: Some(action),
            debug: false,
        })
    }

    /// Test for the statistics aggregation of the logon-summary command.
    #[test]
    pub fn test_evt_logon_stats() {
        let mut dummy_stored_static =
            create_dummy_stored_static(Action::LogonSummary(LogonSummaryOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: None,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    json_input: false,
                    validate_checksums: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                },
                output: None,
                clobber_opt: ClobberOption { clobber: false },
                time_range: TimeRangeOption {
                    end_timeline: None,
                    start_timeline: None,
                },
                remove_duplicate_detections: false,
            }));
        dummy_stored_static.logon_summary_flag = true;
        let mut timeline = Timeline::default();

        // Test that logon_stats_start does nothing when there is no record information.
        timeline.stats.logon_stats_start(&[], &dummy_stored_static);

        // Test 1: When there is no target Timestamp information.
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
        let mut input_records = vec![];
        let alias_ch_record = serde_json::from_str(no_timestamp_record_str).unwrap();
        input_records.push(create_rec_info(
            alias_ch_record,
            "testpath".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));
        timeline
            .stats
            .logon_stats_start(&input_records, &dummy_stored_static);
        assert!(timeline.stats.start_time.is_none());
        assert!(timeline.stats.end_time.is_none());

        // Test 2: When Event.System.TimeCreated_attributes.SystemTime contains a timestamp.
        let tcreated_attrib_record_str = r#"{
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

        let include_tcreated_attrib_record =
            serde_json::from_str(tcreated_attrib_record_str).unwrap();
        input_records.clear();
        input_records.push(create_rec_info(
            include_tcreated_attrib_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        // Test 3: When Event.System.@timestamp contains a timestamp.
        let timestamp_attrib_record_str = r#"{
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
        let include_timestamp_record = serde_json::from_str(timestamp_attrib_record_str).unwrap();
        input_records.push(create_rec_info(
            include_timestamp_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        // Test 4: An RDS Gateway logon (EID 302) whose Username carries a "DOMAIN\user" value.
        // Both the user and the domain are extracted from Event.UserData.EventInfo.Username via
        // the RdsGtwUsername alias (regression test for #1809, where the dst_domain arm looked
        // up the misspelled alias "RdsGtwUserName" and always yielded "-").
        let rds_gtw_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": 302,
                    "Channel": "Microsoft-Windows-TerminalServices-Gateway/Operational",
                    "Computer": "GATEWAY01",
                    "TimeCreated_attributes": {
                        "SystemTime": "2022-12-23T00:00:00.000Z"
                    }
                },
                "UserData": {
                    "EventInfo": {
                        "Username": "CONTOSO\\alice",
                        "IpAddress": "10.0.0.5"
                    }
                }
            },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
        let rds_gtw_record = serde_json::from_str(rds_gtw_record_str).unwrap();
        input_records.push(create_rec_info(
            rds_gtw_record,
            "testpath3".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        let mut expect: HashMap<LoginEvent, [usize; 2]> = HashMap::new();
        expect.insert(
            LoginEvent {
                channel: "RDS-GTW 302".into(),
                dst_user: "alice".into(),
                dst_domain: "CONTOSO".into(),
                hostname: "GATEWAY01".into(),
                logontype: "-".into(),
                src_user: "-".into(),
                src_domain: "-".into(),
                source_computer: "-".into(),
                source_ip: "10.0.0.5".into(),
            },
            [1, 0],
        );
        expect.insert(
            LoginEvent {
                channel: "Sec 4624".into(),
                dst_user: "testuser".into(),
                dst_domain: "-".into(),
                hostname: "HAYABUSA-DESKTOP".into(),
                logontype: "3 - Network".into(),
                src_user: "-".into(),
                src_domain: "-".into(),
                source_computer: "HAYABUSA".into(),
                source_ip: "192.168.100.200".into(),
            },
            [1, 0],
        );
        expect.insert(
            LoginEvent {
                channel: "Sec 4625".into(),
                dst_user: "testuser".into(),
                dst_domain: "-".into(),
                hostname: "HAYABUSA-DESKTOP".into(),
                logontype: "0 - System".into(),
                src_user: "-".into(),
                src_domain: "-".into(),
                source_computer: "-".into(),
                source_ip: "-".into(),
            },
            [0, 1],
        );

        timeline
            .stats
            .logon_stats_start(&input_records, &dummy_stored_static);
        assert_eq!(
            timeline.stats.start_time,
            Some(DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::parse_from_str("2021-12-23T00:00:00.000Z", "%Y-%m-%dT%H:%M:%S%.fZ")
                    .unwrap(),
                Utc
            ))
        );
        assert_eq!(
            timeline.stats.end_time,
            Some(DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::parse_from_str("2022-12-23T00:00:00.000Z", "%Y-%m-%dT%H:%M:%S%.fZ")
                    .unwrap(),
                Utc
            ))
        );

        assert_eq!(timeline.stats.total, 4);

        let dt = |date_str: &str| {
            Some(DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S%.fZ").unwrap(),
                Utc,
            ))
        };
        for (login_event, values) in timeline.stats.stats_login_list.iter() {
            assert!(expect.contains_key(login_event));
            assert_eq!(expect.get(login_event).unwrap(), &values.counts);
            // Each grouping here has a single record, so first == last == that record's time.
            // Sec 4625 exercises the @timestamp fallback; the others use TimeCreated SystemTime.
            let (idx, want) = match login_event.channel.as_str() {
                "Sec 4624" => (0, dt("2021-12-23T00:00:00.000Z")),
                "Sec 4625" => (1, dt("2022-12-23T00:00:00.000Z")),
                "RDS-GTW 302" => (0, dt("2022-12-23T00:00:00.000Z")),
                _ => continue,
            };
            assert_eq!(values.first[idx], want, "first for {}", login_event.channel);
            assert_eq!(values.last[idx], want, "last for {}", login_event.channel);
        }
    }

    #[test]
    pub fn test_tm_stats_dsp_msg() {
        let output_tmp_dir = tempfile::tempdir().unwrap();
        let out_test_tm_stats_csv = output_tmp_dir.path().join("test_tm_stats.csv");
        let dummy_stored_static =
            create_dummy_stored_static(Action::EidMetrics(EidMetricsOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    recover_records: false,
                    time_offset: None,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    json_input: false,
                    validate_checksums: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                },
                output: Some(out_test_tm_stats_csv.clone()),
                clobber_opt: ClobberOption { clobber: false },
                remove_duplicate_detections: false,
            }));
        let mut timeline = Timeline::default();
        let mut input_records = vec![];
        let timestamp_attrib_record_str = r#"{
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
        let include_timestamp_record = serde_json::from_str(timestamp_attrib_record_str).unwrap();
        input_records.push(create_rec_info(
            include_timestamp_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        let include_computer: HashSet<CompactString> = HashSet::new();
        let exclude_computer: HashSet<CompactString> = HashSet::new();

        timeline.stats.evt_stats_start(
            &input_records,
            &dummy_stored_static,
            (&include_computer, &exclude_computer),
        );

        timeline.tm_stats_dsp_msg(
            &dummy_stored_static.event_timeline_config,
            &dummy_stored_static,
        );
        // Event column is defined in rules/config/channel_eid_info.txt
        let expect_records = [["1", "100.0%", "Sec", "4625", "Logon failure"]];
        let expect = "Total,%,Channel,ID,Event\n".to_owned()
            + &expect_records.join(&"\n").join(",").replace(",\n,", "\n")
            + "\n";
        match read_to_string(&out_test_tm_stats_csv) {
            Err(_) => panic!("Failed to open file."),
            Ok(contents) => {
                assert_eq!(contents, expect);
            }
        };
        // Delete the file after the test.
        assert!(remove_file(&out_test_tm_stats_csv).is_ok());
    }

    #[test]
    pub fn test_tm_logon_stats_dsp_msg() {
        let output_tmp_dir = tempfile::tempdir().unwrap();
        let out_test_tm_logon_stats_successful_csv = output_tmp_dir
            .path()
            .join("test_tm_logon_stats-successful.csv");
        let out_test_tm_logon_stats_failed_csv =
            output_tmp_dir.path().join("test_tm_logon_stats-failed.csv");
        let out_test_tm_logon_stats = output_tmp_dir.path().join("test_tm_logon_stats");
        let mut dummy_stored_static =
            create_dummy_stored_static(Action::LogonSummary(LogonSummaryOption {
                input_args: InputOption {
                    directory: None,
                    filepath: Some(Path::new("./dummy.evtx").to_path_buf()),
                    live_analysis: false,
                    recover_records: false,
                    time_offset: None,
                },
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
                detect_common_options: DetectCommonOption {
                    json_input: false,
                    validate_checksums: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                    include_computer: None,
                    exclude_computer: None,
                },
                time_format_options: TimeFormatOptions {
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                },
                output: Some(out_test_tm_logon_stats.clone()),
                clobber_opt: ClobberOption { clobber: false },
                time_range: TimeRangeOption {
                    end_timeline: None,
                    start_timeline: None,
                },
                remove_duplicate_detections: false,
            }));
        dummy_stored_static.logon_summary_flag = true;
        let mut timeline = Timeline::default();
        let mut input_records = vec![];
        let tcreated_attrib_record_str = r#"{
            "Event": {
                "System": {
                    "EventID": 4624,
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
        let include_tcreated_attrib_record =
            serde_json::from_str(tcreated_attrib_record_str).unwrap();
        input_records.clear();
        input_records.push(create_rec_info(
            include_tcreated_attrib_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        let timestamp_attrib_record_str = r#"{
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
        let include_timestamp_record = serde_json::from_str(timestamp_attrib_record_str).unwrap();
        input_records.push(create_rec_info(
            include_timestamp_record,
            "testpath2".to_string(),
            &Nested::<String>::new(),
            &false,
            &false,
            &dummy_stored_static.eventkey_alias,
        ));

        timeline
            .stats
            .logon_stats_start(&input_records, &dummy_stored_static);

        timeline.tm_logon_stats_dsp_msg(&dummy_stored_static);
        // Expected first/last timestamps, formatted the same way the code does (so the test is
        // independent of the local timezone). Successful logon uses SystemTime 2021-12-23;
        // failed logon uses @timestamp 2022-12-23.
        let tfo = &dummy_stored_static
            .output_option
            .as_ref()
            .unwrap()
            .time_format_options;
        let mkdt = |date_str: &str| {
            DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S%.fZ").unwrap(),
                Utc,
            )
        };
        let success_t =
            crate::detections::utils::format_time(&mkdt("2021-12-23T00:00:00.000Z"), false, tfo)
                .to_string();
        let failed_t =
            crate::detections::utils::format_time(&mkdt("2022-12-23T00:00:00.000Z"), false, tfo)
                .to_string();

        // CSV output test for successful logons.
        let expect_success = format!(
            "Successful,First Logon,Last Logon,Event,Target Account,Target Domain,Target Computer,Logon Type,Source Account,Source Domain,Source Computer,Source IP Address\n\
             1,{success_t},{success_t},Sec 4624,testuser,-,HAYABUSA-DESKTOP,3 - Network,-,-,HAYABUSA,192.168.100.200\n"
        );
        match read_to_string(&out_test_tm_logon_stats_successful_csv) {
            Err(_) => panic!("Failed to open file."),
            Ok(contents) => {
                assert_eq!(contents, expect_success);
            }
        };

        // CSV output test for failed logons.
        let expect_failed = format!(
            "Failed,First Attempt,Last Attempt,Event,Target Account,Target Domain,Target Computer,Logon Type,Source Account,Source Domain,Source Computer,Source IP Address\n\
             1,{failed_t},{failed_t},Sec 4625,testuser,-,HAYABUSA-DESKTOP,0 - System,-,-,-,-\n"
        );

        match read_to_string(&out_test_tm_logon_stats_successful_csv) {
            Err(_) => panic!("Failed to open file."),
            Ok(contents) => {
                assert_eq!(contents, expect_success);
            }
        };

        match read_to_string(&out_test_tm_logon_stats_failed_csv) {
            Err(_) => panic!("Failed to open file."),
            Ok(contents) => {
                assert_eq!(contents, expect_failed);
            }
        };
        // Delete the file after the test.
        assert!(remove_file(&out_test_tm_logon_stats_successful_csv).is_ok());
        assert!(remove_file(&out_test_tm_logon_stats_failed_csv).is_ok());
    }
}

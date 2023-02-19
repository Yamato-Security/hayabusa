use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use crate::detections::configs::{Action, EventInfoConfig, StoredStatic};
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::AlertMessage;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::*;
use compact_str::CompactString;
use csv::WriterBuilder;
use downcast_rs::__std::process;

use super::metrics::EventMetrics;
use hashbrown::HashMap;

#[derive(Debug, Clone)]
pub struct Timeline {
    pub stats: EventMetrics,
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Timeline {
    pub fn new() -> Timeline {
        let totalcnt = 0;
        let filepath = String::default();
        let starttm = String::default();
        let endtm = String::default();
        let statslst = HashMap::new();
        let statsloginlst = HashMap::new();

        let statistic =
            EventMetrics::new(totalcnt, filepath, starttm, endtm, statslst, statsloginlst);
        Timeline { stats: statistic }
    }

    pub fn start(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        self.stats.evt_stats_start(records, stored_static);
        self.stats.logon_stats_start(
            records,
            stored_static.logon_summary_flag,
            &stored_static.eventkey_alias,
        );
    }

    pub fn tm_stats_dsp_msg(
        &mut self,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) {
        // 出力メッセージ作成
        let mut sammsges: Vec<String> = Vec::new();
        let total_event_record = format!("\n\nTotal Event Records: {}\n", self.stats.total);
        let mut wtr;
        let target;

        match &stored_static.config.action.as_ref().unwrap() {
            Action::Metrics(option) => {
                if option.input_args.filepath.is_some() {
                    sammsges.push(format!("Evtx File Path: {}", self.stats.filepath));
                    sammsges.push(total_event_record);
                    sammsges.push(format!(
                        "First Timestamp: {}",
                        self.stats.start_time.replace('"', "")
                    ));
                    sammsges.push(format!(
                        "Last Timestamp: {}\n",
                        self.stats.end_time.replace('"', "")
                    ));
                } else {
                    sammsges.push(total_event_record);
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
        let stats_msges: Vec<Vec<String>> =
            self.tm_stats_set_msg(mapsorted, event_timeline_config, stored_static);

        for msgprint in sammsges.iter() {
            println!("{msgprint}");
        }
        if wtr.is_some() {
            for msg in stats_msges.iter() {
                if let Some(ref mut w) = wtr {
                    w.write_record(msg).ok();
                }
            }
        }
        stats_tb.add_rows(stats_msges);
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
                sammsges.push(total_event_record);
                sammsges.push(format!(
                    "First Timestamp: {}",
                    self.stats.start_time.replace('"', "")
                ));
                sammsges.push(format!(
                    "Last Timestamp: {}\n",
                    self.stats.end_time.replace('"', "")
                ));
            } else {
                sammsges.push(total_event_record);
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
        mapsorted: Vec<(&(std::string::String, std::string::String), &usize)>,
        event_timeline_config: &EventInfoConfig,
        stored_static: &StoredStatic,
    ) -> Vec<Vec<String>> {
        let mut msges: Vec<Vec<String>> = Vec::new();

        let channel_config = &stored_static.ch_config;
        for ((event_id, channel), event_cnt) in mapsorted.iter() {
            // 件数の割合を算出
            let rate: f32 = **event_cnt as f32 / self.stats.total as f32;
            let fmted_channel = CompactString::from(channel);

            // イベント情報取得(eventtitleなど)
            let conf = event_timeline_config
                .get_event_id(&fmted_channel, event_id)
                .is_some();
            // event_id_info.txtに登録あるものは情報設定
            // 出力メッセージ1行作成
            let ch = stored_static.disp_abbr_generic.replace_all(
                stored_static
                    .ch_config
                    .get(fmted_channel.to_lowercase().as_str())
                    .unwrap_or(&fmted_channel)
                    .as_str(),
                &stored_static.disp_abbr_general_values,
            );

            channel_config
                .get(fmted_channel.to_lowercase().as_str())
                .unwrap_or(&fmted_channel)
                .to_string();
            if conf {
                msges.push(vec![
                    event_cnt.to_string(),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0),
                    ch,
                    event_id.to_string(),
                    event_timeline_config
                        .get_event_id(&fmted_channel, event_id)
                        .unwrap()
                        .evttitle
                        .to_string(),
                ]);
            } else {
                msges.push(vec![
                    event_cnt.to_string(),
                    format!("{:.1}%", (rate * 1000.0).round() / 10.0),
                    ch,
                    event_id.replace('\"', ""),
                    "Unknown".to_string(),
                ]);
            }
        }
        msges
    }

    /// ユーザ毎のログイン統計情報出力メッセージ生成
    fn tm_loginstats_tb_set_msg(&self, output: &Option<PathBuf>) {
        println!(" Logon Summary:\n");
        if self.stats.stats_login_list.is_empty() {
            let mut loginmsges: Vec<String> = Vec::new();
            loginmsges.push("-----------------------------------------".to_string());
            loginmsges.push("|     No logon events were detected.    |".to_string());
            loginmsges.push("-----------------------------------------\n".to_string());
            for msgprint in loginmsges.iter() {
                println!("{msgprint}");
            }
        } else {
            println!(" Successful Logons:");
            self.tm_loginstats_tb_dsp_msg("Successful", output);
            println!("\n\n Failed Logons:");
            self.tm_loginstats_tb_dsp_msg("Failed", output);
        }
    }

    /// ユーザ毎のログイン統計情報出力
    fn tm_loginstats_tb_dsp_msg(&self, logon_res: &str, output: &Option<PathBuf>) {
        let header = vec![
            logon_res,
            "User",
            "Hostname",
            "Logon Type",
            "Source Computer",
            "Source Ip",
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
                let record_data = vec![
                    values[vnum].to_string(),
                    username.to_string(),
                    hostname.to_string(),
                    logontype.to_string(),
                    source_computer.to_string(),
                    source_ip.to_string(),
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
}

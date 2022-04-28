use crate::detections::{configs, detection::EvtxRecordInfo};
use prettytable::{Cell, Row, Table};

use super::statistics::EventStatistics;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct Timeline {
    pub stats: EventStatistics,
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
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();
        let statsloginlst = HashMap::new();

        let statistic =
            EventStatistics::new(totalcnt, filepath, starttm, endtm, statslst, statsloginlst);
        Timeline { stats: statistic }
    }

    pub fn start(&mut self, records: &[EvtxRecordInfo]) {
        self.stats.evt_stats_start(records);
        self.stats.logon_stats_start(records);
    }

    pub fn tm_stats_dsp_msg(&mut self) {
        if !configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("statistics")
        {
            return;
        }
        // 出力メッセージ作成
        //println!("map -> {:#?}", evtstat_map);
        let mut sammsges: Vec<String> = Vec::new();
        sammsges.push("---------------------------------------".to_string());
        sammsges.push(format!("Evtx File Path: {}", self.stats.filepath));
        sammsges.push(format!("Total Event Records: {}\n", self.stats.total));
        sammsges.push(format!("First Timestamp: {}", self.stats.start_time));
        sammsges.push(format!("Last Timestamp: {}\n", self.stats.end_time));
        sammsges.push("Count (Percent)\tID\tEvent\t".to_string());
        sammsges.push("--------------- ------- ---------------".to_string());

        // 集計件数でソート
        let mut mapsorted: Vec<_> = self.stats.stats_list.iter().collect();
        mapsorted.sort_by(|x, y| y.1.cmp(x.1));

        // イベントID毎の出力メッセージ生成
        let stats_msges: Vec<String> = self.tm_stats_set_msg(mapsorted);

        for msgprint in sammsges.iter() {
            println!("{}", msgprint);
        }
        for msgprint in stats_msges.iter() {
            println!("{}", msgprint);
        }
    }

    pub fn tm_logon_stats_dsp_msg(&mut self) {
        if !configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("logon-summary")
        {
            return;
        }
        // 出力メッセージ作成
        //println!("map -> {:#?}", evtstat_map);
        let mut sammsges: Vec<String> = Vec::new();
        sammsges.push("---------------------------------------".to_string());
        sammsges.push(format!("Evtx File Path: {}", self.stats.filepath));
        sammsges.push(format!("Total Event Records: {}\n", self.stats.total));
        sammsges.push(format!("First Timestamp: {}", self.stats.start_time));
        sammsges.push(format!("Last Timestamp: {}\n", self.stats.end_time));
        sammsges.push("---------------------------------------".to_string());
        for msgprint in sammsges.iter() {
            println!("{}", msgprint);
        }

        self.tm_loginstats_tb_set_msg();
    }

    // イベントID毎の出力メッセージ生成
    fn tm_stats_set_msg(&self, mapsorted: Vec<(&std::string::String, &usize)>) -> Vec<String> {
        let mut msges: Vec<String> = Vec::new();

        for (event_id, event_cnt) in mapsorted.iter() {
            // 件数の割合を算出
            let rate: f32 = **event_cnt as f32 / self.stats.total as f32;

            // イベント情報取得(eventtitleなど)
            let conf = configs::CONFIG.read().unwrap();
            // statistics_event_info.txtに登録あるものは情報設定
            match conf.event_timeline_config.get_event_id(*event_id) {
                Some(e) => {
                    // 出力メッセージ1行作成
                    msges.push(format!(
                        "{0} ({1:.1}%)\t{2}\t{3}",
                        event_cnt,
                        (rate * 1000.0).round() / 10.0,
                        event_id,
                        e.evttitle,
                    ));
                }
                None => {
                    // 出力メッセージ1行作成
                    msges.push(format!(
                        "{0} ({1:.1}%)\t{2}\t{3}",
                        event_cnt,
                        (rate * 1000.0).round() / 10.0,
                        event_id,
                        "Unknown",
                    ));
                }
            }
        }
        msges.push("---------------------------------------".to_string());
        msges
    }
    // ユーザ毎のログイン統計情報出力メッセージ生成
    fn tm_loginstats_tb_set_msg(&self) {
        let mut loginmsges: Vec<String> = Vec::new();
        let mut logins_stats_tb = Table::new();
        logins_stats_tb.set_titles(row!["User", "Failed", "Successful"]);

        loginmsges.push("Logon Summary".to_string());
        if self.stats.stats_login_list.is_empty() {
            loginmsges.push("-----------------------------------------".to_string());
            loginmsges.push("|     No logon events were detected.    |".to_string());
            loginmsges.push("-----------------------------------------\n".to_string());
            for msgprint in loginmsges.iter() {
                println!("{}", msgprint);
            }
        } else {
            for (key, values) in &self.stats.stats_login_list {
                logins_stats_tb.add_row(Row::new(vec![
                    Cell::new(key),
                    Cell::new(&values[1].to_string()),
                    Cell::new(&values[0].to_string()),
                ]));
            }
            for msgprint in loginmsges.iter() {
                println!("{}", msgprint);
            }
            logins_stats_tb.printstd();
            println!();
        }
    }
}

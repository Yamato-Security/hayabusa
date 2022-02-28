use crate::detections::{configs, detection::EvtxRecordInfo};

use super::statistics::EventStatistics;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct Timeline {
    pub stats: EventStatistics,
}

impl Timeline {
    pub fn new() -> Timeline {
        let totalcnt = 0;
        let filepath = String::default();
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();

        let statistic = EventStatistics::new(totalcnt, filepath, starttm, endtm, statslst);
        Timeline { stats: statistic }
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) {
        self.stats.start(records);
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
        sammsges.push("Count (Percent)\tID\tEvent\t\tTimeline".to_string());
        sammsges.push("--------------- ------- --------------- -------".to_string());

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
    // イベントID毎の出力メッセージ生成
    fn tm_stats_set_msg(&self, mapsorted: Vec<(&std::string::String, &usize)>) -> Vec<String> {
        let mut msges: Vec<String> = Vec::new();

        for (event_id, event_cnt) in mapsorted.iter() {
            // 件数の割合を算出
            let rate: f32 = **event_cnt as f32 / self.stats.total as f32;

            // イベント情報取得(eventtitleなど)
            let conf = configs::CONFIG.read().unwrap();
            // timeline_event_info.txtに登録あるものは情報設定
            match conf.event_timeline_config.get_event_id(*event_id) {
                Some(e) => {
                    // 出力メッセージ1行作成
                    msges.push(format!(
                        "{0} ({1:.1}%)\t{2}\t{3}\t{4}",
                        event_cnt,
                        (rate * 1000.0).round() / 10.0,
                        event_id,
                        e.evttitle,
                        e.detectflg
                    ));
                }
                None => {
                    // 出力メッセージ1行作成
                    msges.push(format!(
                        "{0} ({1:.1}%)\t{2}\t{3}\t{4}",
                        event_cnt,
                        (rate * 1000.0).round() / 10.0,
                        event_id,
                        "Unknown".to_string(),
                        "".to_string()
                    ));
                }
            }
        }
        msges.push("---------------------------------------".to_string());
        msges
    }
}

use crate::detections::{configs, detection::EvtxRecordInfo};

use super::statistics::EventStatistics;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Timeline {
    pub stats: EventStatistics,
}

impl Timeline {
    pub fn new() -> Timeline {
        let totalcnt = "".to_string();
        let starttm = "".to_string();
        let endtm = "".to_string();
        let statslst = HashMap::new();

        let statistic = EventStatistics::new(totalcnt, starttm, endtm, statslst);
        return Timeline { stats: statistic };
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) {
        self.stats.start(records);
    }

    pub fn tm_stats_dsp_msg(&mut self) {
        // 出力メッセージ作成
        //println!("map -> {:#?}", evtstat_map);
        let mut sammsges: Vec<String> = Vec::new();
        sammsges.push("---------------------------------------".to_string());
        sammsges.push(format!("Total_counts : {}\n", self.stats.total));
        sammsges.push(format!("firstevent_time: {}", self.stats.start_time));
        sammsges.push(format!("lastevent_time: {}\n", self.stats.end_time));
        sammsges.push("count(rate)\tID\tevent\t\ttimeline".to_string());
        sammsges.push("--------------- ------- --------------- -------".to_string());

        // 集計件数でソート
        let mut mapsorted: Vec<_> = self.stats.stats_list.iter().collect();
        mapsorted.sort_by(|x, y| y.1.cmp(&x.1));

        // イベントID毎の出力メッセージ生成
        let totalnum: usize = self.stats.total.parse().unwrap();
        let res_msges: Vec<String> = self.tm_stats_set_msg(mapsorted, &totalnum);

        for msgprint in sammsges.iter() {
            println!("{}", msgprint);
        }
        for msgprint in res_msges.iter() {
            println!("{}", msgprint);
        }
    }
    // イベントID毎の出力メッセージ生成
    fn tm_stats_set_msg(
        &self,
        mapsorted: Vec<(&std::string::String, &usize)>,
        totalcount: &usize,
    ) -> Vec<String> {
        let mut msges: Vec<String> = Vec::new();

        for (event_id, event_cnt) in mapsorted.iter() {
            // 件数の割合を算出
            let rate: f32 = **event_cnt as f32 / *totalcount as f32;

            // イベント情報取得(eventtitleなど)
            let conf = configs::CONFIG.read().unwrap();
            let mut event_title: String = "Unknown".to_string();
            let mut detect_flg: String = "".to_string();
            // timeline_event_info.txtに登録あるものは情報設定
            for evtinfo in conf.event_timeline_config.iter() {
                if **event_id == evtinfo.get_event_id() {
                    event_title = evtinfo.get_event_title();
                    detect_flg = evtinfo.get_event_flg();
                }
            }
            // 出力メッセージ1行作成
            msges.push(format!(
                "{} ({}%)\t{}\t{}\t{}",
                event_cnt,
                (rate * 10000.0).round() / 100.0,
                event_id,
                event_title,
                detect_flg
            ));
        }
        msges.push("---------------------------------------".to_string());
        return msges;
    }
}

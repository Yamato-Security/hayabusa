use crate::detections::{configs, detection::EvtxRecordInfo, utils};
use std::collections::HashMap;

#[derive(Debug)]
pub struct EventStatistics {
    pub total: String,
    pub start_time: String,
    pub end_time: String,
    pub stats_list: HashMap<String, usize>,
}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventStatistics {
    pub fn new(
        total: String,
        start_time: String,
        end_time: String,
        stats_list: HashMap<String, usize>,
    ) -> EventStatistics {
        return EventStatistics {
            total,
            start_time,
            end_time,
            stats_list,
        };
    }

    pub fn start(&mut self, records: &Vec<EvtxRecordInfo>) -> Vec<String> {
        // 引数でstatisticsオプションが指定されている時だけ、統計情報を出力する。
        if !configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("statistics")
        {
            return vec![];
        }

        //let mut filesize = 0;
        // _recordsから、EventIDを取り出す。
        self.stats_time_cnt(records);

        // EventIDで集計
        //let evtstat_map = HashMap::new();
        self.stats_list = self.timeline_stats_eventid(records);

        // 出力メッセージ作成
        //println!("map -> {:#?}", evtstat_map);
        let mut sammsges: Vec<String> = Vec::new();
        sammsges.push("---------------------------------------".to_string());
        sammsges.push(format!("Total_counts : {}\n", self.total));
        sammsges.push(format!("firstevent_time: {}", self.start_time));
        sammsges.push(format!("lastevent_time: {}\n", self.end_time));
        sammsges.push("count(rate)\tID\tevent\t\ttimeline".to_string());
        sammsges.push("--------------- ------- --------------- -------".to_string());

        for msgprint in sammsges.iter() {
            println!("{}", msgprint);
        }

        return vec![];
    }

    fn stats_time_cnt(&mut self, records: &Vec<EvtxRecordInfo>) {
        if records.len() == 0 {
            return;
        }

        // sortしなくてもイベントログのTimeframeを取得できるように修正しました。
        // sortしないことにより計算量が改善されています。
        // もうちょっと感じに書けるといえば書けます。
        for record in records.iter() {
            let evttime = utils::get_event_value(
                &"Event.System.TimeCreated_attributes.SystemTime".to_string(),
                &record.record,
            )
            .and_then(|evt_value| {
                return Option::Some(evt_value.to_string());
            });
            if evttime.is_none() {
                continue;
            }

            let evttime = evttime.unwrap();
            if self.start_time.len() == 0 || evttime < self.start_time {
                self.start_time = evttime.to_string();
            }
            if self.end_time.len() == 0 || evttime > self.end_time {
                self.end_time = evttime;
            }
        }

        self.total = records.len().to_string(); // for文で数えなくても、Vecの関数で簡単に取得可能
    }

    // EventIDで集計
    fn timeline_stats_eventid(&self, records: &Vec<EvtxRecordInfo>) -> HashMap<String, usize> {
        let mut evtstat_map = HashMap::new();
        for record in records.iter() {
            let evtid = utils::get_event_value(&"EventID".to_string(), &record.record);
            if evtid.is_none() {
                continue;
            }

            let idnum = evtid.unwrap();
            let count: &mut usize = evtstat_map.entry(idnum.to_string()).or_insert(0);
            *count += 1;
        }
        return evtstat_map;
    }

    /// ここの処理も変える必要がありそうだが、何やっているかあまりよく分からないので、本人に確認する。
    /// 多分、timelineに移動する。
    // イベントID毎の出力メッセージ生成
    fn timeline_stats_res_msg(
        &self,
        mapsorted: &Vec<(std::string::String, usize)>,
        totalcount: &usize,
    ) -> Vec<String> {
        let mut msges: Vec<String> = Vec::new();

        for (event_id, event_cnt) in mapsorted.iter() {
            let rate: f32 = *event_cnt as f32 / *totalcount as f32;
            //println!("total:{}",totalcount);
            //println!("{}", rate );
            let conf = configs::CONFIG.read().unwrap();
            let mut event_title: String = "Unknown".to_string();
            let mut detect_flg: String = "".to_string();
            // timeline_event_info.txtに登録あるものは情報設定
            for evtinfo in conf.event_timeline_config.iter() {
                if **event_id == evtinfo.get_event_id() {
                    //                    println!("{:#?}", evtinfo.get_event_id());
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

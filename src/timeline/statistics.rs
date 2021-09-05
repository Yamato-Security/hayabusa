use std::path::PathBuf;

use crate::detections::{configs, detection::EvtxRecordInfo, utils};
use std::collections::HashMap;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EvtList {
    pub evtid: String,
    pub evttime: String,
}
impl EvtList {
    pub fn new(evtid: String, evttime: String) -> EvtList {
        return EvtList { evtid, evttime };
    }
}
pub struct EventStatistics {}
/**
* Windows Event Logの統計情報を出力する
*/
impl EventStatistics {
    pub fn new() -> EventStatistics {
        return EventStatistics {};
    }

    // この関数の戻り値として、コンソールに出力する内容をStringの可変配列(Vec)として返却してください。
    // 可変配列にしているのは改行を表すためで、可変配列にコンソールに出力する内容を1行ずつ追加してください。
    // 引数の_recordsが読み込んだWindowsイベントログのを表す、EvtxRecordInfo構造体の配列になっています。
    // EvtxRecordInfo構造体の pub record: Value というメンバーがいて、それがWindowsイベントログの1レコード分を表していますので、
    // EvtxRecordInfo構造体のrecordから、EventIDとか統計情報を取得するようにしてください。
    // recordからEventIDを取得するには、detection::utils::get_event_value()という関数があるので、それを使うと便利かもしれません。

    // 現状では、この関数の戻り値として返すVec<String>を表示するコードは実装していません。
    pub fn start(
        &mut self,
        evtx_files: &Vec<PathBuf>,
        _records: &Vec<EvtxRecordInfo>,
    ) -> Vec<String> {
        // 引数でstatisticsオプションが指定されている時だけ、統計情報を出力する。
        if !configs::CONFIG
            .read()
            .unwrap()
            .args
            .is_present("statistics")
        {
            return vec![];
        }

        let mut filesize = 0;
        // _recordsから、EventIDを取り出す。
        let (evtlist, index) = self.timeline_get_eventid(&_records);
        //        println!("{}", index);
        let firstevt_time = evtlist[0].evttime.as_str();
        let lastevt_time = evtlist[index - 1].evttime.as_str();
        //println!("firstevet_time: {}", firstevt_time);
        //println!("lastevet_time: {}", lastevt_time);

        // EventIDで集計
        //let evtstat_map = HashMap::new();
        let (evtstat_map, totalcount) = self.timeline_stats_eventid(&evtlist);

        // 出力メッセージ作成
        //println!("map -> {:#?}", evtstat_map);
        let mut sammsges: Vec<String> = Vec::new();
        sammsges.push("---------------------------------------".to_string());
        sammsges.push(format!("Total_counts : {}\n", totalcount));
        sammsges.push(format!("firstevent_time: {}", firstevt_time));
        sammsges.push(format!("lastevent_time: {}\n", lastevt_time));
        sammsges.push("count(rate)\tID\tevent\t\ttimeline".to_string());
        sammsges.push("--------------- ------- --------------- -------".to_string());

        for msgprint in sammsges.iter() {
            println!("{}", msgprint);
        }

        // 集計件数でソート
        let mut mapsorted: Vec<_> = evtstat_map.into_iter().collect();
        mapsorted.sort_by(|x, y| y.1.cmp(&x.1));

        // イベントID毎の出力メッセージ生成
        let res_msg: Vec<String> = self.timeline_stats_res_msg(&mapsorted, &totalcount);

        //        msges.push(res_msg);
        for msgprint in res_msg.iter() {
            println!("{}", msgprint);
        }

        return vec![];
    }

    // _recordsから、EventIDを取り出す。
    fn timeline_get_eventid(&self, _records: &Vec<EvtxRecordInfo>) -> (Vec<EvtList>, usize) {
        let mut evtlist: Vec<EvtList> = Vec::new();
        let mut i = 0;
        // 一旦、EventIDと時刻を取得
        for record in _records.iter() {
            let channel = utils::get_event_value(&"Channel".to_string(), &record.record);
            //println!("channel: {:?}", channel);
            let evtid = utils::get_event_value(&"EventID".to_string(), &record.record);
            let evttime = utils::get_event_value(
                &"Event.System.TimeCreated_attributes.SystemTime".to_string(),
                &record.record,
            );

            let evtdata = EvtList::new(evtid.unwrap().to_string(), evttime.unwrap().to_string());
            // 取得イベントを格納
            evtlist.push(evtdata);
            //println!("no:{},{:?},{:?}", i, evtlist[i].evtid, evtlist[i].evttime);
            //println!("no:{} {:?} {:?}", i, evtlist[i].evtid, evtlist[i].evttime);
            i += 1;
        }
        // 時刻でソート
        evtlist.sort_by(|a, b| a.evttime.cmp(&b.evttime));
        return (evtlist, i);
    }

    // EventIDで集計
    fn timeline_stats_eventid(&self, _evtlist: &Vec<EvtList>) -> (HashMap<String, usize>, usize) {
        let mut evtstat_map = HashMap::new();
        let mut totalcount: usize = 0;
        for evtdata in _evtlist.iter() {
            let idnum = &evtdata.evtid;
            let count: &mut usize = evtstat_map.entry(idnum.to_string()).or_insert(0);
            *count += 1;
            //println!("count: {} idnum: {}", count, idnum);
            totalcount += 1;
        }
        return (evtstat_map, totalcount);
    }

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

use std::path::PathBuf;

use crate::detections::{configs, detection::EvtxRecordInfo, utils};
use std::collections::HashMap;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EvtList {
    pub evttime: String,
    pub evtid: String,
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

        // _recordsから、EventIDを取り出す。
        let mut evtstat_map = HashMap::new();
        let mut totalcount = 0;
        let mut firstevt_time = "";
        let mut lastevt_time = "";
        let mut filesize = 0;
        let mut evtlist: Vec<EvtList> = Vec::new();
        let mut i = 0;
        // 一旦、EventIDと時刻を取得
        for record in _records.iter() {
            let evtid = utils::get_event_value(&"EventID".to_string(), &record.record);
            let evttime = utils::get_event_value(
                &"Event.System.TimeCreated_attributes.SystemTime".to_string(),
                &record.record,
            );
            let evtdata = EvtList::new(evtid.unwrap().to_string(), evttime.unwrap().to_string());
            evtlist.push(evtdata);
            //            println!("no:{},{:?},{:?}", i, evtlist[i].evtid, evtlist[i].evttime);
            //println!("no:{} {:?} {:?}", i, evtlist[i].evtid, evtlist[i].evttime);
            i += 1;
        }
        // 時刻でソート
        evtlist.sort_by(|a, b| a.evttime.cmp(&b.evttime));
        firstevt_time = evtlist[0].evttime.as_str();
        lastevt_time = evtlist[i - 1].evttime.as_str();
        println!("firstevet_time: {}", firstevt_time);
        println!("lastevet_time: {}", lastevt_time);

        // EventIDで集計
        for evtdata in evtlist.iter() {
            let idnum = &evtdata.evtid;
            let count: &mut usize = evtstat_map.entry(idnum).or_insert(0);
            *count += 1;
            //println!("count: {} idnum: {}", count, idnum);
            totalcount += 1;
        }

        //println!("map -> {:#?}", evtstat_map);
        let mut msges: Vec<String> = Vec::new();
        msges.push(format!("Total_counts : {}", totalcount));
        msges.push("count\tID\tevent\ttimeline".to_string());
        msges.push("------- ------- ------- -------".to_string());

        let mut mapsorted: Vec<_> = evtstat_map.into_iter().collect();
        mapsorted.sort_by(|x, y| y.1.cmp(&x.1));
        for (key, value) in mapsorted.iter() {
            msges.push(format!("{}\t{}", key, value));
        }
        for msgprint in msges.iter() {
            println!("{}", msgprint);
        }
        return vec![];
    }
}

use std::path::PathBuf;

use crate::detections::{configs, detection::EvtxRecordInfo};

#[derive(Debug)]
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
        records: &Vec<EvtxRecordInfo>,
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

        // TODO ここから下を書いて欲しいです。

        return vec![];
    }
}

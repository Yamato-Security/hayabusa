use std::sync::Mutex;

use crate::detections::utils::output_duration;
use chrono::{DateTime, Local};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref CHECKPOINT: Mutex<CheckPointProcessTimer> =
        Mutex::new(CheckPointProcessTimer::create_checkpoint_timer());
}

pub struct CheckPointProcessTimer {
    prev_checkpoint: Option<DateTime<Local>>,
    stocked_results: Vec<CheckPointTimeStore>,
}

pub struct CheckPointTimeStore {
    pub output_str: String,
    pub sec: i64,
    pub msec: i64,
}

impl CheckPointProcessTimer {
    /// static変数に最初に投入するための構造体情報を作成する関数
    pub fn create_checkpoint_timer() -> Self {
        CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Vec::new(),
        }
    }

    /// 時間計測開始点を設定する関数
    pub fn set_checkpoint(&mut self, time: DateTime<Local>) {
        self.prev_checkpoint = Some(time);
    }

    /// ラップタイムを取得して、出力用の配列に格納する関数
    pub fn rap_checkpoint(&mut self, output_str: &str) {
        if self.prev_checkpoint.is_none() {
            return;
        }
        let new_checkpoint = Local::now();

        let duration = new_checkpoint - self.prev_checkpoint.unwrap();
        let s = duration.num_seconds();
        let ms = duration.num_milliseconds() - 1000 * s;
        if !self.stocked_results.is_empty()
            && self.stocked_results[self.stocked_results.len() - 1].output_str == output_str
        {
            let stocked_last_idx = self.stocked_results.len() - 1;
            self.stocked_results[stocked_last_idx].sec += s;
            self.stocked_results[stocked_last_idx].msec += ms;
        } else {
            self.stocked_results.push(CheckPointTimeStore {
                output_str: output_str.into(),
                sec: s,
                msec: ms,
            });
        }
        self.prev_checkpoint = None;
    }

    /// ストックした結果を出力する関数
    pub fn output_stocked_result(&self) {
        for output in self.stocked_results.iter() {
            println!(
                "{}: {}",
                output.output_str,
                output_duration((output.sec, output.msec))
            );
        }
    }

    pub fn calculate_all_stocked_results(&self) -> String {
        let mut s = 0;
        let mut ms = 0;
        for output in self.stocked_results.iter() {
            s += output.sec;
            ms += output.msec;
        }
        if let Some(prev_check) = self.prev_checkpoint {
            let duration = Local::now() - prev_check;
            s += duration.num_seconds();
            ms += duration.num_milliseconds() - 1000 * duration.num_seconds();
        }
        output_duration((s, ms))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Local, TimeDelta};

    use crate::debug::checkpoint_process_timer::CheckPointProcessTimer;

    #[test]
    fn test_set_check_point() {
        let mut actual = CheckPointProcessTimer::create_checkpoint_timer();
        let now: DateTime<Local> = Local::now();
        actual.set_checkpoint(now);
        assert_eq!(actual.prev_checkpoint.unwrap(), now);
    }

    #[test]
    fn test_rap_checkpoint() {
        let mut actual = CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Vec::new(),
        };
        actual.rap_checkpoint("Test");
        let now: DateTime<Local> = Local::now();
        actual.set_checkpoint(now);
        actual.rap_checkpoint("Test2");
        actual.set_checkpoint(Local::now());
        assert!(actual.prev_checkpoint.is_some());
        assert_eq!(actual.stocked_results.len(), 1);
        assert!(actual.stocked_results[0].output_str == "Test2");
        assert_ne!(actual.prev_checkpoint.unwrap(), now);

        actual.output_stocked_result();
    }

    #[test]
    fn test_calculate_all_stocked_results() {
        let now = Local::now();
        let mut actual = CheckPointProcessTimer {
            prev_checkpoint: Some(now),
            stocked_results: Vec::new(),
        };
        actual.rap_checkpoint("Test");
        actual.set_checkpoint(
            now.checked_add_signed(TimeDelta::try_seconds(1).unwrap_or_default())
                .unwrap(),
        );
        actual.rap_checkpoint("Test2");
        actual.set_checkpoint(
            now.checked_add_signed(TimeDelta::try_seconds(1).unwrap_or_default())
                .unwrap(),
        );
        assert!(actual.prev_checkpoint.is_some());
        assert_eq!(actual.stocked_results.len(), 2);
        assert!(actual.stocked_results[0].output_str == "Test");
        assert_ne!(actual.prev_checkpoint.unwrap(), now);

        actual.calculate_all_stocked_results();
    }
}

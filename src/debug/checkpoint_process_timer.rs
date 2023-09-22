use std::sync::Mutex;

use crate::detections::utils::output_duration;
use chrono::{DateTime, Local};
use lazy_static::lazy_static;
use nested::Nested;

lazy_static! {
    pub static ref CHECKPOINT: Mutex<CheckPointProcessTimer> =
        Mutex::new(CheckPointProcessTimer::create_checkpoint_timer());
}

pub struct CheckPointProcessTimer {
    prev_checkpoint: Option<DateTime<Local>>,
    stocked_results: Nested<String>,
}

impl CheckPointProcessTimer {
    /// static変数に最初に投入するための構造体情報を作成する関数
    pub fn create_checkpoint_timer() -> Self {
        CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Nested::<String>::new(),
        }
    }

    /// 時間計測開始点を設定する関数
    pub fn set_checkpoint(&mut self, time: DateTime<Local>) {
        self.prev_checkpoint = Some(time);
    }

    /// ラップタイムを取得して、出力用の配列に格納する関数
    pub fn rap_check_point(&mut self, output_str: &str) {
        if self.prev_checkpoint.is_none() {
            return;
        }
        let new_checkpoint = Local::now();
        self.stocked_results.push(format!(
            "{}: {} ",
            output_str,
            output_duration(new_checkpoint - self.prev_checkpoint.unwrap())
        ));
        self.prev_checkpoint = Some(new_checkpoint);
    }

    /// ストックした結果を出力する関数
    pub fn output_stocked_result(&self) {
        for output in self.stocked_results.iter() {
            println!("{output}");
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Local};
    use nested::Nested;

    use crate::debug::checkpoint_process_timer::CheckPointProcessTimer;

    #[test]
    fn test_set_check_point() {
        let mut actual = CheckPointProcessTimer::create_checkpoint_timer();
        let now: DateTime<Local> = Local::now();
        actual.set_checkpoint(now);
        assert_eq!(actual.prev_checkpoint.unwrap(), now);
    }

    #[test]
    fn test_rap_check_point() {
        let mut actual = CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Nested::<String>::new(),
        };
        actual.rap_check_point("Test");
        let now: DateTime<Local> = Local::now();
        actual.set_checkpoint(now);
        actual.rap_check_point("Test2");

        assert!(actual.prev_checkpoint.is_some());
        assert_eq!(actual.stocked_results.len(), 1);
        assert!(actual.stocked_results[0].starts_with("Test2:"));
        assert_ne!(actual.prev_checkpoint.unwrap(), now);

        actual.output_stocked_result();
    }
}

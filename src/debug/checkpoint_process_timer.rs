use std::sync::Mutex;

use crate::detections::utils::output_duration;
use chrono::{DateTime, Local};
use lazy_static::lazy_static;

lazy_static! {
    /// Global timer used to record how long each processing phase (rule parsing, analysis,
    /// output) takes. Lap times are always collected; the per-phase breakdown is only printed
    /// when the --debug option is set, while the accumulated total is always shown as the
    /// "Elapsed time" in the results summary.
    pub static ref CHECKPOINT: Mutex<CheckPointProcessTimer> =
        Mutex::new(CheckPointProcessTimer::create_checkpoint_timer());
}

/// Stopwatch-style timer: `set_checkpoint` starts measuring and `lap_checkpoint` records the
/// elapsed time since the last checkpoint as a labeled lap.
pub struct CheckPointProcessTimer {
    prev_checkpoint: Option<DateTime<Local>>,
    stocked_results: Vec<CheckPointTimeStore>,
}

/// One recorded lap: a label and the elapsed time split into seconds and milliseconds.
pub struct CheckPointTimeStore {
    pub output_str: String,
    pub sec: i64,
    pub msec: i64,
}

impl CheckPointProcessTimer {
    /// Creates the struct data to be initially inserted into the static variable.
    pub fn create_checkpoint_timer() -> Self {
        CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Vec::new(),
        }
    }

    /// Sets the time measurement start point.
    pub fn set_checkpoint(&mut self, time: DateTime<Local>) {
        self.prev_checkpoint = Some(time);
    }

    /// Records the time elapsed since the last checkpoint as a lap labeled `output_str` and
    /// clears the checkpoint. Does nothing if no checkpoint has been set. If the most recently
    /// stocked lap has the same label, the new lap time is added to it instead of creating a new
    /// entry, so a phase that is timed repeatedly (e.g. once per input file) is reported as a
    /// single total.
    pub fn lap_checkpoint(&mut self, output_str: &str) {
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

    /// Prints every stocked lap as "label: duration" (used for the --debug breakdown).
    pub fn output_stocked_result(&self) {
        for output in self.stocked_results.iter() {
            println!(
                "{}: {}",
                output.output_str,
                output_duration((output.sec, output.msec))
            );
        }
    }

    /// Returns the sum of all stocked lap times — plus, if a checkpoint is currently running,
    /// the time elapsed since it was set — formatted as a duration string. Used for the total
    /// "Elapsed time" line in the results summary.
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
    fn test_lap_checkpoint() {
        let mut actual = CheckPointProcessTimer {
            prev_checkpoint: None,
            stocked_results: Vec::new(),
        };
        actual.lap_checkpoint("Test");
        let now: DateTime<Local> = Local::now();
        actual.set_checkpoint(now);
        actual.lap_checkpoint("Test2");
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
        actual.lap_checkpoint("Test");
        actual.set_checkpoint(
            now.checked_add_signed(TimeDelta::try_seconds(1).unwrap_or_default())
                .unwrap(),
        );
        actual.lap_checkpoint("Test2");
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

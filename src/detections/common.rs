use crate::models::event;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Common {
    record_id: u64,
    date: String,
    record_id_list: HashMap<String, String>,
}

impl Common {
    pub fn new() -> Common {
        Common {
            record_id: 0,
            date: "".to_string(),
            record_id_list: HashMap::new(),
        }
    }

    pub fn disp(&self) {
        for (record_id, date) in self.record_id_list.iter() {
            println!("date:{:?} record-id: {:?}", date, record_id);
        }
    }

    pub fn detection(&mut self, system: &event::System, event_data: &HashMap<String, String>) {
        &self.check_record_id(system);
    }

    //
    // Record IDがシーケンスになっているかチェック
    //
    fn check_record_id(&mut self, system: &event::System) {
        let event_record_id: u64 = system.event_record_id.parse().unwrap();
        if self.record_id > 0 && event_record_id - self.record_id > 1 {
            self.record_id_list.insert(
                self.record_id.to_string() + " - " + &system.event_record_id.to_string(),
                self.date.to_string() + " - " + &system.time_created.system_time.to_string(),
            );
        }
        self.record_id = event_record_id;
        self.date = system.time_created.system_time.to_string();
    }
}

extern crate regex;

use crate::models::event;
use regex::Regex;
use std::collections::HashMap;

pub struct AppLocker {}

impl AppLocker {
    pub fn new() -> AppLocker {
        AppLocker {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        _event_data: HashMap<String, String>,
    ) {
        self.appLocker_log_warning(&event_id, &_system);
        self.appLocker_log_block(&event_id, &_system);
    }

    fn appLocker_log_warning(&mut self, event_id: &String, system: &event::System) {
        if event_id != "8003" {
            return;
        }

        let re = Regex::new(r" was .*$").unwrap();
        let default = "".to_string();
        let message = &system.message.as_ref().unwrap_or(&default);
        let command = re.replace_all(&message, "");

        println!("Message Applocker Warning");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }

    fn appLocker_log_block(&mut self, event_id: &String, system: &event::System) {
        if event_id != "8004" {
            return;
        }

        let re = Regex::new(r" was .*$").unwrap();
        let default = "".to_string();
        let message = &system.message.as_ref().unwrap_or(&default);
        let command = re.replace_all(&message, "");

        println!("Message Applocker Block");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }
}

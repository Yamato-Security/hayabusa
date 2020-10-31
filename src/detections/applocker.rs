use crate::models::event;
use std::collections::HashMap;

pub struct AppLocker {}

impl AppLocker {
    pub fn new() -> AppLocker {
        AppLocker {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        AppLocker: &event::AppLocker,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "8003" {
            &self.AppLocker_log_warning();
        } else if event_id == "8004" {
            &self.AppLocker_log_block(event_data);
        }
        // -- Not Implemented 8006 and 8007 on DeepBlueCLI, but reserved these ID. -- 
        //
        //} else if event_id == "8006" {
        //    &self.windows_event_log(event_data);
        //} else if event_id == "8007" {
        //    &self.windows_event_log(event_data);
        //}
    }

    fn AppLocker_log_warning(&mut self, applocker: &event::AppLocker) {
        let re = Regex::new(r" was .*$").unwrap();
        let command = re.replace_all(message, "");

        println!("Message Applocker Warning");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }

    fn AppLocker_log_block(&mut self, applocker: &event::AppLocker) {
        let re = Regex::new(r" was .*$").unwrap();
        let command = re.replace_all(message, "");

        println!("Message Applocker Block");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }

}

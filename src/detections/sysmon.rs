use crate::models::event;
use std::collections::HashMap;

pub struct Sysmon {}

impl Sysmon {
    pub fn new() -> Sysmon {
        Sysmon {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "1" {
            &self.sysmon_event_1(event_data);
        } else if event_id == "7" {
            &self.sysmon_event_7(event_data);
        }
    }

    fn sysmon_event_1(&mut self, event_data: HashMap<String, String>) {
        println!("Message : Sysmon event 1");
        if let Some(_image) = event_data.get("Image") {
            println!("_image : {}",_image);
        }
        if let Some(_command_line) = event_data.get("CommandLine") {
            println!("_command_line : {}",_command_line);
        }
    }

    fn sysmon_event_7(&mut self, event_data: HashMap<String, String>) {
        println!("Message : Sysmon event 7");
    }
}

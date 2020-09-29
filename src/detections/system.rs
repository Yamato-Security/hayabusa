use crate::models::event;
use std::collections::HashMap;

pub struct System {}

impl System {
    pub fn new() -> System {
        System {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "104" {
            &self.system_log_clear();
        } else if event_id == "7040" {
            &self.windows_event_log(event_data);
        }
    }

    fn system_log_clear(&mut self) {
        println!("Message : System Log Clear");
        println!("Results : The System log was cleared.");
    }

    fn windows_event_log(&mut self, event_data: HashMap<String, String>) {
        match event_data.get("param1") {
            Some(_data) => {
                if _data == "Windows Event Log" {
                    println!("Service name : {}", _data);
                    match event_data.get("param2") {
                        Some(_data) => {
                            if _data == "disabled" {
                                println!("Message : Event Log Service Stopped");
                                println!("Results : Selective event log manipulation may follow this event.");
                            } else if _data == "auto start" {
                                println!("Message : Event Log Service Started");
                                println!("Results : Selective event log manipulation may precede this event.");
                            }
                        }
                        None => (),
                    }
                }
            }
            None => (),
        }
    }
}

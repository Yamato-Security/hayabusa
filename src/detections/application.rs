extern crate regex;

use crate::models::event;
use regex::Regex;
use std::collections::HashMap;

pub struct Application {}

impl Application {
    pub fn new() -> Application {
        Application {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "2" {
            &self.emet(system);
        }
    }

    fn emet(&mut self, system: &event::System) {
        match &system.provider.name {
            Some(name) => {
                if name != "EMET" {
                    return;
                }
            }
            None => return,
        }
        match &system.message {
            Some(message) => {
                let message_split: Vec<&str> = message.split("\n").collect();
                if !message_split.is_empty() && message_split.len() >= 5 {
                    let text = message_split[0];
                    let application = message_split[3];
                    let re = Regex::new(r"^Application: ").unwrap();
                    let command = re.replace_all(application, "");
                    let username = message_split[4];

                    println!("Message EMET Block");
                    println!("Command : {}", command);
                    println!("Results : {}", text);
                    println!("Results : {}", username);
                }
            }
            None => {
                println!("Warning: EMET Message field is blank. Install EMET locally to see full details of this alert");
            }
        }
    }
}

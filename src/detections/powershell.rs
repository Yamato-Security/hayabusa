use crate::detections::print::MESSAGES;
use crate::detections::utils;
use crate::models::event;
use regex::Regex;
use std::collections::HashMap;

pub struct PowerShell {}

impl PowerShell {
    pub fn new() -> PowerShell {
        PowerShell {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        self.execute_pipeline(&event_id, &event_data);
        self.execute_remote_command(&event_id, &event_data);
    }

    fn execute_pipeline(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4103" {
            return;
        }

        let message = MESSAGES.lock().unwrap();
        println!("{}", message.return_message("4103"));

        let default = String::from("");
        let commandline = event_data.get("ContextInfo").unwrap_or(&default);

        if commandline.contains("Host Application")
            || commandline.contains("ホスト アプリケーション")
        {
            let rm_before =
                Regex::new("(?ms)^.*(ホスト アプリケーション|Host Application) = ").unwrap();
            let rm_after = Regex::new("(?ms)\n.*$").unwrap();

            let temp_command_with_extra = rm_before.replace_all(commandline, "");
            let command = rm_after.replace_all(&temp_command_with_extra, "");

            if command != "" {
                utils::check_command(4103, &command, 1000, 0, &default, &default);
            }
        }
    }

    fn execute_remote_command(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4104" {
            return;
        }
        let message = MESSAGES.lock().unwrap();
        println!("{}", message.return_message("4104"));

        let default = String::from("");
        let path = event_data.get("Path").unwrap().to_string();
        if path == "".to_string() {
            let commandline = event_data.get("ScriptBlockText").unwrap_or(&default);
            if commandline.to_string() != default {
                utils::check_command(4104, &commandline, 1000, 0, &default, &default);
            }
        }
    }
}

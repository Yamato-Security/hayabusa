use crate::models::event;
use std::collections::HashMap;

pub struct Sysmon {
    checkunsigned: u64,
}

impl Sysmon {
    pub fn new() -> Sysmon {
        Sysmon {
            //checkunsigned: 0, //  DeepBlueでは0固定
            checkunsigned: 1, //  開発用に1
        }
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "1" {
            &self.check_command_lines(event_data);
        } else if event_id == "7" {
            &self.check_for_unsigned_files(event_data);
        }
    }

    fn check_command_lines(&mut self, event_data: HashMap<String, String>) {
        // Check command lines
        if let Some(_command_line) = event_data.get("CommandLine") {
            if let Some(_date) = event_data.get("UtcTime") {
                println!("Date    : {} (UTC)", _date);
            }
            println!("Log     : Sysmon");
            //if let Some(_creater) = event_data.get("ParentImage") {
            //    println!("_creater : {}", _image);
            //}
            self.check_command("1".to_string(), _command_line.to_string());
            println!("");
        }
    }

    fn check_for_unsigned_files(&mut self, event_data: HashMap<String, String>) {
        // Check for unsigned EXEs/DLLs:
        // This can be very chatty, so it's disabled.
        // Set $checkunsigned to 1 (global variable section) to enable:
        if self.checkunsigned == 1 {
            if let Some(_signed) = event_data.get("Signed") {
                if _signed == "false" {
                    if let Some(_date) = event_data.get("UtcTime") {
                        println!("Date    : {} (UTC)", _date);
                    }
                    println!("Log     : Sysmon");
                    println!("EventID : 7");
                    println!("Message : Unsigned Image (DLL)");
                    if let Some(_image) = event_data.get("Image") {
                        println!("Result  : Loaded by: {}", _image);
                    }
                    if let Some(_command_line) = event_data.get("ImageLoaded") {
                        println!("Command : {}", _command_line);
                    }
                    println!("");
                }
            }
        }
    }

    fn check_command(&mut self, _event_id: String, _command_line: String) {
        let _result = "(TBD)";
        let _decoded = "(TBD)";

        //  TBD

        //  Write-Output $obj
        println!("EventID : {}", _event_id);
        println!("Message : Suspicious Command Line");
        println!("Result  : {}", _result);
        println!("Command : {}", _command_line);
        println!("Decoded : {}", _decoded);
    }
}

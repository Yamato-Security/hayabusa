use crate::models::event;
use std::collections::HashMap;

pub struct Sysmon {
    checkunsigned: u64,
}

impl Sysmon {
    pub fn new() -> Sysmon {
        Sysmon {
            //checkunsigned: 0,
            checkunsigned: 1,
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
        if let Some(_date) = event_data.get("UtcTime") {
            println!("Date    : {} (UTC)", _date);
        }
        println!("Log     : Sysmon");
        println!("EventID : 1");
        //if let Some(_creater) = event_data.get("ParentImage") {
        //    println!("_creater : {}", _image);
        //}
        if let Some(_command_line) = event_data.get("CommandLine") {
            self.check_command("1", event_data);
            println!("Command : {}", _command_line);
        }
        println!("");
    }

    fn check_for_unsigned_files(&mut self, event_data: HashMap<String, String>) {
        // Check for unsigned EXEs/DLLs:
        // This can be very chatty, so it's disabled.
        // Set $checkunsigned to 1 (global variable section) to enable:
        if self.checkunsigned == 1 {
            if let Some(_date) = event_data.get("UtcTime") {
                println!("Date    : {} (UTC)", _date);
            }
            println!("Log     : Sysmon");
            println!("EventID : 7");
            //# TBD
            println!("");
        }
    }

    fn check_command(&mut self, event_id: String, event_data: HashMap<String, String>) {
        //# TBD
    }
}

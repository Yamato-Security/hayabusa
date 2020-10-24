use crate::models::event;
use crate::detections::utils::check_command;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;

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
            let minlength = 1000;
            let mut f = File::open("whitelist.txt").expect("file not found");
            let mut contents = String::new();
            f.read_to_string(&mut contents);
            let rdr = csv::Reader::from_reader(contents.as_bytes());
            if let Some(_creater) = event_data.get("ParentImage") {
                check_command(1, _command_line, minlength, 0, "", _creater, rdr);
            } else {
                check_command(1, _command_line, minlength, 0, "", "", rdr);
            }
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
                }
            }
        }
    }
}

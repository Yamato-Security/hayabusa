use crate::detections::utils::check_command;
use crate::models::event;
use std::collections::HashMap;

pub struct Sysmon {
    empty_str: String,
    checkunsigned: u64,
}

impl Sysmon {
    pub fn new() -> Sysmon {
        Sysmon {
            empty_str: String::default(),
            //checkunsigned: 0, //  DeepBlueでは0固定
            checkunsigned: 1, //  開発用に1 (configから設定可能になる予定)
        }
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
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
            let _creater = event_data.get("ParentImage").unwrap_or(&self.empty_str);
            check_command(1, _command_line, minlength, 0, "", _creater);
        }
    }

    fn check_for_unsigned_files(&mut self, event_data: HashMap<String, String>) {
        // Check for unsigned EXEs/DLLs:
        // This can be very chatty, so it's disabled.
        // Set $checkunsigned to 1 (global variable section) to enable:
        if self.checkunsigned == 1 {
            let _signed = event_data.get("Signed").unwrap_or(&self.empty_str);
            if _signed == "false" {
                let _date = event_data.get("UtcTime").unwrap_or(&self.empty_str);
                println!("Date    : {} (UTC)", _date);
                println!("Log     : Sysmon");
                println!("EventID : 7");
                println!("Message : Unsigned Image (DLL)");
                let _image = event_data.get("Image").unwrap_or(&self.empty_str);
                println!("Result  : Loaded by: {}", _image);
                let _command_line = event_data.get("ImageLoaded").unwrap_or(&self.empty_str);
                println!("Command : {}", _command_line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate quick_xml;
    use crate::detections::sysmon;
    use crate::models::event;

    #[test]
    fn test_skelton_hit() {
        assert_eq!(1,1);
    }
}

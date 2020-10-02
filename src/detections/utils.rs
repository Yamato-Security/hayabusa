extern crate csv;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::string::String;

pub fn check_command() {}

fn check_regex(string: &str, r#type: &str) -> std::string::String {
    let mut f = File::open("regexes.txt").expect("file not found");
    let mut contents = String::new();
    f.read_to_string(&mut contents);

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());

    let mut regextext = "".to_string();
    for regex in rdr.records() {
        match regex {
            /*
            data[0] is type.
            data[1] is regex.
            data[2] is string.
            */
            Ok(_data) => {
                if &_data[0] == r#type && &_data[1] == string {
                    regextext.push_str(&_data[2]);
                    regextext.push_str("\n");
                }
            }
            Err(_data) => (),
        }
    }
    return regextext;
}

fn check_creator(command: &str, creator: &str) -> std::string::String {
    let mut creatortext = "".to_string();
    if (!creator.is_empty()) {
        if (command == "powershell") {
            if (creator == "PSEXESVC") {
                creatortext.push_str("PowerShell launched via PsExec: $creator\n");
            } else if (creator == "WmiPrvSE") {
                creatortext.push_str("PowerShell launched via WMI: $creator\n");
            }
        }
    }
    return creatortext;
}

#[cfg(test)]
mod tests {
    use crate::detections::utils;
    #[test]
    fn test_check_regex() {
        let result = utils::check_regex("test", "0");
    }
}

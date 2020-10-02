extern crate csv;
extern crate regex;

use regex::Regex;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::string::String;

fn check_obfu(string: &str) -> std::string::String {
    let mut obfutext = "".to_string();
    let mut lowercasestring = string.to_lowercase();
    let mut length = lowercasestring.len();
    let mut minpercent = 0.65;
    let mut maxbinary = 0.50;

    let mut re = Regex::new(r"[a-z0-9/\;:|.]").unwrap();
    let mut caps = re.captures(&lowercasestring).unwrap();
    let noalphastring = caps.get(0).unwrap().as_str();

    re = Regex::new(r"[01]").unwrap();
    caps = re.captures(&lowercasestring).unwrap();
    let mut nobinarystring = caps.get(0).unwrap().as_str();

    if (length > 0) {
        let mut percent = ((length - noalphastring.len()) / length);
        if ((length / 100) as f64)< minpercent {
            minpercent = (length / 100) as f64;
        }
        if percent < minpercent as usize {
            re = Regex::new(r"{0:P0}").unwrap();
            let percent = &percent.to_string();
            let caps = re.captures(percent).unwrap();
            obfutext.push_str("Possible command obfuscation: only ");
            obfutext.push_str(caps.get(0).unwrap().as_str());    
            obfutext.push_str("alphanumeric and common symbols\n");
        }
        percent = ((nobinarystring.len() - length / length)  /length);
        let mut binarypercent = 1 - percent;
        if binarypercent > maxbinary as usize {
            re = Regex::new(r"{0:P0}").unwrap();
            let binarypercent = &binarypercent.to_string();
            let caps = re.captures(binarypercent).unwrap();
            obfutext.push_str("Possible command obfuscation: ");
            obfutext.push_str(caps.get(0).unwrap().as_str());
            obfutext.push_str("zeroes and ones (possible numeric or binary encoding)\n");
        }
    }
    return obfutext;
}

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
        let creatortext =
            utils::check_regex("^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$", "0");
        println!("{}", creatortext);
    }
}

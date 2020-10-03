extern crate base64;
extern crate csv;
extern crate regex;

use flate2::read::GzDecoder;
use regex::Regex;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::prelude::*;
use std::str;
use std::string::String;

pub fn check_command(
    event_id: usize,
    commandline: &str,
    minlength: usize,
    servicecmd: usize,
    servicename: &str,
    creator: &str,
) {
    let mut text = "".to_string();
    let mut base64 = "".to_string();

    let mut f = File::open("whitelist.txt").expect("file not found");
    let mut contents = String::new();
    f.read_to_string(&mut contents);

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());

    for entry in rdr.records() {
        if let Ok(_data) = entry {
            if (commandline == &_data[0]) {
                return;
            }
        }
    }
    if commandline.len() > minlength {
        text.push_str("Long Command Line: greater than ");
        text.push_str(&minlength.to_string());
        text.push_str("bytes\n");
    }
    text.push_str(&check_obfu(commandline));
    text.push_str(&check_regex(commandline, 0));
    text.push_str(&check_creator(commandline, creator));
    if (Regex::new(r"\-enc.*[A-Za-z0-9/+=]{100}")
        .unwrap()
        .is_match(commandline))
    {
        let re = Regex::new(r"^.* \-Enc(odedCommand)? ").unwrap();
        base64.push_str(&re.replace_all(commandline, ""));
    } else if (Regex::new(r":FromBase64String\(")
        .unwrap()
        .is_match(commandline))
    {
        let re = Regex::new(r"^^.*:FromBase64String\(\'*").unwrap();
        base64.push_str(&re.replace_all(commandline, ""));
        let re = Regex::new(r"\'.*$").unwrap();
        base64.push_str(&re.replace_all(&base64.to_string(), ""));
    }
    if (!base64.is_empty()) {
        if (Regex::new(r"Compression.GzipStream.*Decompress")
            .unwrap()
            .is_match(commandline))
        {
            let decoded = base64::decode(base64).unwrap();
            let mut d = GzDecoder::new(decoded.as_slice());
            let mut uncompressed = String::new();
            d.read_to_string(&mut uncompressed).unwrap();
            println!("Decoded : {}", uncompressed);
            text.push_str("Base64-encoded and compressed function\n");
        } else {
            let decoded = base64::decode(base64).unwrap();
            println!("Decoded : {}", str::from_utf8(decoded.as_slice()).unwrap());
            text.push_str("Base64-encoded function\n");
            text.push_str(&check_obfu(str::from_utf8(decoded.as_slice()).unwrap()));
            text.push_str(&check_regex(str::from_utf8(decoded.as_slice()).unwrap(), 0));
        }
    }
    if !text.is_empty() {
        if servicecmd != 0 {
            println!("Message : Suspicious Service Command");
            println!("Results : Service name: {}\n", servicename);
        } else {
            println!("Message : Suspicious Command Line");
        }
        println!("command : {}", commandline);
        println!("result : {}", text);
        println!("EventID : {}", event_id);
    }
}

fn check_obfu(string: &str) -> std::string::String {
    let mut obfutext = "".to_string();
    let mut lowercasestring = string.to_lowercase();
    let mut length = lowercasestring.len();
    let mut minpercent = 0.65;
    let mut maxbinary = 0.50;

    let mut re = Regex::new(r"[a-z0-9/¥;:|.]").unwrap();
    let mut noalphastring = "";
    if let Some(_caps) = re.captures(&lowercasestring) {
        if let Some(_data) = _caps.get(0) {
            noalphastring = _data.as_str();
        }
    }

    re = Regex::new(r"[01]").unwrap();
    let mut nobinarystring = "";
    if let Some(_caps) = re.captures(&lowercasestring) {
        if let Some(_data) = _caps.get(0) {
            nobinarystring = _data.as_str();
        }
    }

    if (length > 0) {
        let mut percent = ((length - noalphastring.len()) / length);
        if ((length / 100) as f64) < minpercent {
            minpercent = (length / 100) as f64;
        }
        if percent < minpercent as usize {
            obfutext.push_str("Possible command obfuscation: only ");

            re = Regex::new(r"{0:P0}").unwrap();
            let percent = &percent.to_string();
            if let Some(_caps) = re.captures(percent) {
                if let Some(_data) = _caps.get(0) {
                    obfutext.push_str(_data.as_str());
                }
            }

            obfutext.push_str("alphanumeric and common symbols\n");
        }
        percent = ((nobinarystring.len() - length / length) / length);
        let mut binarypercent = 1 - percent;
        if binarypercent > maxbinary as usize {
            obfutext.push_str("Possible command obfuscation: ");

            re = Regex::new(r"{0:P0}").unwrap();
            let binarypercent = &binarypercent.to_string();
            if let Some(_caps) = re.captures(binarypercent) {
                if let Some(_data) = _caps.get(0) {
                    obfutext.push_str(_data.as_str());
                }
            }

            obfutext.push_str("zeroes and ones (possible numeric or binary encoding)\n");
        }
    }
    return obfutext;
}

fn check_regex(string: &str, r#type: usize) -> std::string::String {
    let mut f = File::open("regexes.txt").expect("file not found");
    let mut contents = String::new();
    f.read_to_string(&mut contents);

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());

    let mut regextext = "".to_string();
    for regex in rdr.records() {
        if let Ok(_data) = regex {
            /*
            data[0] is type in csv.
            data[1] is regex in csv.
            data[2] is string in csv.
            */
            if &_data[0] == r#type.to_string() {
                if let Ok(_re) = Regex::new(&_data[1]) {
                    if _re.is_match(string) {
                        regextext.push_str(&_data[2]);
                        regextext.push_str("\n");
                    }
                }
            }
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
        let regextext = utils::check_regex(
            "Metasploit-style cmd with pipe (possible use of Meterpreter 'getsystem')",
            0,
        );
        println!("{}", regextext);
    }

    #[test]
    fn test_check_creator() {
        let mut creatortext = utils::check_creator("powershell", "PSEXESVC");
        assert!(creatortext == "PowerShell launched via PsExec: $creator\n");
        creatortext = utils::check_creator("powershell", "WmiPrvSE");
        assert!(creatortext == "PowerShell launched via WMI: $creator\n");
    }

    #[test]
    fn test_check_obfu() {
        let mut obfutext = utils::check_obfu("dir01");
    }

    #[test]
    fn test_check_command() {
        utils::check_command(1, "dir", 100, 100, "dir", "dir");
    }
}

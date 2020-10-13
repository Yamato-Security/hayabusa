extern crate base64;
extern crate csv;
extern crate regex;

use crate::detections::configs;
use flate2::read::GzDecoder;
use regex::Regex;
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

    let empty = "".to_string();
    for line in configs::singleton().whitelist {
        let r_str = line.get(0).unwrap_or(&empty);
        if r_str.is_empty() {
            continue;
        }

        let r = Regex::new(r_str);
        if r.is_ok() && r.unwrap().is_match(commandline) {
            return;
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
    if Regex::new(r"\-enc.*[A-Za-z0-9/+=]{100}")
        .unwrap()
        .is_match(commandline)
    {
        let re = Regex::new(r"^.* \-Enc(odedCommand)? ").unwrap();
        base64.push_str(&re.replace_all(commandline, ""));
    } else if Regex::new(r":FromBase64String\(")
        .unwrap()
        .is_match(commandline)
    {
        let re = Regex::new(r"^^.*:FromBase64String\(\'*").unwrap();
        base64.push_str(&re.replace_all(commandline, ""));
        let re = Regex::new(r"\'.*$").unwrap();
        base64.push_str(&re.replace_all(&base64.to_string(), ""));
    }
    if !base64.is_empty() {
        if Regex::new(r"Compression.GzipStream.*Decompress")
            .unwrap()
            .is_match(commandline)
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
    let lowercasestring = string.to_lowercase();
    let length = lowercasestring.len() as f64;
    let mut minpercent = 0.65;
    let maxbinary = 0.50;

    let mut re = Regex::new(r"[a-z0-9/¥;:|.]").unwrap();
    let noalphastring = re.replace_all(&lowercasestring, "");

    re = Regex::new(r"[01]").unwrap();
    let nobinarystring = re.replace_all(&lowercasestring, "");

    if length > 0.0 {
        let mut percent = (length - noalphastring.len() as f64) / length;
        if ((length / 100.0) as f64) < minpercent {
            minpercent = length / 100.0;
        }

        if percent < minpercent {
            obfutext.push_str("Possible command obfuscation: only ");
            let percent = (percent * 100.0) as usize;
            obfutext.push_str(&percent.to_string());
            obfutext.push_str("% alphanumeric and common symbols\n");
        }

        percent = ((nobinarystring.len().wrapping_sub(length as usize) as f64) / length) / length;
        let binarypercent = 1.0 - percent;
        if binarypercent > maxbinary {
            obfutext.push_str("Possible command obfuscation: ");
            let binarypercent = (binarypercent * 100.0) as usize;
            obfutext.push_str(&binarypercent.to_string());
            obfutext.push_str("% zeroes and ones (possible numeric or binary encoding)\n");
        }
    }
    return obfutext;
}

fn check_regex(string: &str, r#type: usize) -> std::string::String {
    let empty = "".to_string();
    let mut regextext = "".to_string();
    for line in configs::singleton().regex {
        let type_str = line.get(0).unwrap_or(&empty);
        if type_str != &r#type.to_string() {
            continue;
        }

        let regex_str = line.get(1).unwrap_or(&empty);
        if regex_str.is_empty() {
            continue;
        }

        let re = Regex::new(regex_str);
        if re.is_err() || re.unwrap().is_match(string) == false {
            continue;
        }

        let text = line.get(2).unwrap_or(&empty);
        if text.is_empty() {
            continue;
        }

        regextext.push_str(text);
        regextext.push_str("\n");
    }

    return regextext;
}

fn check_creator(command: &str, creator: &str) -> std::string::String {
    let mut creatortext = "".to_string();
    if !creator.is_empty() {
        if command == "powershell" {
            if creator == "PSEXESVC" {
                creatortext.push_str("PowerShell launched via PsExec: ");
                creatortext.push_str(creator);
                creatortext.push_str("\n");
            } else if creator == "WmiPrvSE" {
                creatortext.push_str("PowerShell launched via WMI: ");
                creatortext.push_str(creator);
                creatortext.push_str("\n");
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
        let regextext = utils::check_regex("\\cvtres.exe", 0);
        assert!(regextext == "Resource File To COFF Object Conversion Utility cvtres.exe\n");
    }

    #[test]
    fn test_check_creator() {
        let mut creatortext = utils::check_creator("powershell", "PSEXESVC");
        assert!(creatortext == "PowerShell launched via PsExec: PSEXESVC\n");
        creatortext = utils::check_creator("powershell", "WmiPrvSE");
        assert!(creatortext == "PowerShell launched via WMI: WmiPrvSE\n");
    }

    #[test]
    fn test_check_obfu() {
        let obfutext = utils::check_obfu("string");
        assert!(obfutext == "Possible command obfuscation: 100% zeroes and ones (possible numeric or binary encoding)\n");
    }

    #[test]
    fn test_check_command() {
        utils::check_command(1, "dir", 100, 100, "dir", "dir");

        //test return with whitelist.
        utils::check_command(
            1,
            "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"",
            100,
            100,
            "dir",
            "dir",
        );
    }
}

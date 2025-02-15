use crate::detections::configs::TimeFormatOptions;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::message::get_event_time;
use crate::detections::utils::{format_time, get_writable_color, write_color_buffer};
use base64::prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD};
use base64::Engine;
use chrono::{TimeZone, Utc};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use csv::Writer;
use encoding_rs::{UTF_16BE, UTF_16LE, UTF_8};
use infer::Type;
use regex::Regex;
use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::string::FromUtf16Error;
use std::sync::LazyLock;
use std::{fmt, str};
use termcolor::{BufferWriter, Color, ColorChoice};

static TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w+/]+").unwrap());
static BASE64_PAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<Base64String>(=*)").unwrap());

struct EvtxInfo {
    ts: String,
    computer: String,
    rec_id: String,
    file_name: String,
    event: String,
}

impl EvtxInfo {
    fn new(val: &Value, file_name: String, event: Event, ts_fmt_opt: &TimeFormatOptions) -> Self {
        let default_time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let ts = get_event_time(val, false).unwrap_or(default_time);
        let ts = format_time(&ts, false, ts_fmt_opt);
        let d = &val["Event"]["System"];
        let computer = d["Computer"].as_str().unwrap_or_default().to_string();
        let rec_id = d["EventRecordID"].as_i64().unwrap().to_string();
        Self {
            ts: ts.to_string(),
            computer,
            rec_id,
            file_name,
            event: event.to_string(),
        }
    }
}

#[derive(Clone)]
enum Event {
    Sec4688,
    Sysmon1,
    System7045,
    PwSh4104,
    PwSh4103,
    PwShClassic400,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::Sec4688 => write!(f, "Sec 4688"),
            Event::Sysmon1 => write!(f, "Sysmon 1"),
            Event::System7045 => write!(f, "Sys 7045"),
            Event::PwSh4104 => write!(f, "PwSh 4104"),
            Event::PwSh4103 => write!(f, "PwSh 4103"),
            Event::PwShClassic400 => write!(f, "PwShClassic 400"),
        }
    }
}

enum Base64Data {
    Utf8(String, String),
    Utf16Le(String, String),
    Utf16Be(String, String),
    Binary(String, Vec<u8>, Option<Type>),
    Unknown(String),
}

impl Base64Data {
    fn new(token: &str, payload: &[u8]) -> Self {
        if is_utf16_le(payload) {
            let s = utf16_le_to_string(payload).unwrap();
            return Base64Data::Utf16Le(token.to_string(), s);
        } else if is_utf16_be(payload) {
            let s = utf16_be_to_string(payload).unwrap();
            return Base64Data::Utf16Be(token.to_string(), s);
        } else if is_utf8(payload) {
            let s = str::from_utf8(payload).unwrap();
            return Base64Data::Utf8(token.to_string(), s.to_string());
        } else {
            let kind = infer::get(payload);
            if let Some(k) = kind {
                return Base64Data::Binary(token.to_string(), payload.to_vec(), Some(k));
            }
        }
        Base64Data::Unknown(token.to_string())
    }

    fn base64_str(&self) -> String {
        match self {
            Base64Data::Utf8(s, _)
            | Base64Data::Utf16Le(s, _)
            | Base64Data::Utf16Be(s, _)
            | Base64Data::Binary(s, _, _)
            | Base64Data::Unknown(s) => s.to_string(),
        }
    }

    fn decoded_str(&self) -> String {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                s.chars().filter(|&c| !c.is_control()).collect()
            }
            Base64Data::Binary(_, _, _) | Base64Data::Unknown(_) => "".to_string(),
        }
    }

    fn file_type(&self) -> String {
        match self {
            Base64Data::Utf8(_, _) | Base64Data::Utf16Le(_, _) | Base64Data::Utf16Be(_, _) => {
                "text".to_string()
            }
            Base64Data::Binary(_, _, kind) => {
                if let Some(kind) = kind {
                    kind.to_string()
                } else {
                    "Unknown".to_string()
                }
            }
            Base64Data::Unknown(_) => "Unknown".to_string(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                s.len()
            }
            Base64Data::Binary(_, bytes, _) => bytes.len(),
            Base64Data::Unknown(s) => s.len(),
        }
    }
    fn is_binary(&self) -> String {
        match self {
            Base64Data::Binary(_, _, _) | Base64Data::Unknown(_) => "Y".to_string(),
            _ => "N".to_string(),
        }
    }

    fn is_double_encoding(&self) -> String {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                match is_base64(s) {
                    true => "Y".to_string(),
                    false => "N".to_string(),
                }
            }
            _ => "N".to_string(),
        }
    }
}

impl fmt::Display for Base64Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Base64Data::Utf8(_, _) => write!(f, "UTF-8"),
            Base64Data::Utf16Le(_, _) => write!(f, "UTF-16 LE"),
            Base64Data::Utf16Be(_, _) => write!(f, "UTF-16 BE"),
            Base64Data::Binary(_, _, _) => write!(f, "Binary"),
            Base64Data::Unknown(_) => write!(f, "Unknown"),
        }
    }
}

fn is_base64(s: &str) -> bool {
    if BASE64_STANDARD_NO_PAD.decode(s).is_ok() {
        true
    } else {
        BASE64_STANDARD.decode(s).is_ok()
    }
}

fn is_utf8(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_8.decode_without_bom_handling(bytes).0.is_ascii()
}

fn is_utf16_le(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_16LE.decode_without_bom_handling(bytes).0.is_ascii()
}

fn is_utf16_be(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_16BE.decode_without_bom_handling(bytes).0.is_ascii()
}

fn extract_payload(data: &Value) -> Vec<(Value, Event)> {
    let ch = data["Event"]["System"]["Channel"].as_str();
    let id = data["Event"]["System"]["EventID"].as_i64();
    let mut values = vec![];
    if let Some(ch) = ch {
        if let Some(id) = id {
            if ch == "Security" && id == 4688 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push((v, Event::Sec4688));
            } else if ch == "Microsoft-Windows-Sysmon/Operational" && id == 1 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push((v, Event::Sysmon1));
                let v = data["Event"]["EventData"]["ParentCommandLine"].clone();
                values.push((v, Event::Sysmon1));
            } else if (ch == "Microsoft-Windows-PowerShell/Operational"
                || ch == "PowerShellCore/Operational")
                && id == 4104
            {
                let v = data["Event"]["EventData"]["ScriptBlockText"].clone();
                values.push((v, Event::PwSh4104));
            } else if (ch == "Microsoft-Windows-PowerShell/Operational"
                || ch == "PowerShellCore/Operational")
                && id == 4103
            {
                let v = data["Event"]["EventData"]["Payload"].clone();
                values.push((v, Event::PwSh4103));
            } else if ch == "Windows PowerShell" && id == 400 {
                let v = data["Event"]["EventData"]["Data"][2].clone();
                values.push((v, Event::PwShClassic400));
            } else if ch == "System" && id == 7045 {
                let v = data["Event"]["EventData"]["ImagePath"].clone();
                values.push((v, Event::System7045));
            }
        }
    }
    values
        .iter()
        .filter(|(v, _)| !v.is_null())
        .cloned()
        .collect()
}

fn tokenize(payload_str: &str) -> Vec<&str> {
    TOKEN_REGEX
        .find_iter(payload_str)
        .map(|mat| mat.as_str())
        .collect()
}

fn utf16_le_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
    let utf16_data: Vec<u16> = bytes
        .chunks(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&utf16_data)
}

fn utf16_be_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
    let utf16_data: Vec<u16> = bytes
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&utf16_data)
}

fn create_base64_extracted_record(
    file: &Path,
    possible_base64: &str,
    data: &Value,
    event: Event,
    ts_fmt_opt: &TimeFormatOptions,
) -> Vec<Vec<String>> {
    let evtx = EvtxInfo::new(data, file.to_string_lossy().to_string(), event, ts_fmt_opt);
    let mut records = Vec::new();
    for token in tokenize(possible_base64) {
        if is_base64(token) {
            if token.len() < 10 || token.chars().all(|c| c.is_alphabetic()) {
                // Skip short tokens and all alphabetic tokens
                continue;
            }
            let payload = match BASE64_STANDARD_NO_PAD.decode(token) {
                Ok(payload) => payload,
                Err(_) => BASE64_STANDARD.decode(token).unwrap(),
            };
            let b64 = Base64Data::new(token, &payload);
            if matches!(b64, Base64Data::Unknown(_)) {
                continue;
            }
            let original = possible_base64
                .replace(b64.base64_str().as_str(), "<Base64String>")
                .to_string();
            let no_pad_original = BASE64_PAD.replace_all(original.as_str(), "<Base64String>");
            if no_pad_original.contains("-<Base64String>") {
                continue;
            }
            let row = vec![
                evtx.ts.to_string(),
                evtx.computer.clone(),
                b64.base64_str(),
                b64.decoded_str(),
                no_pad_original.to_string(),
                b64.len().to_string(),
                b64.is_binary(),
                b64.is_double_encoding(),
                b64.to_string(),
                b64.file_type(),
                evtx.event.clone(),
                evtx.rec_id.clone(),
                evtx.file_name.clone(),
            ];
            records.push(row);
        }
    }
    records
}

fn process_record(data: &Value, file: &Path, opt: &TimeFormatOptions) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let payloads = extract_payload(data);
    for (payload, event) in payloads {
        let possible_base64 = payload.as_str().unwrap_or_default();
        let extracted = create_base64_extracted_record(file, possible_base64, data, event, opt);
        records.extend(extracted);
    }
    records
}

pub fn process_evtx_record_infos(
    records: &[EvtxRecordInfo],
    opt: &TimeFormatOptions,
) -> Vec<Vec<String>> {
    let mut all_records = Vec::new();
    for record in records {
        let file = PathBuf::from(&record.evtx_filepath);
        let extracted = process_record(&record.record, &file, opt);
        all_records.extend(extracted);
    }
    all_records
}

pub fn output_all(
    all_records: Vec<Vec<String>>,
    out_path: Option<&PathBuf>,
    no_color: bool,
) -> Result<(), Box<dyn Error>> {
    if all_records.is_empty() {
        write_color_buffer(
            &BufferWriter::stdout(ColorChoice::Always),
            get_writable_color(Some(Color::Rgb(255, 175, 0)), no_color),
            "No matches found.",
            true,
        )
        .ok();
        println!();
        return Ok(());
    }
    if let Some(out_path) = out_path {
        let mut wtr = Writer::from_path(out_path)?;
        let csv_header = vec![
            "Timestamp",
            "Computer",
            "Base64 String",
            "Decoded String",
            "Original Field",
            "Length",
            "Binary",
            "Double Encoding",
            "Encoding",
            "File Type",
            "Event",
            "Record ID",
            "File Name",
        ];
        wtr.write_record(csv_header)?;
        for row in all_records.clone().iter_mut() {
            let binary = row[6].as_str();
            if binary == "Y" {
                row[3] = "(Binary Data)".to_string();
            }
            wtr.write_record(row)?;
        }
        wtr.flush()?;
    } else {
        let term_header = ["Timestamp", "Computer", "Base64 String", "Decoded String"];
        let term_header_cells: Vec<Cell> = term_header
            .iter()
            .map(|s| Cell::new(s).set_alignment(CellAlignment::Center))
            .collect();
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::DynamicFullWidth)
            .set_header(term_header_cells);
        for row in all_records.clone().iter_mut() {
            let binary = row[6].as_str();
            if binary == "Y" {
                row[3] = "(Binary Data)".to_string();
            }
            table.add_row(&row[0..4]);
        }
        println!("{table}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_base64() {
        assert!(is_base64("SGVsbG8sIHdvcmxkIQ"));
        assert!(is_base64("SGVsbG8sIHdvcmxkIQ=="));
        assert!(!is_base64("Hello, world!"));
    }

    #[test]
    fn test_is_utf8() {
        assert!(is_utf8("Hello, world!".as_bytes()));
        assert!(!is_utf8("こんにちは、世界！".as_bytes()));
    }

    #[test]
    fn test_is_utf16() {
        let utf16le_bytes = vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let utf16be_bytes = vec![0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F];
        assert!(is_utf16_le(utf16le_bytes.as_slice()));
        assert!(!is_utf16_le(utf16be_bytes.as_slice()));
        assert!(is_utf16_be(utf16be_bytes.as_slice()));
        assert!(!is_utf16_be(utf16le_bytes.as_slice()));
    }

    #[test]
    fn utf16_le_to_string_with_valid_utf16le_bytes() {
        let bytes = vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let result = utf16_le_to_string(&bytes).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn utf16_be_to_string_with_valid_utf16be_bytes() {
        let bytes = vec![0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F];
        let result = utf16_be_to_string(&bytes).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_process_record() {
        let data = json!({
            "Event": {
                "System": {
                    "Channel": "Security",
                    "EventID": 4688,
                    "TimeCreated_attributes": {
                        "SystemTime": "2021-12-23T00:00:00.000Z"
                    },
                    "Computer": "HAYABUSA-DESKTOP",
                    "EventRecordID": 12345
                },
                "EventData": {
                    "CommandLine": "dGVzdCBjb21tYW5k" // base64 for "test command"
                }
            }
        });

        let expected = vec![vec![
            "2021-12-23T00:00:00Z".to_string(),
            "HAYABUSA-DESKTOP".to_string(),
            "dGVzdCBjb21tYW5k".to_string(),
            "test command".to_string(),
            "dGVzdCBjb21tYW5k"
                .to_string()
                .replace("dGVzdCBjb21tYW5k", "<Base64String>"),
            "12".to_string(),
            "N".to_string(),
            "N".to_string(),
            "UTF-8".to_string(),
            "text".to_string(),
            "Sec 4688".to_string(),
            "12345".to_string(),
            "test.evtx".to_string(),
        ]];

        let result = process_record(
            &data,
            Path::new("test.evtx"),
            &TimeFormatOptions {
                iso_8601: true,
                ..Default::default()
            },
        );
        assert_eq!(result, expected);
    }
}

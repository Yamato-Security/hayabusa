extern crate serde;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Data {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "$value")]
    pub text: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct TimeCreated {
    #[serde(rename = "SystemTime")]
    pub system_time: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Execution {
    #[serde(rename = "ProcessID")]
    process_id: i32,
    #[serde(rename = "ThreadID")]
    thread_id: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Provider {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Guid")]
    guid: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct System {
    #[serde(rename = "Provider")]
    pub provider: Provider,
    #[serde(rename = "EventID")]
    pub event_id: String,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Level")]
    level: String,
    #[serde(rename = "Task")]
    task: String,
    #[serde(rename = "Opcode")]
    opcode: Option<String>,
    #[serde(rename = "Keywords")]
    keywords: String,
    #[serde(rename = "TimeCreated")]
    pub time_created: TimeCreated,
    #[serde(rename = "EventRecordID")]
    pub event_record_id: String,
    #[serde(rename = "Correlation")]
    correlation: Option<String>,
    #[serde(rename = "Execution")]
    execution: Option<Execution>,
    #[serde(rename = "Channel")]
    pub channel: String, // Security, System, Application ...etc
    #[serde(rename = "Computer")]
    computer: String,
    #[serde(rename = "Security")]
    security: String,
    #[serde(rename = "Message")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EventData {
    #[serde(rename = "Data")]
    pub data: Option<Vec<Data>>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct UserData {
    #[serde(rename = "LogFileCleared")]
    pub log_file_cleared: Option<LogFileCleared>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LogFileCleared {
    #[serde(rename = "SubjectUserSid")]
    pub subject_user_sid: Option<String>,
    #[serde(rename = "SubjectUserName")]
    pub subject_user_name: Option<String>,
    #[serde(rename = "SubjectDomainName")]
    pub subject_domain_name: Option<String>,
    #[serde(rename = "SubjectLogonId")]
    pub subject_logon_id: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Evtx {
    #[serde(rename = "System")]
    pub system: System,
    #[serde(rename = "EventData")]
    pub event_data: Option<EventData>,
    #[serde(rename = "UserData")]
    pub user_data: Option<UserData>,
}

impl Evtx {
    //
    // 文字列データを取得する
    //
    fn get_string(v: &Data) -> String {
        let mut ret = "".to_string();
        if let Some(text) = &v.text {
            ret = text.to_string();
        }
        return ret;
    }

    //
    // EventDataをHashMapとして取得する
    //
    pub fn parse_event_data(&self) -> HashMap<String, String> {
        let mut values = HashMap::new();

        if let Some(event_data) = &self.event_data {
            if let Some(data) = &event_data.data {
                for v in data.iter() {
                    if let Some(name) = &v.name {
                        values.insert(name.to_string(), Evtx::get_string(v));
                    }
                }
            }
        }

        values
    }
}

extern crate serde;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Data {
    pub Name: Option<String>,
    #[serde(rename = "$value")]
    pub Text: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct TimeCreated {
    SystemTime: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Execution {
    ProcessID: i32,
    ThreadID: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Provider {
    Name: Option<String>,
    Guid: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct System {
    Provider: Provider,
    pub EventID: String,
    Version: Option<String>,
    Level: String,
    Task: String,
    Opcode: Option<String>,
    Keywords: String,
    TimeCreated: TimeCreated,
    EventRecordID: String,
    Correlation: Option<String>,
    Execution: Option<Execution>,
    pub Channel: String, // Security, System, Application ...etc
    Computer: String,
    Security: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EventData {
    pub Data: Option<Vec<Data>>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Evtx {
    pub System: System,
    pub EventData: Option<EventData>,
}

impl Evtx {
    
    //
    // 文字列データを取得する
    //
    fn get_string(v: &Data) -> String {
    
        match &v.Text {
            Some(text) => {
                return text.to_string();
            },
            _ => return "".to_string(),
        }
    }
    
    //
    // EventDataをHashMapとして取得する
    //
    pub fn parse_event_data(self) -> HashMap<String,String> {
        let mut values = HashMap::new();
    
        match self.EventData {
            Some(event_data) =>
                match event_data.Data {
                    Some(data) => {
                        for v in data.iter() {
                            match &v.Name {
                                Some(name) => {
                                    values.insert(name.to_string(), Evtx::get_string(v));
                                },
                                None => (),
                            }
                        }
                    },
                    None => (),
                },
            None => (),
        }
    
        values
    }
}

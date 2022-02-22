use hashbrown::HashMap;
use hashbrown::HashSet;
use lazy_static::lazy_static;
use serde_json::Value;
use std::sync::RwLock;

use crate::detections::configs;
use crate::detections::utils::get_serde_number_to_string;

#[derive(Debug)]
pub struct PivotKeyword {
    pub keywords: HashMap<String, HashSet<String>>,
    pub fields: HashMap<String, HashSet<String>>,
}

lazy_static! {
    pub static ref PIVOT_KEYWORD: RwLock<PivotKeyword> = RwLock::new(PivotKeyword::new());
}

impl PivotKeyword {
    pub fn new() -> PivotKeyword {
        let mut pivot_keyword = PivotKeyword {
            keywords: HashMap::new(),
            fields: HashMap::new(),
        };
        pivot_keyword
            .keywords
            .insert("Users".to_string(), HashSet::new());
        pivot_keyword
            .keywords
            .insert("Logon IDs".to_string(), HashSet::new());
        pivot_keyword
            .keywords
            .insert("Workstation Names".to_string(), HashSet::new());
        pivot_keyword
            .keywords
            .insert("Ip Addresses".to_string(), HashSet::new());
        pivot_keyword
            .keywords
            .insert("Processes".to_string(), HashSet::new());

        pivot_keyword
            .fields
            .insert("Users".to_string(), HashSet::new());
        pivot_keyword
            .fields
            .insert("Logon IDs".to_string(), HashSet::new());
        pivot_keyword
            .fields
            .insert("Workstation Names".to_string(), HashSet::new());
        pivot_keyword
            .fields
            .insert("Ip Addresses".to_string(), HashSet::new());
        pivot_keyword
            .fields
            .insert("Processes".to_string(), HashSet::new());
        return pivot_keyword;
    }

    pub fn insert_pivot_keyword(&mut self, event_record: &Value) {
        for (key, fields) in self.fields.iter() {
            for field in fields {
                if let Some(array_str) = configs::EVENTKEY_ALIAS.get_event_key(&String::from(field))
                {
                    let split: Vec<&str> = array_str.split(".").collect();
                    let mut is_exist_event_key = false;
                    let mut tmp_event_record: &Value = event_record.into();
                    for s in split {
                        if let Some(record) = tmp_event_record.get(s) {
                            is_exist_event_key = true;
                            tmp_event_record = record;
                        }
                    }
                    if is_exist_event_key {
                        let hash_value = get_serde_number_to_string(tmp_event_record);

                        if hash_value.is_some() {
                            match key.as_str() {
                                "Workstation Names" => {
                                    if hash_value.as_ref().unwrap() == "-" {
                                        continue;
                                    }
                                    self.keywords
                                        .get_mut("Workstation Names")
                                        .unwrap()
                                        .insert(hash_value.unwrap())
                                }
                                "Ip Addresses" => {
                                    if hash_value.as_ref().unwrap() == "-"
                                        || hash_value.as_ref().unwrap() == "127.0.0.1"
                                    {
                                        continue;
                                    }
                                    self.keywords
                                        .get_mut("Ip Addresses")
                                        .unwrap()
                                        .insert(hash_value.unwrap())
                                }
                                k => self
                                    .keywords
                                    .get_mut(k)
                                    .unwrap()
                                    .insert(hash_value.unwrap()),
                            };
                        };
                    }
                }
            }
        }
    }
}

use crate::detections::configs;
use crate::detections::utils::get_serde_number_to_string;
use hashbrown::HashMap;
use hashbrown::HashSet;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct PivotKeyword {
    pub users: HashSet<String>,
    pub logon_ids: HashSet<String>,
    pub workstation_names: HashSet<String>,
    pub ip_addresses: HashSet<String>,
    pub processes: HashSet<String>,
}

/*
*** fields mapping ***
Users: %SubjectUserName%, %TargetUserName%, %User%
Logon IDs: %SubjectLogonId%,%TargetLogonId%
Workstation Names: %WorkstationName%
IP Addresses: %IpAddress%
Processes: %Image%
*/

impl PivotKeyword {
    pub fn get_pivot_keyword(&mut self, event_record: &Value) {
        let mut fields = HashMap::new();
        fields.insert("SubjectUserName", "users");
        fields.insert("TargetUserName", "users");
        fields.insert("User", "users");
        fields.insert("SubjectLogonId", "logon_ids");
        fields.insert("TargetLogonId", "logon_ids");
        fields.insert("WorkstationName", "workstation_names");
        fields.insert("IpAddress", "ip_addresses");
        fields.insert("Image", "processes");

        for field in fields {
            if let Some(array_str) = configs::EVENTKEY_ALIAS.get_event_key(&String::from(field.0)) {
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
                        match field.1 {
                            "users" => self.users.insert(hash_value.unwrap()),
                            "logon_ids" => self.logon_ids.insert(hash_value.unwrap()),
                            "workstation_names" => {
                                if hash_value.as_ref().unwrap() == "-" {
                                    continue;
                                }
                                self.workstation_names.insert(hash_value.unwrap())
                            }
                            "ip_addresses" => {
                                if hash_value.as_ref().unwrap() == "-"
                                    || hash_value.as_ref().unwrap() == "127.0.0.1"
                                {
                                    continue;
                                }
                                self.ip_addresses.insert(hash_value.unwrap())
                            }
                            "processes" => self.processes.insert(hash_value.unwrap()),
                            _ => true,
                        };
                    };
                }
            }
        }
    }
}

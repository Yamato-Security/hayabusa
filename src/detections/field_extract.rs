use hashbrown::HashMap;
use serde_json::Value;

pub fn extract_fields(
    channel: Option<String>,
    event_id: Option<String>,
    data: &mut Value,
    key_2_values: &mut HashMap<String, String>,
) {
    if let Some(ch) = channel {
        if let Some(eid) = event_id {
            if ch == "Windows PowerShell"
                && (eid == "400" || eid == "403" || eid == "600" || eid == "800")
            {
                let target_data_index = if eid == "800" { 1 } else { 2 };
                extract_powershell_classic_fields(data, target_data_index, key_2_values);
            }
        }
    }
}

fn extract_powershell_classic_fields(
    data: &mut Value,
    data_index: usize,
    key_2_values: &mut HashMap<String, String>,
) -> Option<Value> {
    match data {
        Value::Object(map) => {
            let mut extracted_fields = None;
            for (_, val) in &mut *map {
                extracted_fields = extract_powershell_classic_fields(val, data_index, key_2_values);
                if extracted_fields.is_some() {
                    break;
                }
            }
            match extracted_fields {
                Some(Value::Object(fields)) => {
                    for (key, val) in fields {
                        map.insert(key.clone(), val.clone());
                        match val {
                            Value::String(s) => {
                                key_2_values.insert(key, s.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Value::Array(vec) => {
            if let Some(val) = vec.get(data_index) {
                if let Some(powershell_data_str) = val.as_str() {
                    let fields_data: std::collections::HashMap<&str, &str> = powershell_data_str
                        .trim()
                        .split("\n\t")
                        .map(|s| s.trim_end_matches("\r\n").trim_end_matches('\r'))
                        .filter_map(|s| s.split_once('='))
                        .collect();
                    match serde_json::to_value(fields_data) {
                        Ok(extracted_fields) => {
                            return Some(extracted_fields);
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::detections::field_extract::extract_fields;
    use hashbrown::HashMap;
    use serde_json::Value;

    #[test]
    fn test_powershell_classic_data_fields_extraction_400() {
        let record_json_str = r#"
{
    "Event": {
        "System": {
            "EventID": 400,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "None",
                "NewEngineState=Available"
            ]
        }
    }
}"#;

        let mut val = serde_json::from_str(record_json_str).unwrap();
        let mut key2values: HashMap<String, String> = HashMap::new();
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("400".to_string()),
            &mut val,
            &mut key2values,
        );
        let extracted_fields = val
            .get("Event")
            .unwrap()
            .get("EventData")
            .unwrap()
            .get("NewEngineState")
            .unwrap();
        assert_eq!(extracted_fields, &Value::String("Available".to_string()));
    }

    #[test]
    fn test_powershell_classic_data_fields_extraction_800() {
        let record_json_str = r#"
{
    "Event": {
        "System": {
            "EventID": 800,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "NewEngineState=Available",
                "None"
            ]
        }
    }
}"#;

        let mut val = serde_json::from_str(record_json_str).unwrap();
        let mut key2values: HashMap<String, String> = HashMap::new();
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("800".to_string()),
            &mut val,
            &mut key2values,
        );
        let extracted_fields = val
            .get("Event")
            .unwrap()
            .get("EventData")
            .unwrap()
            .get("NewEngineState")
            .unwrap();
        assert_eq!(extracted_fields, &Value::String("Available".to_string()));
    }

    #[test]
    fn test_powershell_classic_data_fields_extraction_400_data_2_missing() {
        let record_json_str = r#"
{
    "Event": {
        "System": {
            "EventID": 400,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "None"
            ]
        }
    }
}"#;

        let original_val: Value = serde_json::from_str(record_json_str).unwrap();
        let mut val = serde_json::from_str(record_json_str).unwrap();
        let mut key2values: HashMap<String, String> = HashMap::new();
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("400".to_string()),
            &mut val,
            &mut key2values,
        );
        assert_eq!(original_val, val);
    }
}

use itertools::enumerate;
use serde_json::Value;

pub fn extract_fields(channel: Option<String>, event_id: Option<String>, data: &mut Value) {
    if let Some(ch) = channel {
        if let Some(eid) = event_id {
            if ch == "Windows PowerShell"
                && (eid == "400" || eid == "403" || eid == "600" || eid == "800")
            {
                let data_field_index = if eid == "800" { 1 } else { 2 };
                extract_powershell_classic_data_fields(data, data_field_index);
            }
        }
    }
}

fn extract_powershell_classic_data_fields(data: &mut Value, data_field_index: usize) {
    match data {
        Value::Object(map) => {
            for (_, val) in map {
                extract_powershell_classic_data_fields(val, data_field_index);
            }
        }
        Value::Array(vec) => {
            for (i, val) in enumerate(vec) {
                if i == data_field_index {
                    if let Some(powershell_data_str) = val.as_str() {
                        let map_val: std::collections::HashMap<&str, &str> = powershell_data_str
                            .trim()
                            .split("\n\t")
                            .map(|s| s.trim_end_matches("\r\n"))
                            .filter_map(|s| s.split_once('='))
                            .collect();
                        if let Ok(extracted_fields) = serde_json::to_value(map_val) {
                            *val = extracted_fields
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::field_extract::extract_fields;
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
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("400".to_string()),
            &mut val,
        );
        let extracted_fields = val
            .get("Event")
            .unwrap()
            .get("EventData")
            .unwrap()
            .get("Data")
            .unwrap()
            .get(2)
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
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("800".to_string()),
            &mut val,
        );
        let extracted_fields = val
            .get("Event")
            .unwrap()
            .get("EventData")
            .unwrap()
            .get("Data")
            .unwrap()
            .get(1)
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
        extract_fields(
            Some("Windows PowerShell".to_string()),
            Some("400".to_string()),
            &mut val,
        );
        assert_eq!(original_val, val);
    }
}

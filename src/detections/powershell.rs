use crate::models::event;
use std::collections::HashMap;

pub struct PowerShell {}

impl PowerShell {
    pub fn new() -> PowerShell {
        PowerShell {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        if event_id == "4103" {
            &self.execute_pipeline(&event_data);
        } else if event_id == "4104" {
            &self.execute_remote_command(&event_data);
        }
    }

    fn execute_pipeline(&mut self, _event_data: &HashMap<String, String>) {
        // PowerShell Error Code: 4103 is absent.
        // ToDo: Correct Log & Check
        return;
    }

    fn execute_remote_command(&mut self, event_data: &HashMap<String, String>) {
        println!(
            "<Execute Remote Command from Powershell Log>
    Path: {}
    MessageTotal: {}
    ScriptBlockText: {}
    ScriptBlockId: {}
    MessageNumber: {}",
            event_data.get("Path").unwrap_or(&String::from("")),
            event_data.get("MessageTotal").unwrap_or(&String::from("")),
            event_data
                .get("ScriptBlockText")
                .unwrap_or(&String::from("")),
            event_data
                .get("ScriptBlockId")
                .unwrap_or(&String::from("")),
            event_data.get("MessageNumber").unwrap_or(&String::from("")),
        );

        return;
    }
}

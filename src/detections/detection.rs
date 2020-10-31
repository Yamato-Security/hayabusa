extern crate csv;
extern crate quick_xml;

use crate::detections::application;
use crate::detections::applocker;
use crate::detections::common;
use crate::detections::powershell;
use crate::detections::security;
use crate::detections::sysmon;
use crate::detections::system;
use crate::models::event;
use evtx::EvtxParser;
use quick_xml::de::DeError;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Detection {
    timeline_list: BTreeMap<String, String>,
}

impl Detection {
    pub fn new() -> Detection {
        Detection {
            timeline_list: BTreeMap::new(),
        }
    }

    pub fn start(&mut self, mut parser: EvtxParser<std::fs::File>) -> Result<(), DeError> {
        let mut common: common::Common = common::Common::new();
        let mut security = security::Security::new();
        let mut system = system::System::new();
        let mut application = application::Application::new();
        let mut applocker = applocker::AppLocker::new();
        let mut sysmon = sysmon::Sysmon::new();
        let mut powershell = powershell::PowerShell::new();

        for record in parser.records() {
            match record {
                Ok(r) => {
                    let event: event::Evtx = quick_xml::de::from_str(&r.data)?;
                    let event_id = event.system.event_id.to_string();
                    let channel = event.system.channel.to_string();
                    let event_data = event.parse_event_data();

                    &common.detection(&event.system, &event_data);
                    if channel == "Security" {
                        &security.detection(event_id, &event.system, &event.user_data, event_data);
                    } else if channel == "System" {
                        &system.detection(event_id, &event.system, event_data);
                    } else if channel == "Application" {
                        &application.detection(event_id, &event.system, event_data);
                    } else if channel == "Microsoft-Windows-PowerShell/Operational" {
                        &powershell.detection(event_id, &event.system, event_data);
                    } else if channel == "Microsoft-Windows-Sysmon/Operational" {
                        &sysmon.detection(event_id, &event.system, event_data);
                    } else if channel == "Microsoft-Windows-Applocker/Operational" {
                        &applocker.detection(event_id, &event.system, event_data);
                    } else {
                        //&other.detection();
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }

        ////////////////////////////
        // 表示
        ////////////////////////////
        common.disp();
        security.disp();

        return Ok(());
    }
}

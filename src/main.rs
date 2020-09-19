extern crate serde;
extern crate quick_xml;

use evtx::EvtxParser;
use std::env;
use std::process;
use std::path::PathBuf;
use quick_xml::de::{DeError};
use yamato_event_analyzer::models::event;
use yamato_event_analyzer::detections::security;
use yamato_event_analyzer::detections::system;
use yamato_event_analyzer::detections::application;

fn main() -> Result<(), DeError> {

    let args: Vec<String> = env::args().collect();
    let fp: PathBuf;
    if (args.len() > 1) {
        fp = PathBuf::from(args[1].to_string());
    } else {
        fp = PathBuf::from(format!("./samples/security.evtx"));
    }
    
    
    let mut security = security::Security::new();
    let mut system = system::System::new();
    let mut application = application::Application::new();
    let mut parser = match EvtxParser::from_path(fp) {
        Ok(pointer) => pointer,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        },
    };
        
    for record in parser.records() {
        match record {
            Ok(r) => {
                let event: event::Evtx = quick_xml::de::from_str(&r.data)?;
                let event_id = event.System.EventID.to_string();

                if event.System.Channel == "Security" {
                    let event_data = event.parse_event_data();
                    &security.detection(event_id, event_data);
                } else if event.System.Channel == "System" {
                    &system.detection();
                } else if event.System.Channel == "Application" {
                    &application.detection();
                }
            },
            Err(e) => eprintln!("{}", e),
        }
    }

    ////////////////////////////
    // 表示
    ////////////////////////////
    security.disp();

    Ok(())
}


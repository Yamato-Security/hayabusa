extern crate serde;
extern crate quick_xml;

use evtx::EvtxParser;
use std::env;
use std::process;
use std::path::PathBuf;
use std::collections::HashMap;
use quick_xml::de::{DeError};
use yamato_event_analyzer::models::event;
use yamato_event_analyzer::detections::security;

fn main() -> Result<(), DeError> {

    let args: Vec<String> = env::args().collect();
    let fp: PathBuf;
    if (args.len() > 1) {
        fp = PathBuf::from(args[1].to_string());
    } else {
        fp = PathBuf::from(format!("./samples/security.evtx"));
    }
    
    let alert_all_admin = 0;
    let mut total_admin_logons = 0;
    let mut admin_logons: HashMap<String, HashMap<String, i32>> = HashMap::new();
    let mut multiple_admin_logons: HashMap<String, i32> = HashMap::new();
    
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
                // ログがSecurity.evtxなら
                if (event.System.Channel == "Security") {
                    if (event.System.EventID == "4672") {
                        let event_data = event.parse_event_data();
                        security::se_debug_privilege(event_data, alert_all_admin, &mut total_admin_logons,
                            &mut admin_logons, &mut multiple_admin_logons);
                    }
                }
            },
            Err(e) => eprintln!("{}", e),
        }
    }

    if (total_admin_logons > 0) {
        println!("total_admin_logons:{}", total_admin_logons);
        println!("admin_logons:{:?}", admin_logons);
        println!("multiple_admin_logons:{:?}", multiple_admin_logons);
    }

    Ok(())
}


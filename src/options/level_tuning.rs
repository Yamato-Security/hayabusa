use crate::detections::{configs, print::AlertMessage, utils};
use crate::filter;
use crate::yaml::ParseYaml;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufWriter;
use std::io::{Read, Write};

pub struct LevelTuning {}

impl LevelTuning {
    pub fn run(level_tuning_config_path: &str) {
        let read_result = utils::read_csv(level_tuning_config_path);
        if read_result.is_err() {
            AlertMessage::warn(
                &mut BufWriter::new(std::io::stderr().lock()),
                read_result.as_ref().unwrap_err(),
            )
            .ok();
            return;
        }
        let mut tuning_map: HashMap<String, String> = HashMap::new();
        read_result.unwrap().into_iter().for_each(|line| {
            if line.len() != 2 {
                return;
            }
            let id = line.get(0).unwrap();
            // TODO: id validation
            let level = line.get(1).unwrap();
            // TODO: level validation
            // Cut Comments
            tuning_map.insert(id.to_string(), level.to_string());
        });
        let mut rulefile_loader = ParseYaml::new();
        let result_readdir = rulefile_loader.read_dir(
            configs::CONFIG
                .read()
                .unwrap()
                .args
                .value_of("rules")
                .unwrap_or("rules"),
            "informational",
            &filter::exclude_ids(),
        );
        if result_readdir.is_err() {
            let errmsg = format!("{}", result_readdir.unwrap_err());
            AlertMessage::warn(&mut BufWriter::new(std::io::stderr().lock()), &errmsg).ok();
            return;
        }

        for (path, rule) in rulefile_loader.files {
            if let Some(new_level) = tuning_map.get(rule["id"].as_str().unwrap()) {
                println!("path: {}", path);
                let mut content = fs::read_to_string(&path).unwrap(); // TODO: Error Handling
                let past_level = "level: ".to_string() + rule["level"].as_str().unwrap();

                if new_level.starts_with("informational") {
                    content = content.replace(&past_level, "level: informational");
                }
                if new_level.starts_with("low") {
                    content = content.replace(&past_level, "level: informational");
                }
                if new_level.starts_with("medium") {
                    content = content.replace(&past_level, "level: medium");
                }
                if new_level.starts_with("high") {
                    content = content.replace(&past_level, "level: high");
                }
                if new_level.starts_with("critical") {
                    content = content.replace(&past_level, "level: critical");
                }

                let mut file = match File::options()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                {
                    Err(e) => panic!("Couldn't open {}: {}", path, e),
                    Ok(file) => file,
                };

                file.write_all(content.as_bytes()).unwrap(); // TODO: use result
                println!(
                    "level: {} -> {}",
                    rule["level"].as_str().unwrap(),
                    new_level
                );
            }
        }
    }
}

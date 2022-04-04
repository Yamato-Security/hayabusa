use crate::detections::{configs, utils};
use crate::filter;
use crate::yaml::ParseYaml;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
pub struct LevelTuning {}

impl LevelTuning {
    pub fn run(level_tuning_config_path: &str) -> Result<(), String> {
        let read_result = utils::read_csv(level_tuning_config_path);
        if read_result.is_err() {
            return Result::Err(read_result.as_ref().unwrap_err().to_string());
        }

        // Read Tuning files
        let mut tuning_map: HashMap<String, String> = HashMap::new();
        read_result.unwrap().into_iter().try_for_each(|line| -> Result<(), String> {
            let id = match line.get(0) {
                Some(_id) => {
                    if !configs::IDS_REGEX.is_match(_id) {
                        return Result::Err(format!("Failed to read level tuning file. {} is not correct id format, fix it.", _id));
                    }
                    _id
                }
                _ => return Result::Err("Failed to read id...".to_string())
            };
            let level = match line.get(1) {
                Some(_level) => {
                    if _level.starts_with("informational")
                        || _level.starts_with("low")
                        || _level.starts_with("medium")
                        || _level.starts_with("high")
                        || _level.starts_with("critical") {
                            _level
                        } else {
                            return Result::Err("level tuning file's level must in informational, low, medium, high, critical".to_string())
                        }
                    }
                _ => return Result::Err("Failed to read level...".to_string())
            };
            tuning_map.insert(id.to_string(), level.to_string());
            Ok(())
        })?;

        // Read Rule files
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
            return Result::Err(format!("{}", result_readdir.unwrap_err()));
        }

        // Convert rule files
        for (path, rule) in rulefile_loader.files {
            if let Some(new_level) = tuning_map.get(rule["id"].as_str().unwrap()) {
                println!("path: {}", path);
                let mut content = match fs::read_to_string(&path) {
                    Ok(_content) => _content,
                    Err(e) => return Result::Err(e.to_string()),
                };
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

                let mut file = match File::options().write(true).truncate(true).open(&path) {
                    Ok(file) => file,
                    Err(e) => return Result::Err(e.to_string()),
                };

                file.write_all(content.as_bytes()).unwrap();
                println!(
                    "level: {} -> {}",
                    rule["level"].as_str().unwrap(),
                    new_level
                );
            }
        }
        Result::Ok(())
    }
}

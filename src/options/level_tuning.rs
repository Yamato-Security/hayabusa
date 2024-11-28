use crate::detections::configs::StoredStatic;
use crate::detections::utils::write_color_buffer;
use crate::detections::{configs, utils};
use crate::filter::RuleExclude;
use crate::yaml::ParseYaml;
use hashbrown::HashMap;
use std::fs::{self, File};
use std::io::Write;
use termcolor::{BufferWriter, ColorChoice};

pub struct LevelTuning {}

impl LevelTuning {
    pub fn run(
        level_tuning_config_path: &str,
        rules_path: &str,
        stored_static: &StoredStatic,
    ) -> Result<(), String> {
        let read_result = match utils::read_csv(level_tuning_config_path) {
            Ok(c) => c,
            Err(e) => return Result::Err(e.to_string()),
        };

        // Read Tuning files
        let mut tuning_map: HashMap<String, String> = HashMap::new();
        read_result.iter().try_for_each(|line| -> Result<(), String> {
            // 1つ目の要素も存在しない場合はread_csvの段階で読み飛ばされるためget(0)がNoneにはならない
            let id = line.first().unwrap();
            if !configs::IDS_REGEX.is_match(id) {
                return Result::Err(format!("Failed to read level tuning file. {id} is not correct id format, fix it."));
            }

            let level = match line.get(1) {
                Some(_level) => {
                    if _level.starts_with("informational")
                        || _level.starts_with("low")
                        || _level.starts_with("medium")
                        || _level.starts_with("high")
                        || _level.starts_with("critical") {
                            _level.split('#').collect::<Vec<&str>>()[0].to_string()
                        } else if _level.starts_with("info"){
                            _level.split('#').collect::<Vec<&str>>()[0].to_string().replace("info", "informational")
                        }
                        else {
                            return Result::Err("level tuning file's level must in informational, low, medium, high, critical".to_string())
                        }
                    }
                // headerに2つ以上の列が存在していない場合このエラーが発生する
                _ => return Result::Err("Failed to read level...".to_string())
            };
            tuning_map.insert(id.to_string(), level);
            Ok(())
        })?;

        // Read Rule files
        let mut rulefile_loader = ParseYaml::new(stored_static);
        //noisy rules and exclude rules treats as update target
        let result_readdir = rulefile_loader.read_dir(
            rules_path,
            "informational",
            "",
            &RuleExclude::new(),
            stored_static,
        );
        if result_readdir.is_err() {
            return Result::Err(format!("{}", result_readdir.unwrap_err()));
        }

        // Convert rule files
        for (path, rule) in rulefile_loader.files {
            match tuning_map.get(rule["id"].as_str().unwrap()) { Some(new_level) => {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &format!("path: {path}"),
                    true,
                )
                .ok();
                let mut content = match fs::read_to_string(&path) {
                    Ok(_content) => _content,
                    Err(e) => return Result::Err(e.to_string()),
                };
                let past_level = "level: ".to_string() + rule["level"].as_str().unwrap();

                if new_level.starts_with("informational") || new_level.starts_with("info") {
                    content = content.replace(&past_level, "level: informational");
                }
                if new_level.starts_with("low") {
                    content = content.replace(&past_level, "level: low");
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
                file.flush().unwrap();
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    &format!(
                        "level: {} -> {}",
                        rule["level"].as_str().unwrap(),
                        new_level
                    ),
                    true,
                )
                .ok();
            } _ => {}}
        }
        println!();
        Result::Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::path::Path;

    use super::*;
    use crate::detections::configs::{Action, CommonOptions, Config, LevelTuningOption};

    fn create_dummy_stored_static(level_tuning_path: &str) -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(Action::LevelTuning(LevelTuningOption {
                level_tuning: Path::new(level_tuning_path).to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
            })),
            debug: false,
        }))
    }

    #[test]
    fn rule_level_failed_to_open_file() {
        let level_tuning_config_path = "./none.txt";
        let dummy_stored_static = create_dummy_stored_static(level_tuning_config_path);
        let res = LevelTuning::run(level_tuning_config_path, "", &dummy_stored_static);
        let expected = Result::Err("Cannot open file. [file:./none.txt]".to_string());
        assert_eq!(res, expected);
    }

    #[test]
    fn rule_level_id_error_file() {
        let level_tuning_config_path = "./test_files/config/level_tuning_error1.txt";
        let dummy_stored_static = create_dummy_stored_static(level_tuning_config_path);
        let res = LevelTuning::run(level_tuning_config_path, "", &dummy_stored_static);
        let expected = Result::Err("Failed to read level tuning file. 12345678-1234-1234-1234-12 is not correct id format, fix it.".to_string());
        assert_eq!(res, expected);
    }

    #[test]
    fn rule_level_level_error_file() {
        let level_tuning_config_path = "./test_files/config/level_tuning_error2.txt";
        let dummy_stored_static = create_dummy_stored_static(level_tuning_config_path);
        let res = LevelTuning::run(level_tuning_config_path, "", &dummy_stored_static);
        let expected = Result::Err(
            "level tuning file's level must in informational, low, medium, high, critical"
                .to_string(),
        );
        assert_eq!(res, expected);
    }

    #[test]
    fn rule_level_level_error_empty_line() {
        let level_tuning_config_path = "./test_files/config/level_tuning_error3.txt";
        let dummy_stored_static = create_dummy_stored_static(level_tuning_config_path);
        let res = LevelTuning::run(level_tuning_config_path, "", &dummy_stored_static);
        let expected = Result::Err("Failed to read level...".to_string());
        assert_eq!(res, expected);
    }

    #[test]
    fn test_level_tuning_update_rule_files() {
        let level_tuning_config_path = "./test_files/config/level_tuning.txt";
        let rule_str = r#"
        id: 12345678-1234-1234-1234-123456789012
        level: informational
        "#;

        let expected_rule = r#"
        id: 12345678-1234-1234-1234-123456789012
        level: high
        "#;

        let path = "test_files/rules/level_tuning_test.yml";
        let mut file = File::create(path).unwrap();
        let buf = rule_str.as_bytes();
        file.write_all(buf).unwrap();
        file.flush().unwrap();

        let dummy_stored_static = create_dummy_stored_static(path);
        let res = LevelTuning::run(level_tuning_config_path, path, &dummy_stored_static);
        assert_eq!(res, Ok(()));

        assert_eq!(fs::read_to_string(path).unwrap(), expected_rule);
        fs::remove_file(path).unwrap();
    }
}

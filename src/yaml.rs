extern crate serde_derive;
extern crate yaml_rust;

use crate::detections::configs;
use crate::detections::print::AlertMessage;
use crate::detections::print::ERROR_LOG_STACK;
use crate::detections::print::QUIET_ERRORS_FLAG;
use crate::filter::RuleExclude;
use hashbrown::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use yaml_rust::Yaml;
use yaml_rust::YamlLoader;

pub struct ParseYaml {
    pub files: Vec<(String, yaml_rust::Yaml)>,
    pub rulecounter: HashMap<String, u128>,
    pub rule_load_cnt: HashMap<String, u128>,
    pub rule_status_cnt: HashMap<String, u128>,
    pub errorrule_count: u128,
}

impl Default for ParseYaml {
    fn default() -> Self {
        Self::new()
    }
}

impl ParseYaml {
    pub fn new() -> ParseYaml {
        ParseYaml {
            files: Vec::new(),
            rulecounter: HashMap::new(),
            rule_load_cnt: HashMap::from([
                ("excluded".to_string(), 0_u128),
                ("noisy".to_string(), 0_u128),
            ]),
            rule_status_cnt: HashMap::from([("deprecated".to_string(), 0_u128)]),
            errorrule_count: 0,
        }
    }

    pub fn read_file(&self, path: PathBuf) -> Result<String, String> {
        let mut file_content = String::new();

        let mut fr = fs::File::open(path)
            .map(BufReader::new)
            .map_err(|e| e.to_string())?;

        fr.read_to_string(&mut file_content)
            .map_err(|e| e.to_string())?;

        Ok(file_content)
    }

    pub fn read_dir<P: AsRef<Path>>(
        &mut self,
        path: P,
        level: &str,
        exclude_ids: &RuleExclude,
    ) -> io::Result<String> {
        let metadata = fs::metadata(path.as_ref());
        if metadata.is_err() {
            let errmsg = format!(
                "fail to read metadata of file: {}",
                path.as_ref().to_path_buf().display(),
            );
            if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                AlertMessage::alert(&errmsg)?;
            }
            if !*QUIET_ERRORS_FLAG {
                ERROR_LOG_STACK
                    .lock()
                    .unwrap()
                    .push(format!("[ERROR] {}", errmsg));
            }
            return io::Result::Ok(String::default());
        }
        let mut yaml_docs = vec![];
        if metadata.unwrap().file_type().is_file() {
            // 拡張子がymlでないファイルは無視
            if path
                .as_ref()
                .to_path_buf()
                .extension()
                .unwrap_or_else(|| OsStr::new(""))
                != "yml"
            {
                return io::Result::Ok(String::default());
            }

            // 個別のファイルの読み込みは即終了としない。
            let read_content = self.read_file(path.as_ref().to_path_buf());
            if read_content.is_err() {
                let errmsg = format!(
                    "fail to read file: {}\n{} ",
                    path.as_ref().to_path_buf().display(),
                    read_content.unwrap_err()
                );
                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    AlertMessage::warn(&errmsg)?;
                }
                if !*QUIET_ERRORS_FLAG {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[WARN] {}", errmsg));
                }
                self.errorrule_count += 1;
                return io::Result::Ok(String::default());
            }

            // ここも個別のファイルの読み込みは即終了としない。
            let yaml_contents = YamlLoader::load_from_str(&read_content.unwrap());
            if yaml_contents.is_err() {
                let errmsg = format!(
                    "Failed to parse yml: {}\n{} ",
                    path.as_ref().to_path_buf().display(),
                    yaml_contents.unwrap_err()
                );
                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    AlertMessage::warn(&errmsg)?;
                }
                if !*QUIET_ERRORS_FLAG {
                    ERROR_LOG_STACK
                        .lock()
                        .unwrap()
                        .push(format!("[WARN] {}", errmsg));
                }
                self.errorrule_count += 1;
                return io::Result::Ok(String::default());
            }

            yaml_docs.extend(yaml_contents.unwrap().into_iter().map(|yaml_content| {
                let filepath = format!("{}", path.as_ref().to_path_buf().display());
                (filepath, yaml_content)
            }));
        } else {
            let mut entries = fs::read_dir(path)?;
            yaml_docs = entries.try_fold(vec![], |mut ret, entry| {
                let entry = entry?;
                // フォルダは再帰的に呼び出す。
                if entry.file_type()?.is_dir() {
                    self.read_dir(entry.path(), level, exclude_ids)?;
                    return io::Result::Ok(ret);
                }
                // ファイル以外は無視
                if !entry.file_type()?.is_file() {
                    return io::Result::Ok(ret);
                }

                // 拡張子がymlでないファイルは無視
                let path = entry.path();
                if path.extension().unwrap_or_else(|| OsStr::new("")) != "yml" {
                    return io::Result::Ok(ret);
                }

                // ignore if yml file in .git folder.
                if path.to_str().unwrap().contains("/.git/")
                    || path.to_str().unwrap().contains("\\.git\\")
                {
                    return io::Result::Ok(ret);
                }

                // 個別のファイルの読み込みは即終了としない。
                let read_content = self.read_file(path);
                if read_content.is_err() {
                    let errmsg = format!(
                        "fail to read file: {}\n{} ",
                        entry.path().display(),
                        read_content.unwrap_err()
                    );
                    if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                        AlertMessage::warn(&errmsg)?;
                    }
                    if !*QUIET_ERRORS_FLAG {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {}", errmsg));
                    }
                    self.errorrule_count += 1;
                    return io::Result::Ok(ret);
                }

                // ここも個別のファイルの読み込みは即終了としない。
                let yaml_contents = YamlLoader::load_from_str(&read_content.unwrap());
                if yaml_contents.is_err() {
                    let errmsg = format!(
                        "Failed to parse yml: {}\n{} ",
                        entry.path().display(),
                        yaml_contents.unwrap_err()
                    );
                    if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                        AlertMessage::warn(&errmsg)?;
                    }
                    if !*QUIET_ERRORS_FLAG {
                        ERROR_LOG_STACK
                            .lock()
                            .unwrap()
                            .push(format!("[WARN] {}", errmsg));
                    }
                    self.errorrule_count += 1;
                    return io::Result::Ok(ret);
                }

                let yaml_contents = yaml_contents.unwrap().into_iter().map(|yaml_content| {
                    let filepath = format!("{}", entry.path().display());
                    (filepath, yaml_content)
                });
                ret.extend(yaml_contents);
                io::Result::Ok(ret)
            })?;
        }

        let files: Vec<(String, Yaml)> = yaml_docs
            .into_iter()
            .filter_map(|(filepath, yaml_doc)| {
                //除外されたルールは無視する
                let rule_id = &yaml_doc["id"].as_str();
                if rule_id.is_some() {
                    if let Some(v) = exclude_ids
                        .no_use_rule
                        .get(&rule_id.unwrap_or(&String::default()).to_string())
                    {
                        let entry_key = if v.contains("exclude_rule") {
                            "excluded"
                        } else {
                            "noisy"
                        };
                        let entry = self.rule_load_cnt.entry(entry_key.to_string()).or_insert(0);
                        *entry += 1;
                        return Option::None;
                    }
                }

                self.rulecounter.insert(
                    yaml_doc["ruletype"].as_str().unwrap_or("Other").to_string(),
                    self.rulecounter
                        .get(&yaml_doc["ruletype"].as_str().unwrap_or("Other").to_string())
                        .unwrap_or(&0)
                        + 1,
                );

                let status_cnt = self
                    .rule_status_cnt
                    .entry(
                        yaml_doc["status"]
                            .as_str()
                            .unwrap_or("undefined")
                            .to_string(),
                    )
                    .or_insert(0);
                *status_cnt += 1;

                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    println!("Loaded yml file path: {}", filepath);
                }

                // 指定されたレベルより低いルールは無視する
                let doc_level = &yaml_doc["level"]
                    .as_str()
                    .unwrap_or("informational")
                    .to_string()
                    .to_uppercase();
                let doc_level_num = configs::LEVELMAP.get(doc_level).unwrap_or(&1);
                let args_level_num = configs::LEVELMAP.get(level).unwrap_or(&1);
                if doc_level_num < args_level_num {
                    return Option::None;
                }

                if !configs::CONFIG
                    .read()
                    .unwrap()
                    .args
                    .is_present("enable-deprecated-rules")
                {
                    let rule_status = &yaml_doc["status"].as_str().unwrap_or_default();
                    if *rule_status == "deprecated" {
                        let entry = self
                            .rule_status_cnt
                            .entry(rule_status.to_string())
                            .or_insert(0);
                        *entry += 1;
                        return Option::None;
                    }
                }

                Option::Some((filepath, yaml_doc))
            })
            .collect();
        self.files.extend(files);
        io::Result::Ok(String::default())
    }
}

#[cfg(test)]
mod tests {

    use crate::detections::print::AlertMessage;
    use crate::detections::print::ERROR_LOG_PATH;
    use crate::filter;
    use crate::yaml;
    use crate::yaml::RuleExclude;
    use hashbrown::HashMap;
    use std::path::Path;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_read_file_yaml() {
        AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());

        let mut yaml = yaml::ParseYaml::new();
        let exclude_ids = RuleExclude::default();
        let _ = &yaml.read_dir(
            "test_files/rules/yaml/1.yml",
            &String::default(),
            &exclude_ids,
        );
        assert_eq!(yaml.files.len(), 1);
    }

    #[test]
    fn test_read_dir_yaml() {
        AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());

        let mut yaml = yaml::ParseYaml::new();
        let exclude_ids = RuleExclude {
            no_use_rule: HashMap::new(),
        };
        let _ = &yaml.read_dir("test_files/rules/yaml/", &String::default(), &exclude_ids);
        assert_ne!(yaml.files.len(), 0);
    }

    #[test]
    fn test_read_yaml() {
        let yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml/1.yml");
        let ret = yaml.read_file(path.to_path_buf()).unwrap();
        let rule = YamlLoader::load_from_str(&ret).unwrap();
        for i in rule {
            if i["title"].as_str().unwrap() == "Sysmon Check command lines" {
                assert_eq!(
                    "*",
                    i["detection"]["selection"]["CommandLine"].as_str().unwrap()
                );
                assert_eq!(1, i["detection"]["selection"]["EventID"].as_i64().unwrap());
            }
        }
    }

    #[test]
    fn test_failed_read_yaml() {
        let yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml/error.yml");
        let ret = yaml.read_file(path.to_path_buf()).unwrap();
        let rule = YamlLoader::load_from_str(&ret);
        assert!(rule.is_err());
    }

    #[test]
    /// no specifed "level" arguments value is adapted default level(informational)
    fn test_default_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "", &filter::exclude_ids()).unwrap();
        assert_eq!(yaml.files.len(), 5);
    }

    #[test]
    fn test_info_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "informational", &filter::exclude_ids())
            .unwrap();
        assert_eq!(yaml.files.len(), 5);
    }
    #[test]
    fn test_low_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "LOW", &filter::exclude_ids()).unwrap();
        assert_eq!(yaml.files.len(), 4);
    }
    #[test]
    fn test_medium_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "MEDIUM", &filter::exclude_ids())
            .unwrap();
        assert_eq!(yaml.files.len(), 3);
    }
    #[test]
    fn test_high_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "HIGH", &filter::exclude_ids()).unwrap();
        assert_eq!(yaml.files.len(), 2);
    }
    #[test]
    fn test_critical_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path, "CRITICAL", &filter::exclude_ids())
            .unwrap();
        assert_eq!(yaml.files.len(), 1);
    }
    #[test]
    fn test_all_exclude_rules_file() {
        AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());

        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml");
        yaml.read_dir(path, "", &filter::exclude_ids()).unwrap();
        assert_eq!(yaml.rule_load_cnt.get("excluded").unwrap().to_owned(), 5);
    }
    #[test]
    fn test_all_noisy_rules_file() {
        AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());

        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml");
        yaml.read_dir(path, "", &filter::exclude_ids()).unwrap();
        assert_eq!(yaml.rule_load_cnt.get("noisy").unwrap().to_owned(), 5);
    }
    #[test]
    fn test_none_exclude_rules_file() {
        AlertMessage::create_error_log(ERROR_LOG_PATH.to_string());

        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml");
        let exclude_ids = RuleExclude::default();
        yaml.read_dir(path, "", &exclude_ids).unwrap();
        assert_eq!(yaml.rule_load_cnt.get("excluded").unwrap().to_owned(), 0);
    }
    #[test]
    fn test_exclude_deprecated_rules_file() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/deprecated");
        let exclude_ids = RuleExclude::default();
        yaml.read_dir(path, "", &exclude_ids).unwrap();
        assert_eq!(
            yaml.rule_status_cnt.get("deprecated").unwrap().to_owned(),
            2
        );
    }
}

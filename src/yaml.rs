extern crate serde_derive;
extern crate yaml_rust;

use crate::detections::configs;
use crate::detections::print::AlertMessage;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use yaml_rust::Yaml;
use yaml_rust::YamlLoader;

pub struct ParseYaml {
    pub files: Vec<(String, yaml_rust::Yaml)>,
}

impl ParseYaml {
    pub fn new() -> ParseYaml {
        ParseYaml { files: Vec::new() }
    }

    pub fn read_file(&self, path: PathBuf) -> Result<String, String> {
        let mut file_content = String::new();

        let mut fr = fs::File::open(path)
            .map(|f| BufReader::new(f))
            .map_err(|e| e.to_string())?;

        fr.read_to_string(&mut file_content)
            .map_err(|e| e.to_string())?;

        Ok(file_content)
    }

    pub fn read_dir<P: AsRef<Path>>(&mut self, path: P, level: &str) -> io::Result<String> {
        let mut entries = fs::read_dir(path)?;
        let yaml_docs = entries.try_fold(vec![], |mut ret, entry| {
            let entry = entry?;
            // フォルダは再帰的に呼び出す。
            if entry.file_type()?.is_dir() {
                self.read_dir(entry.path(), level)?;
                return io::Result::Ok(ret);
            }
            // ファイル以外は無視
            if !entry.file_type()?.is_file() {
                return io::Result::Ok(ret);
            }

            // 拡張子がymlでないファイルは無視
            let path = entry.path();
            if path.extension().unwrap_or(OsStr::new("")) != "yml" {
                return io::Result::Ok(ret);
            }

            // 個別のファイルの読み込みは即終了としない。
            let read_content = self.read_file(path);
            if read_content.is_err() {
                AlertMessage::warn(
                    &mut std::io::stdout().lock(),
                    format!(
                        "fail to read file: {}\n{} ",
                        entry.path().display(),
                        read_content.unwrap_err()
                    ),
                )?;
                return io::Result::Ok(ret);
            }

            // ここも個別のファイルの読み込みは即終了としない。
            let yaml_contents = YamlLoader::load_from_str(&read_content.unwrap());
            if yaml_contents.is_err() {
                AlertMessage::warn(
                    &mut std::io::stdout().lock(),
                    format!(
                        "fail to parse as yaml: {}\n{} ",
                        entry.path().display(),
                        yaml_contents.unwrap_err()
                    ),
                )?;
                return io::Result::Ok(ret);
            }

            let yaml_contents = yaml_contents.unwrap().into_iter().map(|yaml_content| {
                let filepath = format!("{}", entry.path().display());
                return (filepath, yaml_content);
            });
            ret.extend(yaml_contents);
            return io::Result::Ok(ret);
        })?;

        let files: Vec<(String, Yaml)> = yaml_docs
            .into_iter()
            .filter_map(|(filepath, yaml_doc)| {
                // ignoreフラグがONになっているルールは無視する。
                if yaml_doc["ignore"].as_bool().unwrap_or(false) {
                    return Option::None;
                }
                if configs::CONFIG.read().unwrap().args.is_present("verbose") {
                    println!("Loaded yml FilePath: {}", filepath);
                }
                // 指定されたレベルより低いルールは無視する
                let doc_level = &yaml_doc["level"]
                    .as_str()
                    .unwrap_or("INFO")
                    .to_string()
                    .to_uppercase();
                let doc_level_num = configs::LEVELMAP.get(doc_level).unwrap_or(&1);
                let args_level_num = configs::LEVELMAP.get(level).unwrap_or(&1);
                if doc_level_num < args_level_num {
                    return Option::None;
                }

                return Option::Some((filepath, yaml_doc));
            })
            .collect();
        self.files.extend(files);

        return io::Result::Ok(String::default());
    }
}

#[cfg(test)]
mod tests {

    use crate::yaml;
    use std::path::Path;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_read_dir_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        &yaml.read_dir("test_files/rules/yaml/".to_string(), &"".to_owned());
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
        assert_eq!(rule.is_err(), true);
    }

    #[test]
    /// no specifed "level" arguments value is adapted default level(INFO)
    fn test_default_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path.to_path_buf(), &"").unwrap();
        assert_eq!(yaml.files.len(), 5);
    }

    #[test]
    fn test_info_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path.to_path_buf(), &"INFO").unwrap();
        assert_eq!(yaml.files.len(), 5);
    }
    #[test]
    fn test_low_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");

        yaml.read_dir(path.to_path_buf(), &"LOW").unwrap();
        assert_eq!(yaml.files.len(), 4);
    }
    #[test]
    fn test_medium_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path.to_path_buf(), &"MEDIUM").unwrap();
        assert_eq!(yaml.files.len(), 3);
    }
    #[test]
    fn test_high_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path.to_path_buf(), &"HIGH").unwrap();
        assert_eq!(yaml.files.len(), 2);
    }
    #[test]
    fn test_critical_level_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/level_yaml");
        yaml.read_dir(path.to_path_buf(), &"CRITICAL").unwrap();
        assert_eq!(yaml.files.len(), 1);
    }
}

extern crate serde_derive;
extern crate yaml_rust;

use std::fs;
use std::io;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use yaml_rust::YamlLoader;

pub struct ParseYaml {
    pub files: Vec<yaml_rust::Yaml>,
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

    pub fn read_dir<P: AsRef<Path>>(&mut self, path: P) -> io::Result<String> {
        Ok(fs::read_dir(path)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_file() {
                    match self.read_file(entry.path()) {
                        Ok(s) => {
                            let docs = YamlLoader::load_from_str(&s).unwrap();
                            for i in docs {
                                if i["enabled"].as_bool().unwrap() {
                                    &self.files.push(i);
                                }
                            }
                        }
                        Err(e) => panic!("fail to read file: {}", e),
                    };
                }
                if entry.file_type().ok()?.is_dir() {
                    let _ = self.read_dir(entry.path());
                }
                Some("")
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {

    use crate::yaml;

    #[test]
    fn test_read_yaml() {
        let mut yaml = yaml::ParseYaml::new();
        &yaml.read_dir("test_files/rules/yaml/".to_string());
        for rule in yaml.files {
            if rule["title"].as_str().unwrap() == "Sysmon Check command lines" {
                assert_eq!(
                    "*",
                    rule["detection"]["selection"]["CommandLine"]
                        .as_str()
                        .unwrap()
                );
                assert_eq!(
                    1,
                    rule["detection"]["selection"]["EventID"].as_i64().unwrap()
                );
            }
        }
    }
}

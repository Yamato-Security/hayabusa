extern crate serde_derive;
extern crate toml;

use crate::models::rule;
use std::fs;
use std::io;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

pub struct ParseToml {
    pub rules: Vec<Result<rule::Toml, toml::de::Error>>,
}

impl ParseToml {
    pub fn new() -> ParseToml {
        ParseToml { rules: Vec::new() }
    }

    fn read_file(&self, path: PathBuf) -> Result<String, String> {
        let mut file_content = String::new();

        let mut fr = fs::File::open(path)
            .map(|f| BufReader::new(f))
            .map_err(|e| e.to_string())?;

        fr.read_to_string(&mut file_content)
            .map_err(|e| e.to_string())?;

        Ok(file_content)
    }

    fn read_dir<P: AsRef<Path>>(&mut self, path: P) -> io::Result<String> {
        Ok(fs::read_dir(path)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_file() {
                    match self.read_file(entry.path()) {
                        Ok(s) => &self.rules.push(toml::from_str(&s)),
                        Err(e) => panic!("fail to read file: {}", e),
                    };
                }
                Some("")
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {

    use crate::toml;

    #[test]
    fn test_read_toml() {
        let mut toml = toml::ParseToml::new();
        &toml.read_dir("test_files/rules".to_string());

        for rule in toml.rules {
            match rule {
                Ok(_rule) => {
                    if let Some(severity) = _rule.rule.severity {
                        assert_eq!("high", severity);
                    }
                }
                Err(_) => (),
            }
        }
    }
}

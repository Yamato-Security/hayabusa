use crate::detections::configs::CURRENT_EXE_PATH;
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::utils::{check_setting_path, get_writable_color, write_color_buffer};
use console::{style, Style};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Confirm;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::{fs, io};
use strum::{EnumIter, IntoEnumIterator};
use termcolor::{BufferWriter, Color, ColorChoice};

static CONFIG_CRITICAL_SYSTEMS: &str = "config/critical_systems.txt";
#[derive(Eq, Hash, PartialEq, Debug, Clone, EnumIter)]
enum ComputerType {
    DomainController,
    FileServer,
}

impl ComputerType {
    fn to_str(&self) -> &str {
        match self {
            ComputerType::DomainController => "Domain Controllers",
            ComputerType::FileServer => "File Servers",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfigCriticalSystems {
    computers: HashMap<ComputerType, HashSet<String>>,
    config_txt_path: PathBuf,
}

impl Default for ConfigCriticalSystems {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigCriticalSystems {
    pub fn new() -> Self {
        Self {
            computers: HashMap::new(),
            config_txt_path: check_setting_path(
                &CURRENT_EXE_PATH.to_path_buf(),
                CONFIG_CRITICAL_SYSTEMS,
                true,
            )
            .unwrap_or(PathBuf::from(CONFIG_CRITICAL_SYSTEMS)),
        }
    }

    pub fn process(&mut self, records: &[EvtxRecordInfo]) {
        for record in records {
            self.find_critical_computers(&record.record);
        }
    }

    fn find_critical_computers(&mut self, data: &Value) {
        if let Some(ch) = data["Event"]["System"]["Channel"].as_str() {
            if let Some(id) = data["Event"]["System"]["EventID"].as_i64() {
                if ch == "Security" {
                    if id == 4768 {
                        let v = data["Event"]["System"]["Computer"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        self.computers
                            .entry(ComputerType::DomainController)
                            .or_default()
                            .insert(v);
                    } else if id == 5145 {
                        let share = data["Event"]["EventData"]["ShareName"]
                            .as_str()
                            .unwrap_or_default();
                        if share == r"\\*\IPC$" {
                            return;
                        }
                        let v = data["Event"]["System"]["Computer"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        self.computers
                            .entry(ComputerType::FileServer)
                            .or_default()
                            .insert(v);
                    }
                }
            }
        }
    }

    pub fn output_computers(&mut self, no_color: bool) {
        for computer_type in ComputerType::iter() {
            match self.computers.get(&computer_type) {
                Some(names) => {
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        get_writable_color(Some(Color::Rgb(0, 255, 0)), no_color),
                        &format!("{} found ({}):", computer_type.to_str(), names.len()),
                        true,
                    )
                    .ok();
                    let mut names: Vec<_> = names.iter().collect();
                    names.sort();
                    for name in &names {
                        write_color_buffer(
                            &BufferWriter::stdout(ColorChoice::Always),
                            None,
                            name,
                            true,
                        )
                        .ok();
                    }
                    println!();
                    let color_theme = if no_color {
                        ColorfulTheme {
                            defaults_style: Style::new().for_stderr(),
                            prompt_style: Style::new().for_stderr().bold(),
                            prompt_prefix: style("?".to_string()).for_stderr(),
                            prompt_suffix: style("›".to_string()).for_stderr(),
                            success_prefix: style("✔".to_string()).for_stderr(),
                            success_suffix: style("·".to_string()).for_stderr(),
                            error_prefix: style("✘".to_string()).for_stderr(),
                            error_style: Style::new().for_stderr(),
                            hint_style: Style::new().for_stderr(),
                            values_style: Style::new().for_stderr(),
                            active_item_style: Style::new().for_stderr(),
                            inactive_item_style: Style::new().for_stderr(),
                            active_item_prefix: style("❯".to_string()).for_stderr(),
                            inactive_item_prefix: style(" ".to_string()).for_stderr(),
                            checked_item_prefix: style("✔".to_string()).for_stderr(),
                            unchecked_item_prefix: style("⬚".to_string()).for_stderr(),
                            picked_item_prefix: style("❯".to_string()).for_stderr(),
                            unpicked_item_prefix: style(" ".to_string()).for_stderr(),
                        }
                    } else {
                        ColorfulTheme {
                            active_item_prefix: Style::new()
                                .color256(214)
                                .apply_to("❯".to_string()), // orange
                            checked_item_prefix: Style::new()
                                .color256(46)
                                .apply_to("✔".to_string()), // green
                            picked_item_prefix: Style::new()
                                .color256(214)
                                .apply_to("❯".to_string()), // orange
                            active_item_style: Style::new().color256(51), // cyan
                            values_style: Style::new().color256(46),      // green
                            prompt_prefix: Style::new().color256(214).apply_to("?".to_string()), // orange
                            prompt_suffix: Style::new().color256(15).apply_to("›".to_string()), // cyan
                            defaults_style: Style::new().color256(51), // cyan
                            hint_style: Style::new().color256(214),    // orange
                            success_prefix: Style::new().color256(46).apply_to("✔".to_string()), // green
                            success_suffix: Style::new().color256(15).apply_to("·".to_string()), // white
                            error_prefix: Style::new().color256(9).apply_to("✘".to_string()), // red
                            ..Default::default()
                        }
                    };
                    let prompt_fmt = format!(
                        "Would you like to add them to the {} file?:",
                        CONFIG_CRITICAL_SYSTEMS
                    );
                    let config_append = Confirm::with_theme(&color_theme)
                        .with_prompt(prompt_fmt)
                        .default(true)
                        .show_default(true)
                        .interact()
                        .unwrap();
                    if config_append {
                        let mut file = fs::OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(&self.config_txt_path)
                            .expect("Failed to open file");
                        names.iter().for_each(|name| {
                            file.write_all(format!("{}\n", name).as_bytes()).ok();
                        });
                        file.flush().ok();
                        sort_and_dedup_file(&self.config_txt_path).ok();
                        write_color_buffer(
                            &BufferWriter::stdout(ColorChoice::Always),
                            get_writable_color(Some(Color::Rgb(255, 175, 0)), no_color),
                            &format!("Added to the {} file.", CONFIG_CRITICAL_SYSTEMS),
                            true,
                        )
                        .ok();
                        println!();
                    }
                }
                None => {
                    let msg = format!("No {:?} found.", computer_type);
                    write_color_buffer(
                        &BufferWriter::stdout(ColorChoice::Always),
                        get_writable_color(Some(Color::Rgb(215, 0, 0)), no_color),
                        msg.as_str(),
                        true,
                    )
                    .ok();
                    println!();
                }
            }
        }
    }
}

fn sort_and_dedup_file(file_path: &Path) -> io::Result<()> {
    let file = fs::File::open(file_path)?;
    let reader = BufReader::new(file);

    // 行を読み込み、重複を削除してソートする
    let mut lines: HashSet<String> = HashSet::new();
    for line in reader.lines() {
        lines.insert(line?);
    }
    let mut sorted_lines: Vec<String> = lines.into_iter().collect();
    sorted_lines.sort();

    // ファイルを上書きする
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)?;
    for line in sorted_lines {
        writeln!(file, "{}", line)?;
    }
    file.flush().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_critical_computers() {
        let mut config = ConfigCriticalSystems::new();
        let data = json!({
            "Event": {
                "System": {
                    "Channel": "Security",
                    "EventID": 4768,
                    "Computer": "DC1"
                }
            }
        });
        config.find_critical_computers(&data);
        assert!(config
            .computers
            .get(&ComputerType::DomainController)
            .unwrap()
            .contains("DC1"));

        let data = json!({
            "Event": {
                "System": {
                    "Channel": "Security",
                    "EventID": 5145,
                    "Computer": "FileServer1"
                },
                "EventData": {
                    "ShareName": r"\\*\IPC$"
                }
            }
        });
        config.find_critical_computers(&data);
        assert!(!config.computers.contains_key(&ComputerType::FileServer));

        let data = json!({
            "Event": {
                "System": {
                    "Channel": "Security",
                    "EventID": 5145,
                    "Computer": "FileServer2"
                },
                "EventData": {
                    "ShareName": r"\\*\Share$"
                }
            }
        });
        config.find_critical_computers(&data);
        assert!(config
            .computers
            .get(&ComputerType::FileServer)
            .unwrap()
            .contains("FileServer2"));
    }
}

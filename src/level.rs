use crate::afterfact::Colors;
use crate::detections::configs::CURRENT_EXE_PATH;
use crate::detections::message::AlertMessage;
use crate::detections::utils;
use crate::detections::utils::parse_csv;
use hashbrown::{HashMap, HashSet};
use lazy_static::lazy_static;
use rust_embed::Embed;
lazy_static! {
    static ref CRITICAL_SYSTEM: HashSet<String> = {
        let current = CURRENT_EXE_PATH.to_path_buf();
        let path = current.join("config/critical_system.txt");
        let content = fs::read_to_string(path).unwrap_or("".to_string());
        content
            .lines()
            .map(|line| line.trim().to_string())
            .collect()
    };
}
use std::fs;
use std::path::Path;
use strum::EnumIter;

use termcolor::Color;

#[derive(Embed)]
#[folder = "config"]
#[include = "level_color.txt"]
struct LevelColor;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, Default, Hash)]
pub enum LEVEL {
    #[default]
    UNDEFINED,
    INFORMATIONAL,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
    EMERGENCY,
}

impl LEVEL {
    pub fn from(s: &str) -> Self {
        match s {
            "informational" => LEVEL::INFORMATIONAL,
            "low" => LEVEL::LOW,
            "medium" => LEVEL::MEDIUM,
            "high" => LEVEL::HIGH,
            "critical" => LEVEL::CRITICAL,
            "emergency" => LEVEL::EMERGENCY,
            _ => LEVEL::UNDEFINED,
        }
    }
    pub fn to_full(&self) -> &str {
        match *self {
            LEVEL::INFORMATIONAL => "informational",
            LEVEL::LOW => "low",
            LEVEL::MEDIUM => "medium",
            LEVEL::HIGH => "high",
            LEVEL::CRITICAL => "critical",
            LEVEL::EMERGENCY => "emergency",
            _ => "undefined",
        }
    }

    pub fn to_abbrev(&self) -> &str {
        match *self {
            LEVEL::INFORMATIONAL => "info",
            LEVEL::LOW => "low",
            LEVEL::MEDIUM => "med",
            LEVEL::HIGH => "high",
            LEVEL::CRITICAL => "crit",
            LEVEL::EMERGENCY => "emer",
            _ => "undef",
        }
    }

    pub fn index(&self) -> usize {
        match *self {
            LEVEL::UNDEFINED => 0,
            LEVEL::INFORMATIONAL => 1,
            LEVEL::LOW => 2,
            LEVEL::MEDIUM => 3,
            LEVEL::HIGH => 4,
            LEVEL::CRITICAL => 5,
            LEVEL::EMERGENCY => 6,
        }
    }

    pub fn convert(&self, computer: &str) -> &LEVEL {
        // computerがCRITICAL_SYSTEMに含まれている場合は、レベルを上げる
        let computers = computer.split(" ¦ ");
        for c in computers {
            if CRITICAL_SYSTEM.contains(c) {
                return match self {
                    LEVEL::INFORMATIONAL => &LEVEL::INFORMATIONAL,
                    LEVEL::LOW => &LEVEL::MEDIUM,
                    LEVEL::MEDIUM => &LEVEL::HIGH,
                    LEVEL::HIGH => &LEVEL::CRITICAL,
                    LEVEL::CRITICAL => &LEVEL::EMERGENCY,
                    LEVEL::EMERGENCY => &LEVEL::EMERGENCY,
                    _ => &LEVEL::UNDEFINED,
                };
            }
        }
        self
    }
}

impl PartialEq<str> for LEVEL {
    fn eq(&self, other: &str) -> bool {
        self.to_full() == other || self.to_abbrev() == other
    }
}

/// level_color.txtファイルを読み込み対応する文字色のマッピングを返却する関数
pub fn create_output_color_map(no_color_flag: bool) -> HashMap<LEVEL, Colors> {
    let path = utils::check_setting_path(Path::new("."), "config/level_color.txt", false)
        .unwrap_or_else(|| {
            utils::check_setting_path(
                &CURRENT_EXE_PATH.to_path_buf(),
                "config/level_color.txt",
                false,
            )
            .unwrap_or_default()
        });
    let read_result = match utils::read_csv(path.to_str().unwrap()) {
        Ok(c) => Ok(c),
        Err(_) => {
            let level_color = LevelColor::get("level_color.txt").unwrap();
            let embed_level_color =
                parse_csv(std::str::from_utf8(level_color.data.as_ref()).unwrap_or_default());
            if embed_level_color.is_empty() {
                Err("Not found level_color.txt in embed resource.".to_string())
            } else {
                Ok(embed_level_color)
            }
        }
    };
    let mut color_map: HashMap<LEVEL, Colors> = HashMap::new();
    if no_color_flag {
        return color_map;
    }
    let color_map_contents = match read_result {
        Ok(c) => c,
        Err(e) => {
            // color情報がない場合は通常の白色の出力が出てくるのみで動作への影響を与えない為warnとして処理する
            AlertMessage::warn(&e).ok();
            return color_map;
        }
    };
    color_map_contents.iter().for_each(|line| {
        if line.len() != 2 {
            return;
        }
        let empty = &"".to_string();
        let level = LEVEL::from(line.first().unwrap_or(empty).to_lowercase().as_str());
        let convert_color_result = hex::decode(line.get(1).unwrap_or(empty).trim());
        if convert_color_result.is_err() {
            AlertMessage::warn(&format!(
                "Failed hex convert in level_color.txt. Color output is disabled. Input Line: {}",
                line.join(",")
            ))
            .ok();
            return;
        }
        let color_code = convert_color_result.unwrap();
        if level == LEVEL::UNDEFINED || color_code.len() < 3 {
            return;
        }
        color_map.insert(
            level,
            Colors {
                output_color: Color::Rgb(color_code[0], color_code[1], color_code[2]),
                table_color: comfy_table::Color::Rgb {
                    r: color_code[0],
                    g: color_code[1],
                    b: color_code[2],
                },
            },
        );
    });
    color_map
}

pub fn _get_output_color(color_map: &HashMap<LEVEL, Colors>, level: &LEVEL) -> Option<Color> {
    let mut color = None;
    if let Some(c) = color_map.get(level) {
        color = Some(c.output_color);
    }
    color
}

#[cfg(test)]
mod tests {
    use crate::afterfact::Colors;
    use crate::level::LEVEL;
    use hashbrown::HashMap;

    fn check_hashmap_data(target: HashMap<LEVEL, Colors>, expected: HashMap<LEVEL, Colors>) {
        assert_eq!(target.len(), expected.len());
        for (k, v) in target {
            assert!(expected.get(&k).is_some());
            assert_eq!(format!("{v:?}"), format!("{:?}", expected.get(&k).unwrap()));
        }
    }

    #[test]
    /// To confirm that empty character color mapping data is returned when the no_color flag is given.
    fn test_set_output_color_no_color_flag() {
        let expect: HashMap<LEVEL, Colors> = HashMap::new();
        check_hashmap_data(crate::level::create_output_color_map(true), expect);
    }
}

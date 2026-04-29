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
        let path = current.join("config/critical_systems.txt");
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
        let s = s.to_lowercase();
        let s = s.as_str();
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
        // If the computer is included in CRITICAL_SYSTEM, raise the level.
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

/// Reads the level_color.txt file and returns the corresponding text color mapping.
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
            // If there is no color information, only the normal white output will appear and it will not affect behavior, so it is treated as a warning.
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
    use crate::level::{_get_output_color, LEVEL, create_output_color_map};
    use hashbrown::HashMap;
    use termcolor::Color;

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
        check_hashmap_data(create_output_color_map(true), expect);
    }

    #[test]
    fn test_level_from_known_strings() {
        assert_eq!(LEVEL::from("informational"), LEVEL::INFORMATIONAL);
        assert_eq!(LEVEL::from("low"), LEVEL::LOW);
        assert_eq!(LEVEL::from("medium"), LEVEL::MEDIUM);
        assert_eq!(LEVEL::from("high"), LEVEL::HIGH);
        assert_eq!(LEVEL::from("critical"), LEVEL::CRITICAL);
        assert_eq!(LEVEL::from("emergency"), LEVEL::EMERGENCY);
    }

    #[test]
    fn test_level_from_is_case_insensitive() {
        assert_eq!(LEVEL::from("HIGH"), LEVEL::HIGH);
        assert_eq!(LEVEL::from("Critical"), LEVEL::CRITICAL);
        assert_eq!(LEVEL::from("eMeRgEnCy"), LEVEL::EMERGENCY);
    }

    #[test]
    fn test_level_from_unknown_is_undefined() {
        assert_eq!(LEVEL::from(""), LEVEL::UNDEFINED);
        assert_eq!(LEVEL::from("info"), LEVEL::UNDEFINED);
        assert_eq!(LEVEL::from("not_a_level"), LEVEL::UNDEFINED);
    }

    #[test]
    fn test_level_default_is_undefined() {
        assert_eq!(LEVEL::default(), LEVEL::UNDEFINED);
    }

    #[test]
    fn test_level_to_full() {
        assert_eq!(LEVEL::INFORMATIONAL.to_full(), "informational");
        assert_eq!(LEVEL::LOW.to_full(), "low");
        assert_eq!(LEVEL::MEDIUM.to_full(), "medium");
        assert_eq!(LEVEL::HIGH.to_full(), "high");
        assert_eq!(LEVEL::CRITICAL.to_full(), "critical");
        assert_eq!(LEVEL::EMERGENCY.to_full(), "emergency");
        assert_eq!(LEVEL::UNDEFINED.to_full(), "undefined");
    }

    #[test]
    fn test_level_to_abbrev() {
        assert_eq!(LEVEL::INFORMATIONAL.to_abbrev(), "info");
        assert_eq!(LEVEL::LOW.to_abbrev(), "low");
        assert_eq!(LEVEL::MEDIUM.to_abbrev(), "med");
        assert_eq!(LEVEL::HIGH.to_abbrev(), "high");
        assert_eq!(LEVEL::CRITICAL.to_abbrev(), "crit");
        assert_eq!(LEVEL::EMERGENCY.to_abbrev(), "emer");
        assert_eq!(LEVEL::UNDEFINED.to_abbrev(), "undef");
    }

    #[test]
    fn test_level_index_is_strictly_increasing() {
        assert_eq!(LEVEL::UNDEFINED.index(), 0);
        assert_eq!(LEVEL::INFORMATIONAL.index(), 1);
        assert_eq!(LEVEL::LOW.index(), 2);
        assert_eq!(LEVEL::MEDIUM.index(), 3);
        assert_eq!(LEVEL::HIGH.index(), 4);
        assert_eq!(LEVEL::CRITICAL.index(), 5);
        assert_eq!(LEVEL::EMERGENCY.index(), 6);
    }

    #[test]
    fn test_level_partial_eq_str_matches_full_and_abbrev() {
        assert!(LEVEL::HIGH == *"high");
        assert!(LEVEL::MEDIUM == *"medium");
        assert!(LEVEL::MEDIUM == *"med");
        assert!(LEVEL::CRITICAL == *"crit");
        assert!(LEVEL::INFORMATIONAL == *"info");
        assert!(LEVEL::UNDEFINED == *"undefined");
        assert!(LEVEL::UNDEFINED == *"undef");
    }

    #[test]
    fn test_level_partial_eq_str_rejects_mismatch() {
        assert!(!(LEVEL::HIGH == *"low"));
        assert!(!(LEVEL::HIGH == *"HIGH"));
        assert!(!(LEVEL::CRITICAL == *""));
    }

    #[test]
    fn test_level_convert_returns_self_when_no_critical_system_match() {
        // The default config/critical_systems.txt is empty, so no host name will match
        // and convert() should return the original level for every variant.
        for level in [
            LEVEL::INFORMATIONAL,
            LEVEL::LOW,
            LEVEL::MEDIUM,
            LEVEL::HIGH,
            LEVEL::CRITICAL,
            LEVEL::EMERGENCY,
            LEVEL::UNDEFINED,
        ] {
            assert_eq!(level.convert("UNKNOWN-HOST"), &level);
        }
    }

    #[test]
    fn test_level_convert_handles_pipe_separated_computers() {
        // convert() splits on " ¦ "; when none of the names match CRITICAL_SYSTEM
        // it should still return the original level rather than panic.
        assert_eq!(
            LEVEL::HIGH.convert("HOST-A ¦ HOST-B ¦ HOST-C"),
            &LEVEL::HIGH
        );
        assert_eq!(LEVEL::LOW.convert(""), &LEVEL::LOW);
    }

    #[test]
    fn test_get_output_color_returns_none_for_missing_level() {
        let map: HashMap<LEVEL, Colors> = HashMap::new();
        assert!(_get_output_color(&map, &LEVEL::HIGH).is_none());
    }

    #[test]
    fn test_get_output_color_returns_color_for_present_level() {
        let mut map: HashMap<LEVEL, Colors> = HashMap::new();
        map.insert(
            LEVEL::HIGH,
            Colors {
                output_color: Color::Rgb(0xff, 0xc1, 0x00),
                table_color: comfy_table::Color::Rgb {
                    r: 0xff,
                    g: 0xc1,
                    b: 0x00,
                },
            },
        );
        let got = _get_output_color(&map, &LEVEL::HIGH);
        assert_eq!(got, Some(Color::Rgb(0xff, 0xc1, 0x00)));
        assert!(_get_output_color(&map, &LEVEL::LOW).is_none());
    }

    #[test]
    fn test_create_output_color_map_loads_levels_when_color_enabled() {
        // With color enabled, the map should be populated either from the on-disk
        // config/level_color.txt or the embedded fallback. Either way it must
        // contain the levels listed in the shipped level_color.txt.
        let map = create_output_color_map(false);
        assert!(map.contains_key(&LEVEL::EMERGENCY));
        assert!(map.contains_key(&LEVEL::CRITICAL));
        assert!(map.contains_key(&LEVEL::HIGH));
        assert!(map.contains_key(&LEVEL::MEDIUM));
        assert!(map.contains_key(&LEVEL::LOW));
        // UNDEFINED is filtered out when building the map.
        assert!(!map.contains_key(&LEVEL::UNDEFINED));
    }
}

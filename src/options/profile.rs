use crate::detections::configs::{self, CURRENT_EXE_PATH};
use crate::detections::message::AlertMessage;
use crate::detections::utils::check_setting_path;
use crate::yaml;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use std::path::Path;
use yaml_rust::{Yaml, YamlLoader};

lazy_static! {
    pub static ref PROFILES: Option<HashMap<String, String>> = load_profile(
        check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "config/default_profile.txt"
        )
        .to_str()
        .unwrap(),
        check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "config/profiles.txt"
        )
        .to_str()
        .unwrap()
    );
}

// 指定されたパスのprofileを読み込む処理
fn read_profile_data(profile_path: &str) -> Result<Vec<Yaml>, String> {
    let yml = yaml::ParseYaml::new();
    if let Ok(loaded_profile) = yml.read_file(Path::new(profile_path).to_path_buf()) {
        match YamlLoader::load_from_str(&loaded_profile) {
            Ok(profile_yml) => Ok(profile_yml), 
            Err(e) => Err(format!("Parse error: {}. {}", profile_path, e))
        }
    } else {
        Err(format!(
            "Not exist profile file({}). Please check default profile.",
            profile_path
        ))
    }
}

/// プロファイル情報`を読み込む関数
pub fn load_profile(
    default_profile_path: &str,
    profile_path: &str,
) -> Option<HashMap<String, String>> {
    let conf = &configs::CONFIG.read().unwrap().args;
    let profile_all: Vec<Yaml> = if conf.profile.is_none() {
        match read_profile_data(default_profile_path) {
            Ok(data) => data,
            Err(e) => {
                AlertMessage::alert(&e).ok();
                vec![]
            }
        }
    } else {
        match read_profile_data(profile_path) {
            Ok(data) => data,
            Err(e) => {
                AlertMessage::alert(&e).ok();
                vec![]
            }
        }
    };

    // profileを読み込んで何も結果がない場合はAlert出しているためプログラム終了のためにNoneを出力する。
    if profile_all.is_empty() {
        return None;
    }
    let profile_data = &profile_all[0];
    let mut ret: HashMap<String, String> = HashMap::new();
    if let Some(profile_name) = &conf.profile {
        if !profile_data[profile_name.as_str()].is_badvalue() {
            profile_data[profile_name.as_str()].clone().as_hash().unwrap().into_iter().for_each(|(k, v)| {
                ret.insert(k.as_str().unwrap().to_string(), v.as_str().unwrap().to_string());
            });
            Some(ret)
        } else {
            AlertMessage::alert(&format!("Invalid profile specified: {}", profile_name)).ok();
            None
        }
    } else {
        AlertMessage::alert("Not specified --profile").ok();
        None
    }
}

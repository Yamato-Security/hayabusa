use crate::detections::configs::{self, CURRENT_EXE_PATH};
use crate::detections::message::AlertMessage;
use crate::detections::utils::check_setting_path;
use crate::yaml;
use linked_hash_map::LinkedHashMap;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

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

/// デフォルトプロファイルを設定する関数
pub fn set_default_profile(default_profile_path: &str, profile_path: &str) -> Result<(), String> {
    let profile_data: Vec<Yaml> = match read_profile_data(profile_path) {
        Ok(data) => data,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return Err("Failed set default profile.".to_string());
        }
    };

    // デフォルトプロファイルを設定する処理
    if let Some(profile_name) = &configs::CONFIG.read().unwrap().args.set_default_profile {
        if let Ok(mut buf_wtr) = File::open(default_profile_path).map(BufWriter::new) {
            let prof_all_data = &profile_data[0];
            let overwrite_default_data = &prof_all_data[profile_name.as_str()];
            println!("hoge is {:?}", prof_all_data["hoge"]);
            if !overwrite_default_data.is_null() {
                let mut out_str = String::default();
                let mut yml_writer = YamlEmitter::new(&mut out_str);
                let dump_result = yml_writer.dump(overwrite_default_data);
                match dump_result {
                    Ok(_) => match write!(buf_wtr, "{}", out_str) {
                        Err(e) => Err(format!(
                            "Failed set profile to default profile file({}). {}",
                            profile_path, e
                        )),
                        _ => Ok(()),
                    },
                    Err(e) => Err(format!(
                        "Failed set profile to default profile file({}). {}",
                        profile_path, e
                    )),
                }
            } else {
                Err(format!("Invalid profile specified: {}", profile_name))
            }
        } else {
            Err(format!(
                "Failed set profile to default profile file({}).",
                profile_path
            ))
        }
    } else {
        Err("Not specified --set-default-profile".to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::options::profile::load_profile;
    use crate::detections::configs;

    #[test]
    /// プロファイルオプションが設定されていないときにロードをした場合のテスト
    fn test_load_profile_without_profile_option() {
        configs::CONFIG.write().unwrap().args.profile = None;
        assert_eq!(None, load_profile("test_files/config/profile/default_profile.txt", "test_files/config/profile/target.txt"));
    }

    #[test]
    /// プロファイルオプションが設定されていないときにロードをした場合のテスト
    fn test_load_profile_no_exist_profile_files() {
        configs::CONFIG.write().unwrap().args.profile = Some("minimal".to_string());
        assert_eq!(None, load_profile("test_files/config/profile/no_exist_default_profile.txt", "test_files/config/profile/no_exist_target.txt"));
        assert_eq!(None, load_profile("test_files/config/profile/default_profile.txt", "test_files/config/profile/no_exist_target.txt"));
        assert_eq!(None, load_profile("test_files/config/profile/no_exist_default_profile.txt", "test_files/config/profile/target.txt"));
    }
}

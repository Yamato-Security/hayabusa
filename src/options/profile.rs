use crate::detections::configs::{self, CURRENT_EXE_PATH};
use crate::detections::message::AlertMessage;
use crate::detections::utils::check_setting_path;
use crate::yaml;
use hashbrown::HashSet;
use lazy_static::lazy_static;
use linked_hash_map::LinkedHashMap;
use regex::RegexSet;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

lazy_static! {
    pub static ref PROFILES: Option<LinkedHashMap<String, String>> = load_profile(
        check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "config/default_profile.yaml",
            true
        )
        .unwrap()
        .to_str()
        .unwrap(),
        check_setting_path(
            &CURRENT_EXE_PATH.to_path_buf(),
            "config/profiles.yaml",
            true
        )
        .unwrap()
        .to_str()
        .unwrap()
    );
    pub static ref LOAEDED_PROFILE_ALIAS: HashSet<String> = HashSet::from_iter(
        PROFILES
            .as_ref()
            .unwrap_or(&LinkedHashMap::default())
            .values()
            .cloned()
    );
    pub static ref PRELOAD_PROFILE: Vec<&'static str> = vec![
        "%Timestamp%",
        "%Computer%",
        "%Channel%",
        "%Level%",
        "%EventID%",
        "%RecordID%",
        "%RuleTitle%",
        "%RecordInformation%",
        "%RuleFile%",
        "%EvtxFile%",
        "%MitreTactics%",
        "%MitreTags%",
        "%OtherTags%",
        "%RuleAuthor%",
        "%RuleCreationDate%",
        "%RuleModifiedDate%",
        "%Status%",
    ];
    pub static ref PRELOAD_PROFILE_REGEX: RegexSet = RegexSet::new(&*PRELOAD_PROFILE).unwrap();
}

// 指定されたパスのprofileを読み込む処理
fn read_profile_data(profile_path: &str) -> Result<Vec<Yaml>, String> {
    let yml = yaml::ParseYaml::new();
    if let Ok(loaded_profile) = yml.read_file(Path::new(profile_path).to_path_buf()) {
        match YamlLoader::load_from_str(&loaded_profile) {
            Ok(profile_yml) => Ok(profile_yml),
            Err(e) => Err(format!("Parse error: {}. {}", profile_path, e)),
        }
    } else {
        Err(format!(
            "The profile file({}) does not exist. Please check your default profile.",
            profile_path
        ))
    }
}

/// プロファイル情報を読み込む関数
pub fn load_profile(
    default_profile_path: &str,
    profile_path: &str,
) -> Option<LinkedHashMap<String, String>> {
    let conf = &configs::CONFIG.read().unwrap().args;
    if conf.set_default_profile.is_some() {
        if let Err(e) = set_default_profile(default_profile_path, profile_path) {
            AlertMessage::alert(&e).ok();
        } else {
            println!("Successfully updated the default profile.");
        };
    }
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
    let mut ret: LinkedHashMap<String, String> = LinkedHashMap::new();
    if let Some(profile_name) = &conf.profile {
        let target_data = &profile_data[profile_name.as_str()];
        if !target_data.is_badvalue() {
            target_data
                .as_hash()
                .unwrap()
                .into_iter()
                .for_each(|(k, v)| {
                    ret.insert(
                        k.as_str().unwrap().to_string(),
                        v.as_str().unwrap().to_string(),
                    );
                });
            Some(ret)
        } else {
            let profile_names: Vec<&str> = profile_data
                .as_hash()
                .unwrap()
                .keys()
                .map(|k| k.as_str().unwrap())
                .collect();
            AlertMessage::alert(&format!(
                "Invalid profile specified: {}\nPlease specify one of the following profiles:\n {}",
                profile_name,
                profile_names.join(", ")
            ))
            .ok();
            None
        }
    } else {
        profile_data
            .as_hash()
            .unwrap()
            .into_iter()
            .for_each(|(k, v)| {
                ret.insert(
                    k.as_str().unwrap().to_string(),
                    v.as_str().unwrap().to_string(),
                );
            });
        Some(ret)
    }
}

/// デフォルトプロファイルを設定する関数
pub fn set_default_profile(default_profile_path: &str, profile_path: &str) -> Result<(), String> {
    let profile_data: Vec<Yaml> = match read_profile_data(profile_path) {
        Ok(data) => data,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return Err("Failed to set the default profile.".to_string());
        }
    };

    // デフォルトプロファイルを設定する処理
    if let Some(profile_name) = &configs::CONFIG.read().unwrap().args.set_default_profile {
        if let Ok(mut buf_wtr) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(default_profile_path)
            .map(BufWriter::new)
        {
            let prof_all_data = &profile_data[0];
            let overwrite_default_data = &prof_all_data[profile_name.as_str()];
            if !overwrite_default_data.is_badvalue() {
                let mut out_str = String::default();
                let mut yml_writer = YamlEmitter::new(&mut out_str);
                let dump_result = yml_writer.dump(overwrite_default_data);
                match dump_result {
                    Ok(_) => match buf_wtr.write_all(out_str.as_bytes()) {
                        Err(e) => Err(format!(
                            "Failed to set the default profile file({}). {}",
                            profile_path, e
                        )),
                        _ => {
                            buf_wtr.flush().ok();
                            Ok(())
                        }
                    },
                    Err(e) => Err(format!(
                        "Failed to set the default profile file({}). {}",
                        profile_path, e
                    )),
                }
            } else {
                let profile_names: Vec<&str> = prof_all_data
                    .as_hash()
                    .unwrap()
                    .keys()
                    .map(|k| k.as_str().unwrap())
                    .collect();
                Err(format!(
                    "Invalid profile specified: {}\nPlease specify one of the following profiles:\n{}",
                    profile_name,
                    profile_names.join(", ")
                ))
            }
        } else {
            Err(format!(
                "Failed to set the default profile file({}).",
                profile_path
            ))
        }
    } else {
        Err("Not specified: --set-default-profile".to_string())
    }
}

/// Get profile name and tag list in yaml file.
pub fn get_profile_list(profile_path: &str) -> Vec<Vec<String>> {
    let ymls = match read_profile_data(
        check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), profile_path, true)
            .unwrap()
            .to_str()
            .unwrap(),
    ) {
        Ok(data) => data,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            vec![]
        }
    };
    let mut ret = vec![];
    for yml in ymls.iter() {
        for (k, v) in yml.as_hash().unwrap() {
            let mut row = vec![];
            row.push(k.as_str().unwrap().to_string());
            let tmp: Vec<String> = v
                .as_hash()
                .unwrap()
                .values()
                .map(|contents| contents.as_str().unwrap().to_string())
                .collect();
            row.push(tmp.join(", "));
            ret.push(row);
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use linked_hash_map::LinkedHashMap;

    use crate::detections::configs;
    use crate::options::profile::{get_profile_list, load_profile};

    #[test]
    ///オプションの設定が入ると値の冪等性が担保できないためテストを逐次的に処理する
    fn test_load_profile() {
        test_load_profile_without_profile_option();
        test_load_profile_no_exist_profile_files();
        test_load_profile_with_profile_option();
        test_get_profile_names();
    }

    /// プロファイルオプションが設定されていないときにロードをした場合のテスト
    fn test_load_profile_without_profile_option() {
        configs::CONFIG.write().unwrap().args.profile = None;
        let mut expect: LinkedHashMap<String, String> = LinkedHashMap::new();
        expect.insert("Timestamp".to_owned(), "%Timestamp%".to_owned());
        expect.insert("Computer".to_owned(), "%Computer%".to_owned());
        expect.insert("Channel".to_owned(), "%Channel%".to_owned());
        expect.insert("Level".to_owned(), "%Level%".to_owned());
        expect.insert("EventID".to_owned(), "%EventID%".to_owned());
        expect.insert("MitreAttack".to_owned(), "%MitreAttack%".to_owned());
        expect.insert("RecordID".to_owned(), "%RecordID%".to_owned());
        expect.insert("RuleTitle".to_owned(), "%RuleTitle%".to_owned());
        expect.insert("Details".to_owned(), "%Details%".to_owned());
        expect.insert(
            "RecordInformation".to_owned(),
            "%RecordInformation%".to_owned(),
        );
        expect.insert("RuleFile".to_owned(), "%RuleFile%".to_owned());
        expect.insert("EvtxFile".to_owned(), "%EvtxFile%".to_owned());
        expect.insert("Tags".to_owned(), "%MitreAttack%".to_owned());

        assert_eq!(
            Some(expect),
            load_profile(
                "test_files/config/default_profile.yaml",
                "test_files/config/profiles.yaml"
            )
        );
    }

    /// プロファイルオプションが設定されて`おり、そのオプションに該当するプロファイルが存在する場合のテスト
    fn test_load_profile_with_profile_option() {
        configs::CONFIG.write().unwrap().args.profile = Some("minimal".to_string());
        let mut expect: LinkedHashMap<String, String> = LinkedHashMap::new();
        expect.insert("Timestamp".to_owned(), "%Timestamp%".to_owned());
        expect.insert("Computer".to_owned(), "%Computer%".to_owned());
        expect.insert("Channel".to_owned(), "%Channel%".to_owned());
        expect.insert("EventID".to_owned(), "%EventID%".to_owned());
        expect.insert("Level".to_owned(), "%Level%".to_owned());
        expect.insert("RuleTitle".to_owned(), "%RuleTitle%".to_owned());
        expect.insert("Details".to_owned(), "%Details%".to_owned());

        assert_eq!(
            Some(expect),
            load_profile(
                "test_files/config/default_profile.yaml",
                "test_files/config/profiles.yaml"
            )
        );
    }

    /// プロファイルオプションが設定されているが、対象のオプションが存在しない場合のテスト
    fn test_load_profile_no_exist_profile_files() {
        configs::CONFIG.write().unwrap().args.profile = Some("not_exist".to_string());

        //両方のファイルが存在しない場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/no_exist_profiles.yaml"
            )
        );

        //デフォルトプロファイルは存在しているがprofileオプションが指定されているため読み込み失敗の場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/profile/default_profile.yaml",
                "test_files/config/profile/no_exist_profiles.yaml"
            )
        );

        //オプション先のターゲットのプロファイルファイルが存在しているが、profileオプションで指定されたオプションが存在しない場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/profiles.yaml"
            )
        );
    }

    /// yamlファイル内のプロファイル名一覧を取得する機能のテスト
    fn test_get_profile_names() {
        let expect = vec![vec![
            "minimal", "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %Details%"
         ],
         vec!["standard", "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreAttack%, %RecordID%, %RuleTitle%, %Details%"],
         vec!["verbose-1", "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreAttack%, %RecordID%, %RuleTitle%, %Details%, %RuleFile%, %EvtxFile%"],
         vec!["verbose-2", "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreAttack%, %RecordID%, %RuleTitle%, %Details%, %RecordInformation%"],
         ];
        assert_eq!(expect, get_profile_list("test_files/config/profiles.yaml"));
    }
}

use crate::detections::configs::{Action, StoredStatic, CURRENT_EXE_PATH};
use crate::detections::message::AlertMessage;
use crate::detections::utils::check_setting_path;
use crate::options::profile::Profile::{
    AllFieldInfo, Channel, Computer, Details, EventID, EvtxFile, Level, Literal, MitreTactics,
    MitreTags, OtherTags, Provider, RecordID, RenderedMessage, RuleAuthor, RuleCreationDate,
    RuleFile, RuleID, RuleModifiedDate, RuleTitle, SrcASN, SrcCity, SrcCountry, Status, TgtASN,
    TgtCity, TgtCountry, Timestamp,
};
use crate::yaml;
use compact_str::CompactString;
use itertools::Itertools;
use nested::Nested;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum Profile {
    Timestamp(CompactString),
    Computer(CompactString),
    Channel(CompactString),
    Level(CompactString),
    EventID(CompactString),
    RecordID(CompactString),
    RuleTitle(CompactString),
    AllFieldInfo(CompactString),
    RuleFile(CompactString),
    EvtxFile(CompactString),
    MitreTactics(CompactString),
    MitreTags(CompactString),
    OtherTags(CompactString),
    RuleAuthor(CompactString),
    RuleCreationDate(CompactString),
    RuleModifiedDate(CompactString),
    Status(CompactString),
    RuleID(CompactString),
    Provider(CompactString),
    Details(CompactString),
    RenderedMessage(CompactString),
    SrcASN(CompactString),
    SrcCountry(CompactString),
    SrcCity(CompactString),
    TgtASN(CompactString),
    TgtCountry(CompactString),
    TgtCity(CompactString),
    Literal(CompactString), // profiles.yamlの固定文字列を変換なしでそのまま出力する場合
}

impl Profile {
    pub fn to_value(&self) -> String {
        match &self {
            Timestamp(v) | Computer(v) | Channel(v) | Level(v) | EventID(v) | RecordID(v)
            | RuleTitle(v) | AllFieldInfo(v) | RuleFile(v) | EvtxFile(v) | MitreTactics(v)
            | MitreTags(v) | OtherTags(v) | RuleAuthor(v) | RuleCreationDate(v)
            | RuleModifiedDate(v) | Status(v) | RuleID(v) | Provider(v) | Details(v)
            | RenderedMessage(v) | SrcASN(v) | SrcCountry(v) | SrcCity(v) | TgtASN(v)
            | TgtCountry(v) | TgtCity(v) | Literal(v) => v.to_string(),
        }
    }

    pub fn convert(&self, converted_string: &CompactString) -> Self {
        match self {
            Timestamp(_) => Timestamp(converted_string.to_owned()),
            Computer(_) => Computer(converted_string.to_owned()),
            Channel(_) => Channel(converted_string.to_owned()),
            Level(_) => Level(converted_string.to_owned()),
            EventID(_) => EventID(converted_string.to_owned()),
            RecordID(_) => RecordID(converted_string.to_owned()),
            RuleTitle(_) => RuleTitle(converted_string.to_owned()),
            RuleFile(_) => RuleFile(converted_string.to_owned()),
            EvtxFile(_) => EvtxFile(converted_string.to_owned()),
            MitreTactics(_) => MitreTactics(converted_string.to_owned()),
            MitreTags(_) => MitreTags(converted_string.to_owned()),
            OtherTags(_) => OtherTags(converted_string.to_owned()),
            RuleAuthor(_) => RuleAuthor(converted_string.to_owned()),
            RuleCreationDate(_) => RuleCreationDate(converted_string.to_owned()),
            RuleModifiedDate(_) => RuleModifiedDate(converted_string.to_owned()),
            Status(_) => Status(converted_string.to_owned()),
            RuleID(_) => RuleID(converted_string.to_owned()),
            Provider(_) => Provider(converted_string.to_owned()),
            RenderedMessage(_) => RenderedMessage(converted_string.to_owned()),
            SrcASN(_) => SrcASN(converted_string.to_owned()),
            SrcCountry(_) => SrcCountry(converted_string.to_owned()),
            SrcCity(_) => SrcCity(converted_string.to_owned()),
            TgtASN(_) => TgtASN(converted_string.to_owned()),
            TgtCountry(_) => TgtCountry(converted_string.to_owned()),
            TgtCity(_) => TgtCity(converted_string.to_owned()),
            p => p.to_owned(),
        }
    }
}

impl From<&str> for Profile {
    fn from(alias: &str) -> Self {
        match alias {
            "%Timestamp%" => Timestamp(Default::default()),
            "%Computer%" => Computer(Default::default()),
            "%Channel%" => Channel(Default::default()),
            "%Level%" => Level(Default::default()),
            "%EventID%" => EventID(Default::default()),
            "%RecordID%" => RecordID(Default::default()),
            "%RuleTitle%" => RuleTitle(Default::default()),
            "%AllFieldInfo%" => AllFieldInfo(Default::default()),
            "%RuleFile%" => RuleFile(Default::default()),
            "%EvtxFile%" => EvtxFile(Default::default()),
            "%MitreTactics%" => MitreTactics(Default::default()),
            "%MitreTags%" => MitreTags(Default::default()),
            "%OtherTags%" => OtherTags(Default::default()),
            "%RuleAuthor%" => RuleAuthor(Default::default()),
            "%RuleCreationDate%" => RuleCreationDate(Default::default()),
            "%RuleModifiedDate%" => RuleModifiedDate(Default::default()),
            "%Status%" => Status(Default::default()),
            "%RuleID%" => RuleID(Default::default()),
            "%Provider%" => Provider(Default::default()),
            "%Details%" => Details(Default::default()),
            "%RenderedMessage%" => RenderedMessage(Default::default()),
            s => Literal(CompactString::from(s)), // profiles.yamlの固定文字列を変換なしでそのまま出力する場合
        }
    }
}

// 指定されたパスのprofileを読み込む処理
fn read_profile_data(
    profile_path: &str,
    stored_static: &StoredStatic,
) -> Result<Vec<Yaml>, String> {
    let yml = yaml::ParseYaml::new(stored_static);
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
    opt_stored_static: Option<&StoredStatic>,
) -> Option<Vec<(CompactString, Profile)>> {
    if Action::to_usize(opt_stored_static?.config.action.as_ref()) == 7 {
        if let Err(e) = set_default_profile(
            default_profile_path,
            profile_path,
            opt_stored_static.as_ref().unwrap(),
        ) {
            AlertMessage::alert(&e).ok();
        } else {
            println!("Successfully updated the default profile.");
        }
    }

    let profile = if let Some(opt) = &opt_stored_static.as_ref().unwrap().output_option {
        &opt.profile
    } else {
        &None
    };

    let profile_all: Vec<Yaml> = if profile.is_none() {
        match read_profile_data(default_profile_path, opt_stored_static.unwrap()) {
            Ok(data) => data,
            Err(e) => {
                AlertMessage::alert(&e).ok();
                vec![]
            }
        }
    } else {
        match read_profile_data(profile_path, opt_stored_static.unwrap()) {
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
    let mut ret: Vec<(CompactString, Profile)> = vec![];

    // insert preserved keyword when get-ip option specified.
    if opt_stored_static.unwrap().geo_ip_db_path.is_some() {
        ret.push((CompactString::from("SrcASN"), Profile::from("SrcASN")));
        ret.push((
            CompactString::from("SrcCountry"),
            Profile::from("SrcCountry"),
        ));
        ret.push((CompactString::from("SrcCity"), Profile::from("SrcCity")));
        ret.push((CompactString::from("TgtASN"), Profile::from("TgtASN")));
        ret.push((
            CompactString::from("TgtCountry"),
            Profile::from("TgtCountry"),
        ));
        ret.push((CompactString::from("TgtCity"), Profile::from("TgtCity")));
    }

    if let Some(profile_name) = profile {
        let target_data = &profile_data[profile_name.as_str()];
        if !target_data.is_badvalue() {
            target_data
                .as_hash()
                .unwrap()
                .into_iter()
                .for_each(|(k, v)| {
                    ret.push((
                        CompactString::from(k.as_str().unwrap()),
                        Profile::from(v.as_str().unwrap()),
                    ));
                });
            Some(ret)
        } else {
            AlertMessage::alert(&format!(
                "Invalid profile specified: {}\nPlease specify one of the following profiles:\n {}",
                profile_name,
                profile_data
                    .as_hash()
                    .unwrap()
                    .keys()
                    .map(|k| k.as_str().unwrap())
                    .join(", ")
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
                ret.push((
                    CompactString::from(k.as_str().unwrap()),
                    Profile::from(v.as_str().unwrap()),
                ));
            });
        Some(ret)
    }
}

/// デフォルトプロファイルを設定する関数
pub fn set_default_profile(
    default_profile_path: &str,
    profile_path: &str,
    stored_static: &StoredStatic,
) -> Result<(), String> {
    let profile_data: Vec<Yaml> = match read_profile_data(profile_path, stored_static) {
        Ok(data) => data,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            return Err("Failed to set the default profile.".to_string());
        }
    };

    let set_default_profile = match &stored_static.config.action.as_ref().unwrap() {
        Action::SetDefaultProfile(s) => Some(s),
        _ => None,
    };
    if set_default_profile.is_some() && set_default_profile.unwrap().profile.is_some() {
        let profile_name = set_default_profile
            .as_ref()
            .unwrap()
            .profile
            .as_ref()
            .unwrap();
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
                let result = match dump_result {
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
                };
                result
            } else {
                Err(format!(
                    "Invalid profile specified: {}\nPlease specify one of the following profiles:\n{}",
                    profile_name,
                    prof_all_data
                    .as_hash()
                    .unwrap()
                    .keys()
                    .map(|k| k.as_str().unwrap()).join(", ")
                ))
            }
        } else {
            Err(format!(
                "Failed to set the default profile file({}).",
                profile_path
            ))
        }
    } else {
        Err("Failed to set the default profile file. Please specify a profile.".to_string())
    }
}

/// Get profile name and tag list in yaml file.
pub fn get_profile_list(profile_path: &str, stored_static: &StoredStatic) -> Nested<Vec<String>> {
    let ymls = match read_profile_data(
        check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), profile_path, true)
            .unwrap()
            .to_str()
            .unwrap(),
        stored_static,
    ) {
        Ok(data) => data,
        Err(e) => {
            AlertMessage::alert(&e).ok();
            vec![]
        }
    };
    let mut ret = Nested::<Vec<String>>::new();
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
    use std::path::Path;

    use crate::detections::configs::{
        Action, Config, CsvOutputOption, InputOption, OutputOption, StoredStatic, UpdateOption,
    };
    use crate::options::profile::{get_profile_list, load_profile, Profile};
    use compact_str::CompactString;
    use nested::Nested;

    fn create_dummy_stored_static(action: Action) -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action: Some(action),
            no_color: false,
            quiet: false,
            debug: false,
        }))
    }

    #[test]
    fn test_profile_enum_detail_arc_to_string() {
        let profile_enum = Profile::Details(String::from("a").into());
        assert_eq!("a", profile_enum.to_value())
    }

    #[test]
    ///オプションの設定が入ると値の冪等性が担保できないためテストを逐次的に処理する
    fn test_load_profile() {
        test_load_profile_without_profile_option();
        test_load_profile_no_exist_profile_files();
        test_load_profile_with_profile_option();
        test_get_profile_names();
    }

    #[test]
    fn test_get_profile_list_err_load() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                    },
                    profile: None,
                    output: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                },
                json_input: false,
                geo_ip: None,
            }));
        assert_eq!(
            Nested::<Vec<String>>::new(),
            get_profile_list("test_files/not_exist_path", &dummy_stored_static)
        );
    }

    /// プロファイルオプションが設定されていないときにロードをした場合のテスト
    fn test_load_profile_without_profile_option() {
        let expect: Vec<(CompactString, Profile)> = vec![
            (
                CompactString::new("Timestamp"),
                Profile::Timestamp(Default::default()),
            ),
            (
                CompactString::new("Computer"),
                Profile::Computer(Default::default()),
            ),
            (
                CompactString::new("Channel"),
                Profile::Channel(Default::default()),
            ),
            (
                CompactString::new("Level"),
                Profile::Level(Default::default()),
            ),
            (
                CompactString::new("EventID"),
                Profile::EventID(Default::default()),
            ),
            (
                CompactString::new("MitreAttack"),
                Profile::MitreTactics(Default::default()),
            ),
            (
                CompactString::new("RecordID"),
                Profile::RecordID(Default::default()),
            ),
            (
                CompactString::new("RuleTitle"),
                Profile::RuleTitle(Default::default()),
            ),
            (
                CompactString::new("Details"),
                Profile::Details(Default::default()),
            ),
            (
                CompactString::new("RecordInformation"),
                Profile::AllFieldInfo(Default::default()),
            ),
            (
                CompactString::new("RuleFile"),
                Profile::RuleFile(Default::default()),
            ),
            (
                CompactString::new("EvtxFile"),
                Profile::EvtxFile(Default::default()),
            ),
            (
                CompactString::new("Tags"),
                Profile::MitreTags(Default::default()),
            ),
        ];

        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                    },
                    profile: None,
                    output: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                },
                json_input: false,
                geo_ip: None,
            }));
        assert_eq!(
            Some(expect),
            load_profile(
                "test_files/config/default_profile.yaml",
                "test_files/config/profiles.yaml",
                Some(&dummy_stored_static),
            )
        );
    }

    /// プロファイルオプションが設定されて`おり、そのオプションに該当するプロファイルが存在する場合のテスト
    fn test_load_profile_with_profile_option() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                    },
                    profile: Some("minimal".to_string()),
                    output: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                },
                json_input: false,
                geo_ip: None,
            }));

        let expect: Vec<(CompactString, Profile)> = vec![
            (
                CompactString::new("Timestamp"),
                Profile::Timestamp(Default::default()),
            ),
            (
                CompactString::new("Computer"),
                Profile::Computer(Default::default()),
            ),
            (
                CompactString::new("Channel"),
                Profile::Channel(Default::default()),
            ),
            (
                CompactString::new("EventID"),
                Profile::EventID(Default::default()),
            ),
            (
                CompactString::new("Level"),
                Profile::Level(Default::default()),
            ),
            (
                CompactString::new("RuleTitle"),
                Profile::RuleTitle(Default::default()),
            ),
            (
                CompactString::new("Details"),
                Profile::Details(Default::default()),
            ),
        ];
        assert_eq!(
            Some(expect),
            load_profile(
                "test_files/config/default_profile.yaml",
                "test_files/config/profiles.yaml",
                Some(&dummy_stored_static),
            )
        );
    }

    /// プロファイルオプションが設定されているが、対象のオプションが存在しない場合のテスト
    fn test_load_profile_no_exist_profile_files() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    input_args: InputOption {
                        directory: None,
                        filepath: None,
                        live_analysis: false,
                        evtx_file_ext: None,
                        thread_number: None,
                        quiet_errors: false,
                        config: Path::new("./rules/config").to_path_buf(),
                        verbose: false,
                    },
                    profile: Some("not_exist".to_string()),
                    output: None,
                    enable_deprecated_rules: false,
                    exclude_status: None,
                    min_level: "informational".to_string(),
                    enable_noisy_rules: false,
                    end_timeline: None,
                    start_timeline: None,
                    eid_filter: false,
                    european_time: false,
                    iso_8601: false,
                    rfc_2822: false,
                    rfc_3339: false,
                    us_military_time: false,
                    us_time: false,
                    utc: false,
                    visualize_timeline: false,
                    rules: Path::new("./rules").to_path_buf(),
                    html_report: None,
                    no_summary: false,
                },
                json_input: false,
                geo_ip: None,
            }));
        //両方のファイルが存在しない場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/no_exist_profiles.yaml",
                Some(&dummy_stored_static),
            )
        );

        //デフォルトプロファイルは存在しているがprofileオプションが指定されているため読み込み失敗の場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/profile/default_profile.yaml",
                "test_files/config/profile/no_exist_profiles.yaml",
                None,
            )
        );

        //オプション先のターゲットのプロファイルファイルが存在しているが、profileオプションで指定されたオプションが存在しない場合
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/profiles.yaml",
                None,
            )
        );
    }

    /// yamlファイル内のプロファイル名一覧を取得する機能のテスト
    fn test_get_profile_names() {
        let mut expect: Nested<Vec<String>> = Nested::<Vec<String>>::new();
        expect.push(vec![
            "minimal".to_string(),
            "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %Details%"
                .to_string(),
        ]);
        expect.push(vec!["standard".to_string(), "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTags%, %RecordID%, %RuleTitle%, %Details%".to_string()]);
        expect.push(vec!["verbose-1".to_string(), "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTags%, %RecordID%, %RuleTitle%, %Details%, %RuleFile%, %EvtxFile%".to_string()]);
        expect.push(vec!["verbose-2".to_string(), "%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTags%, %RecordID%, %RuleTitle%, %Details%, %AllFieldInfo%".to_string()]);
        assert_eq!(
            expect,
            get_profile_list(
                "test_files/config/profiles.yaml",
                &create_dummy_stored_static(Action::UpdateRules(UpdateOption {
                    rules: Path::new("./rules").to_path_buf(),
                }))
            )
        );
    }
}

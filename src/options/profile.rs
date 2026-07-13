use crate::detections::configs::{Action, CURRENT_EXE_PATH, StoredStatic};
use crate::detections::message::AlertMessage;
use crate::detections::utils::check_setting_path;
use crate::options::profile::Profile::{
    AllFieldInfo, Channel, Computer, Details, EventID, EvtxFile, ExtraFieldInfo, Level, Literal,
    MitreTactics, MitreTags, OtherTags, Provider, RecordID, RecoveredRecord, RenderedMessage,
    RuleAuthor, RuleCreationDate, RuleFile, RuleID, RuleModifiedDate, RuleTitle, SrcASN, SrcCity,
    SrcCountry, Status, TgtASN, TgtCity, TgtCountry, Timestamp,
};
use crate::yaml;
use compact_str::CompactString;
use itertools::Itertools;
use nested::Nested;
use rust_embed::Embed;
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

// Embeds all config/*.yaml files into the binary at build time so the standard profile files can
// still be loaded when the config folder is missing on disk (see read_profile_data()).
#[derive(Embed)]
#[folder = "config/"]
#[include = "*.yaml"]
struct DefaultProfile;

/// One output column of a timeline profile. Each variant corresponds to a `%Alias%` placeholder
/// usable in profiles.yaml and identifies which piece of detection data fills the column. The
/// inner `Cow` carries the column's data: empty when first parsed from profiles.yaml, later
/// replaced via `convert()` with the value rendered for each detection.
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum Profile {
    Timestamp(Cow<'static, str>),
    Computer(Cow<'static, str>),
    Channel(Cow<'static, str>),
    Level(Cow<'static, str>),
    EventID(Cow<'static, str>),
    RecordID(Cow<'static, str>),
    RuleTitle(Cow<'static, str>),
    AllFieldInfo(Cow<'static, str>),
    RuleFile(Cow<'static, str>),
    EvtxFile(Cow<'static, str>),
    MitreTactics(Cow<'static, str>),
    MitreTags(Cow<'static, str>),
    OtherTags(Cow<'static, str>),
    RuleAuthor(Cow<'static, str>),
    RuleCreationDate(Cow<'static, str>),
    RuleModifiedDate(Cow<'static, str>),
    Status(Cow<'static, str>),
    RuleID(Cow<'static, str>),
    Provider(Cow<'static, str>),
    Details(Cow<'static, str>),
    RenderedMessage(Cow<'static, str>),
    SrcASN(Cow<'static, str>),
    SrcCountry(Cow<'static, str>),
    SrcCity(Cow<'static, str>),
    TgtASN(Cow<'static, str>),
    TgtCountry(Cow<'static, str>),
    TgtCity(Cow<'static, str>),
    ExtraFieldInfo(Cow<'static, str>),
    RecoveredRecord(Cow<'static, str>),
    Literal(Cow<'static, str>), // For outputting fixed strings from profiles.yaml without conversion.
}

impl Profile {
    /// Returns the inner value regardless of variant.
    pub fn to_value(&self) -> String {
        match &self {
            Timestamp(v) | Computer(v) | Channel(v) | Level(v) | EventID(v) | RecordID(v)
            | RuleTitle(v) | AllFieldInfo(v) | RuleFile(v) | EvtxFile(v) | MitreTactics(v)
            | MitreTags(v) | OtherTags(v) | RuleAuthor(v) | RuleCreationDate(v)
            | RuleModifiedDate(v) | Status(v) | RuleID(v) | Provider(v) | Details(v)
            | RenderedMessage(v) | SrcASN(v) | SrcCountry(v) | SrcCity(v) | TgtASN(v)
            | TgtCountry(v) | TgtCity(v) | RecoveredRecord(v) | ExtraFieldInfo(v) | Literal(v) => {
                v.to_string()
            }
        }
    }

    /// Returns a copy of this variant carrying `converted_string` as its value. Used to fill a
    /// profile column with the value rendered for the record currently being output.
    pub fn convert(&self, converted_string: &CompactString) -> Self {
        match self {
            Timestamp(_) => Timestamp(converted_string.to_owned().into()),
            Computer(_) => Computer(converted_string.to_owned().into()),
            Channel(_) => Channel(converted_string.to_owned().into()),
            Level(_) => Level(converted_string.to_owned().into()),
            EventID(_) => EventID(converted_string.to_owned().into()),
            RecordID(_) => RecordID(converted_string.to_owned().into()),
            RuleTitle(_) => RuleTitle(converted_string.to_owned().into()),
            RuleFile(_) => RuleFile(converted_string.to_owned().into()),
            EvtxFile(_) => EvtxFile(converted_string.to_owned().into()),
            MitreTactics(_) => MitreTactics(converted_string.to_owned().into()),
            MitreTags(_) => MitreTags(converted_string.to_owned().into()),
            OtherTags(_) => OtherTags(converted_string.to_owned().into()),
            RuleAuthor(_) => RuleAuthor(converted_string.to_owned().into()),
            RuleCreationDate(_) => RuleCreationDate(converted_string.to_owned().into()),
            RuleModifiedDate(_) => RuleModifiedDate(converted_string.to_owned().into()),
            Status(_) => Status(converted_string.to_owned().into()),
            RuleID(_) => RuleID(converted_string.to_owned().into()),
            Provider(_) => Provider(converted_string.to_owned().into()),
            RenderedMessage(_) => RenderedMessage(converted_string.to_owned().into()),
            SrcASN(_) => SrcASN(converted_string.to_owned().into()),
            SrcCountry(_) => SrcCountry(converted_string.to_owned().into()),
            SrcCity(_) => SrcCity(converted_string.to_owned().into()),
            TgtASN(_) => TgtASN(converted_string.to_owned().into()),
            TgtCountry(_) => TgtCountry(converted_string.to_owned().into()),
            TgtCity(_) => TgtCity(converted_string.to_owned().into()),
            ExtraFieldInfo(_) => ExtraFieldInfo(converted_string.to_owned().into()),
            RecoveredRecord(_) => RecoveredRecord(converted_string.to_owned().into()),
            Details(_) => Details(converted_string.to_owned().into()),
            AllFieldInfo(_) => AllFieldInfo(converted_string.to_owned().into()),
            // Literal is the only variant left: fixed strings are never converted per record.
            p => p.to_owned(),
        }
    }
}

/// Maps a `%Alias%` placeholder from profiles.yaml to its `Profile` variant. Any string that is
/// not a known alias becomes a `Literal` and is output verbatim.
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
            "%ExtraFieldInfo%" => ExtraFieldInfo(Default::default()),
            "%RecoveredRecord%" => RecoveredRecord(Default::default()),
            s => Literal(s.to_string().into()), // For outputting fixed strings from profiles.yaml without conversion.
        }
    }
}

// Loads the profile YAML at the specified path, falling back to the copy embedded in the binary
// (see DefaultProfile) when the file does not exist on disk.
fn read_profile_data(profile_path: &str) -> Result<Vec<Yaml>, String> {
    let profile_path_buf = Path::new(profile_path).to_path_buf();
    if let Ok(loaded_profile) = yaml::ParseYaml::read_file(&profile_path_buf) {
        match YamlLoader::load_from_str(&loaded_profile) {
            Ok(profile_yml) => Ok(profile_yml),
            Err(e) => Err(format!("Parse error: {profile_path}. {e}")),
        }
    } else {
        let default_profile_name_path = DefaultProfile::get(
            profile_path_buf
                .file_name()
                .unwrap()
                .to_str()
                .unwrap_or_default(),
        );
        // The file was not found on disk, but its file name matches one of the profile files
        // bundled into the binary, so load the embedded copy instead.
        if let Some(path) = default_profile_name_path {
            match YamlLoader::load_from_str(
                std::str::from_utf8(path.data.as_ref()).unwrap_or_default(),
            ) {
                Ok(profile_yml) => Ok(profile_yml),
                Err(e) => Err(format!("Parse error: {profile_path}. {e}")),
            }
        } else {
            Err(format!(
                "The profile file({profile_path}) does not exist. Please check your default profile."
            ))
        }
    }
}

/// Loads the output profile as an ordered list of (column name, field kind) pairs. The profile
/// named by the --profile option is used if one was given; otherwise the default profile is
/// loaded. Reserved GeoIP columns are appended when a GeoIP database has been loaded, and a
/// RecoveredRecord column is appended when record recovery is enabled. Returns None if
/// `opt_stored_static` is None or the profile cannot be loaded (in the latter case an alert has
/// already been printed).
pub fn load_profile(
    default_profile_path: &str,
    profile_path: &str,
    opt_stored_static: Option<&StoredStatic>,
) -> Option<Vec<(CompactString, Profile)>> {
    opt_stored_static.as_ref()?;
    let profile = if let Some(opt) = &opt_stored_static.as_ref().unwrap().output_option {
        &opt.profile
    } else {
        &None
    };

    let profile_all: Vec<Yaml> = if profile.is_none() {
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

    // If loading the profile yielded no documents, an alert was already printed above, so return
    // None to make the caller terminate the program.
    if profile_all.is_empty() {
        return None;
    }
    let profile_data = &profile_all[0];
    let mut ret: Vec<(CompactString, Profile)> = vec![];

    // yaml-rust2 hashes preserve insertion order, so the output columns keep the order in which
    // they are written in the profile file.
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
            return None;
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
    }
    // Append the reserved GeoIP output columns when the GeoIP option was specified (i.e. a GeoIP
    // database has been loaded).
    if opt_stored_static.unwrap().geo_ip_search.is_some() {
        ret.push((CompactString::from("SrcASN"), SrcASN(Cow::default())));
        ret.push((
            CompactString::from("SrcCountry"),
            SrcCountry(Cow::default()),
        ));
        ret.push((CompactString::from("SrcCity"), SrcCity(Cow::default())));
        ret.push((CompactString::from("TgtASN"), TgtASN(Cow::default())));
        ret.push((
            CompactString::from("TgtCountry"),
            TgtCountry(Cow::default()),
        ));
        ret.push((CompactString::from("TgtCity"), TgtCity(Cow::default())));
    }
    if let Some(opt) = &opt_stored_static.as_ref().unwrap().output_option
        && opt.input_args.recover_records
    {
        ret.push((
            CompactString::from("RecoveredRecord"),
            RecoveredRecord(Cow::default()),
        ));
    }
    Some(ret)
}

/// Handles the set-default-profile action: overwrites the default profile file with the contents
/// of the profile selected by --profile, and records the chosen profile name in
/// default_profile_name.txt next to it.
pub fn set_default_profile(
    default_profile_path: &str,
    profile_path: &str,
    stored_static: &StoredStatic,
) -> Result<(), String> {
    let profile_data: Vec<Yaml> = match read_profile_data(profile_path) {
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

    let default_profile_name_path = Path::new(default_profile_path)
        .to_path_buf()
        .with_file_name("default_profile_name.txt");

    if let Some(prof) = set_default_profile {
        let profile_name = prof.profile.as_ref().unwrap();
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
                            "Failed to set the default profile file({profile_path}). {e}"
                        )),
                        _ => {
                            buf_wtr.flush().ok();
                            if let Ok(mut default_name_buf_wtr) = OpenOptions::new()
                                .write(true)
                                .truncate(true)
                                .open(default_profile_name_path)
                                .map(BufWriter::new)
                            {
                                default_name_buf_wtr.write_all(profile_name.as_bytes()).ok();
                                println!("Successfully updated the default profile.\n");
                            }
                            Ok(())
                        }
                    },
                    Err(e) => Err(format!(
                        "Failed to set the default profile file({profile_path}). {e}"
                    )),
                }
            } else {
                Err(format!(
                    "Invalid profile specified: {}\nPlease specify one of the following profiles:\n{}",
                    profile_name,
                    prof_all_data
                        .as_hash()
                        .unwrap()
                        .keys()
                        .map(|k| k.as_str().unwrap())
                        .join(", ")
                ))
            }
        } else {
            Err(format!(
                "Failed to set the default profile file({profile_path})."
            ))
        }
    } else {
        Err("Failed to set the default profile file. Please specify a profile.".to_string())
    }
}

/// Returns one row per profile in the YAML file: the profile name followed by a comma-joined
/// list of its column placeholders. Backs the list-profiles command.
pub fn get_profile_list(profile_path: &str) -> Nested<Vec<String>> {
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

    use crate::detections::configs::{Action, Config, CsvOutputOption, OutputOption, StoredStatic};
    use crate::options::profile::{Profile, get_profile_list, load_profile};
    use compact_str::CompactString;
    use nested::Nested;

    fn create_dummy_stored_static(action: Action) -> StoredStatic {
        StoredStatic::create_static_data(Config {
            action: Some(action),
            debug: false,
        })
    }

    #[test]
    fn test_profile_enum_detail_arc_to_string() {
        let profile_enum = Profile::Details(String::from("a").into());
        assert_eq!("a", profile_enum.to_value())
    }

    #[test]
    /// The profile-loading assertions below are grouped into a single test and run sequentially.
    fn test_load_profile() {
        test_load_profile_without_profile_option();
        test_load_profile_no_exist_profile_files();
        test_load_profile_with_profile_option();
        test_get_profile_names();
    }

    #[test]
    fn test_get_profile_list_err_load() {
        assert_eq!(
            Nested::<Vec<String>>::new(),
            get_profile_list("test_files/not_exist_path")
        );
    }

    /// Test for when loading is done without the profile option set.
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
                    min_level: "informational".to_string(),
                    ..Default::default()
                },
                ..Default::default()
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

    /// Test for when the profile option is set and a profile matching that option exists.
    fn test_load_profile_with_profile_option() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    profile: Some("minimal".to_string()),
                    min_level: "informational".to_string(),
                    ..Default::default()
                },
                ..Default::default()
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

    /// Test for when the profile option is set but the target option does not exist.
    fn test_load_profile_no_exist_profile_files() {
        let dummy_stored_static =
            create_dummy_stored_static(Action::CsvTimeline(CsvOutputOption {
                output_options: OutputOption {
                    profile: Some("not_exist".to_string()),
                    min_level: "informational".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            }));
        // When neither file exists.
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/no_exist_profiles.yaml",
                Some(&dummy_stored_static),
            )
        );

        // When the default profile exists but loading fails because the profile option is specified.
        assert_eq!(
            None,
            load_profile(
                "test_files/config/profile/default_profile.yaml",
                "test_files/config/profile/no_exist_profiles.yaml",
                None,
            )
        );

        // When the target profile file for the option exists, but the option specified by the profile option does not exist.
        assert_eq!(
            None,
            load_profile(
                "test_files/config/no_exist_default_profile.yaml",
                "test_files/config/profiles.yaml",
                None,
            )
        );
    }

    /// Test for the feature that retrieves the list of profile names in a yaml file.
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
        assert_eq!(expect, get_profile_list("test_files/config/profiles.yaml"));
    }
}

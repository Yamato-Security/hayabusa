use crate::detections::configs::StoredStatic;
use crate::detections::message::AlertMessage;
use crate::detections::utils::write_color_buffer;
use crate::filter;
use crate::yaml::ParseYaml;
use chrono::{DateTime, Local, TimeZone};
use git2::{ErrorCode, Repository};
use serde_json::Value;
use std::fs::{self, create_dir};
use std::path::Path;

use hashbrown::{HashMap, HashSet};
use std::cmp::Ordering;

use std::time::SystemTime;

use termcolor::{BufferWriter, ColorChoice};

pub struct Update {}

impl Update {
    /// get latest hayabusa version number.
    pub fn get_latest_hayabusa_version() -> Result<Option<String>, Box<dyn std::error::Error>> {
        let text =
            ureq::get("https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest")
                .set("User-Agent", "HayabusaUpdateChecker")
                .set("Accept", "application/vnd.github.v3+json")
                .call()?
                .into_string()?;
        let json_res: Value = serde_json::from_str(&text)?;

        if json_res["tag_name"].is_null() {
            Ok(None)
        } else {
            Ok(Some(json_res["tag_name"].to_string()))
        }
    }

    /// update rules(hayabusa-rules subrepository)
    pub fn update_rules(
        rule_path: &str,
        stored_staic: &StoredStatic,
    ) -> Result<String, git2::Error> {
        let mut result;
        let mut prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let mut prev_modified_rules: HashSet<String> = HashSet::default();
        let hayabusa_repo = Repository::open(Path::new("."));
        let hayabusa_rule_repo = Repository::open(Path::new(rule_path));
        if hayabusa_repo.is_err() && hayabusa_rule_repo.is_err() {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "Attempting to git clone the hayabusa-rules repository into the rules folder.",
                true,
            )
            .ok();
            // execution git clone of hayabusa-rules repository when failed open hayabusa repository.
            result = Update::clone_rules(Path::new(rule_path));
        } else if hayabusa_rule_repo.is_ok() {
            // case of exist hayabusa-rules repository
            Update::_repo_main_reset_hard(hayabusa_rule_repo.as_ref().unwrap())?;
            // case of failed fetching origin/main, git clone is not executed so network error has occurred possibly.
            prev_modified_rules =
                Update::get_updated_rules(rule_path, &prev_modified_time, stored_staic);
            prev_modified_time = fs::metadata(rule_path).unwrap().modified().unwrap();
            result = Update::pull_repository(&hayabusa_rule_repo.unwrap());
        } else {
            // case of no exist hayabusa-rules repository in rules.
            // execute update because submodule information exists if hayabusa repository exists submodule information.

            let rules_path = Path::new(rule_path);
            if !rules_path.exists() {
                create_dir(rules_path).ok();
            }
            prev_modified_time = fs::metadata(rule_path).unwrap().modified().unwrap();
            if rule_path == "./rules" {
                let hayabusa_repo = hayabusa_repo.unwrap();
                let submodules = hayabusa_repo.submodules()?;
                let mut is_success_submodule_update = true;
                // submodule rules erase path is hard coding to avoid unintentional remove folder.
                fs::remove_dir_all(".git/.submodule/rules").ok();
                for mut submodule in submodules {
                    submodule.update(true, None)?;
                    let submodule_repo = submodule.open()?;
                    if let Err(e) = Update::pull_repository(&submodule_repo) {
                        AlertMessage::alert(&format!("Failed submodule update. {e}")).ok();
                        is_success_submodule_update = false;
                    }
                }
                if is_success_submodule_update {
                    result = Ok("Successed submodule update".to_string());
                } else {
                    result = Err(git2::Error::from_str(&String::default()));
                }
            } else {
                write_color_buffer(
                    &BufferWriter::stdout(ColorChoice::Always),
                    None,
                    "Attempting to git clone the hayabusa-rules repository into the rules folder.",
                    true,
                )
                .ok();
                // execution git clone of hayabusa-rules repository when failed open hayabusa repository.
                result = Update::clone_rules(rules_path);
            }
        }
        if result.is_ok() {
            let updated_modified_rules =
                Update::get_updated_rules(rule_path, &prev_modified_time, stored_staic);
            result =
                Update::print_diff_modified_rule_dates(prev_modified_rules, updated_modified_rules);
        }
        result
    }

    /// hard reset in main branch
    fn _repo_main_reset_hard(input_repo: &Repository) -> Result<(), git2::Error> {
        let branch = input_repo
            .find_branch("main", git2::BranchType::Local)
            .unwrap();
        let local_head = branch.get().target().unwrap();
        let object = input_repo.find_object(local_head, None).unwrap();
        match input_repo.reset(&object, git2::ResetType::Hard, None) {
            Ok(()) => Ok(()),
            _ => Err(git2::Error::from_str("Failed reset main branch in rules")),
        }
    }

    /// Pull(fetch and fast-forward merge) repositoryto input_repo.
    fn pull_repository(input_repo: &Repository) -> Result<String, git2::Error> {
        match input_repo
            .find_remote("origin")?
            .fetch(&["main"], None, None)
            .map_err(|e| {
                AlertMessage::alert(&format!("Failed git fetch to rules folder. {e}")).ok();
            }) {
            Ok(it) => it,
            Err(_err) => return Err(git2::Error::from_str(&String::default())),
        };
        let fetch_head = input_repo.find_reference("FETCH_HEAD")?;
        let fetch_commit = input_repo.reference_to_annotated_commit(&fetch_head)?;
        let analysis = input_repo.merge_analysis(&[&fetch_commit])?;
        if analysis.0.is_up_to_date() {
            Ok("Already up to date".to_string())
        } else if analysis.0.is_fast_forward() {
            let mut reference = input_repo.find_reference("refs/heads/main")?;
            reference.set_target(fetch_commit.id(), "Fast-Forward")?;
            input_repo.set_head("refs/heads/main")?;
            input_repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
            Ok("Finished fast forward merge.".to_string())
        } else if analysis.0.is_normal() {
            AlertMessage::alert(
            "update-rules option is git Fast-Forward merge only. please check your rules folder."
                ,
            ).ok();
            Err(git2::Error::from_str(&String::default()))
        } else {
            Err(git2::Error::from_str(&String::default()))
        }
    }

    /// git clone でhauyabusa-rules レポジトリをrulesフォルダにgit cloneする関数
    fn clone_rules(rules_path: &Path) -> Result<String, git2::Error> {
        match Repository::clone(
            "https://github.com/Yamato-Security/hayabusa-rules.git",
            rules_path,
        ) {
            Ok(_repo) => {
                println!("Finished cloning the hayabusa-rules repository.");
                Ok("Finished clone".to_string())
            }
            Err(e) => {
                if e.code() == ErrorCode::Exists {
                    AlertMessage::alert(
                        "You need to update the rules as the user that you downloaded Hayabusa with.\n        You can also move or delete the current rules folder to sync to the latest rules."
                    )
                        .ok();
                } else {
                    AlertMessage::alert(
                        "Failed to git clone into the rules folder. Please rename your rules folder name." )
                        .ok();
                }
                Err(e)
            }
        }
    }

    /// Create rules folder files Hashset. Format is "[rule title in yaml]|[filepath]|[filemodified date]|[rule type in yaml]"
    fn get_updated_rules(
        rule_folder_path: &str,
        target_date: &SystemTime,
        stored_staic: &StoredStatic,
    ) -> HashSet<String> {
        let mut rulefile_loader = ParseYaml::new(stored_staic);
        // level in read_dir is hard code to check all rules.
        rulefile_loader
            .read_dir(
                rule_folder_path,
                "INFORMATIONAL",
                "",
                &filter::RuleExclude::new(),
                stored_staic,
            )
            .ok();

        rulefile_loader
            .files
            .into_iter()
            .filter_map(|(filepath, yaml)| {
                let file_modified_date = fs::metadata(&filepath).unwrap().modified().unwrap();

                if file_modified_date.cmp(target_date).is_gt() {
                    let yaml_date = yaml["date"].as_str().unwrap_or("-");
                    return Option::Some(format!(
                        "{}|{}|{}|{}|{}",
                        yaml["title"].as_str().unwrap_or(&String::default()),
                        yaml["modified"].as_str().unwrap_or(yaml_date),
                        &filepath,
                        yaml["ruletype"].as_str().unwrap_or("Other"),
                        yaml.as_str().unwrap_or(&String::default())
                    ));
                }
                Option::None
            })
            .collect()
    }

    /// print updated rule files.
    fn print_diff_modified_rule_dates(
        prev_sets: HashSet<String>,
        updated_sets: HashSet<String>,
    ) -> Result<String, git2::Error> {
        let diff = updated_sets.difference(&prev_sets);
        let mut update_count_by_rule_type: HashMap<String, u128> = HashMap::new();
        let mut latest_update_date = Local.timestamp_opt(0, 0).unwrap();
        for diff_key in diff {
            let tmp: Vec<&str> = diff_key.split('|').collect();
            let file_modified_date = fs::metadata(tmp[2]).unwrap().modified().unwrap();

            let dt_local: DateTime<Local> = file_modified_date.into();

            if latest_update_date.cmp(&dt_local) == Ordering::Less {
                latest_update_date = dt_local;
            }
            *update_count_by_rule_type
                .entry(tmp[3].to_string())
                .or_insert(0b0) += 1;
            let path_str: &str = if tmp[2].starts_with("./") {
                tmp[2].strip_prefix("./").unwrap()
            } else {
                tmp[2]
            };
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                &format!(" - {} (Modified: {} | Path: {})", tmp[0], tmp[1], path_str),
                true,
            )
            .ok();
        }
        println!();
        for (key, value) in &update_count_by_rule_type {
            println!("Updated {key} rules: {value}");
        }
        if !&update_count_by_rule_type.is_empty() {
            Ok("Rule updated".to_string())
        } else {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                "You currently have the latest rules.",
                true,
            )
            .ok();
            Ok("You currently have the latest rules.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        detections::configs::{Action, CommonOptions, Config, StoredStatic, UpdateOption},
        options::update::Update,
    };
    use std::fs::read_to_string;
    use std::{path::Path, time::SystemTime};

    #[test]
    fn test_get_updated_rules() {
        let prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                },
            })),
            debug: false,
        }));
        let prev_modified_rules = Update::get_updated_rules(
            "test_files/rules/level_yaml",
            &prev_modified_time,
            &dummy_stored_static,
        );
        assert_eq!(prev_modified_rules.len(), 5);

        let target_time: SystemTime = SystemTime::now();
        let prev_modified_rules2 = Update::get_updated_rules(
            "test_files/rules/level_yaml",
            &target_time,
            &dummy_stored_static,
        );
        assert_eq!(prev_modified_rules2.len(), 0);
    }

    #[test]
    fn test_no_diff_print_diff_modified_rule_dates() {
        let prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                },
            })),
            debug: false,
        }));
        let prev_modified_rules = Update::get_updated_rules(
            "test_files/rules/level_yaml",
            &prev_modified_time,
            &dummy_stored_static,
        );
        let dummy_after_updated_rules = prev_modified_rules.clone();

        let actual =
            Update::print_diff_modified_rule_dates(prev_modified_rules, dummy_after_updated_rules);
        assert!(actual.is_ok());
        assert_eq!(
            actual.unwrap(),
            "You currently have the latest rules.".to_string()
        );
    }

    #[test]
    fn test_diff_print_diff_modified_rule_dates() {
        let prev_modified_time: SystemTime = SystemTime::UNIX_EPOCH;
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                },
            })),
            debug: false,
        }));
        let prev_modified_rules = Update::get_updated_rules(
            "test_files/rules/level_yaml",
            &prev_modified_time,
            &dummy_stored_static,
        );
        let mut dummy_after_updated_rules = prev_modified_rules.clone();
        dummy_after_updated_rules.insert(format!(
            "Dummy New|-|{}|Other|{}",
            Path::new("test_files/rules/yaml/1.yml").to_str().unwrap(),
            read_to_string(Path::new("test_files/rules/yaml/1.yml").to_str().unwrap())
                .unwrap_or_default()
        ));
        let actual =
            Update::print_diff_modified_rule_dates(prev_modified_rules, dummy_after_updated_rules);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), "Rule updated".to_string());
    }
}

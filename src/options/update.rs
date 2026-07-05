use crate::detections::configs::StoredStatic;
use crate::detections::message::AlertMessage;
use crate::detections::utils::{get_writable_color, write_color_buffer};
use crate::filter;
use crate::yaml::ParseYaml;
use git2::{ErrorCode, Repository};
use serde_json::Value;
use std::fs::{self, create_dir};
use std::path::Path;

use hashbrown::HashMap;

use termcolor::{BufferWriter, Color, ColorChoice};

pub struct Update {}

impl Update {
    /// Gets the latest Hayabusa version number (release tag name) from the GitHub Releases API.
    /// Note that the returned tag name keeps its JSON string quotes (Value::to_string), which the
    /// caller strips.
    pub fn get_latest_hayabusa_version() -> Result<Option<String>, Box<dyn std::error::Error>> {
        let text =
            ureq::get("https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest")
                .header("User-Agent", "HayabusaUpdateChecker")
                .header("Accept", "application/vnd.github.v3+json")
                .call()?
                .body_mut()
                .read_to_string()?;
        let json_res: Value = serde_json::from_str(&text)?;

        if json_res["tag_name"].is_null() {
            Ok(None)
        } else {
            Ok(Some(json_res["tag_name"].to_string()))
        }
    }

    /// Updates the detection rules (the hayabusa-rules repository, checked out in the rules
    /// folder or referenced as a git submodule), then prints which rule files changed.
    pub fn update_rules(
        rule_path: &str,
        stored_static: &StoredStatic,
    ) -> Result<String, git2::Error> {
        let mut result;
        let mut prev_modified_rules: HashMap<String, String> = HashMap::default();
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
            // Neither the hayabusa repository nor the rules repository could be opened, so git
            // clone the hayabusa-rules repository from scratch.
            result = Update::clone_rules(Path::new(rule_path));
        } else if hayabusa_rule_repo.is_ok() {
            // The hayabusa-rules repository already exists: hard reset it to local main, then
            // pull. If fetching origin/main fails here, no git clone fallback is attempted, so a
            // failure most likely means a network error.
            Update::_repo_main_reset_hard(hayabusa_rule_repo.as_ref().unwrap())?;
            prev_modified_rules = Update::get_updated_rules(rule_path, stored_static);
            result = Update::pull_repository(&hayabusa_rule_repo.unwrap());
        } else {
            // The rules folder is not a git repository, but the hayabusa repository itself could
            // be opened. If the hayabusa repository has submodule information (i.e. it is a
            // source checkout), update the rules through the submodule.

            let rules_path = Path::new(rule_path);
            if !rules_path.exists() {
                create_dir(rules_path).ok();
            }
            if rule_path == "./rules" {
                let hayabusa_repo = hayabusa_repo.unwrap();
                let submodules = hayabusa_repo.submodules()?;
                let mut submodule_update_succeeded = true;
                // The stale submodule metadata path to delete is hardcoded so that no unintended
                // folder can be removed.
                fs::remove_dir_all(".git/.submodule/rules").ok();
                for mut submodule in submodules {
                    submodule.update(true, None)?;
                    let submodule_repo = submodule.open()?;
                    if let Err(e) = Update::pull_repository(&submodule_repo) {
                        AlertMessage::alert(&format!("Failed submodule update. {e}")).ok();
                        submodule_update_succeeded = false;
                    }
                }
                if submodule_update_succeeded {
                    result = Ok("Submodule update succeeded".to_string());
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
                // A custom rules path is not managed as a submodule, so git clone the
                // hayabusa-rules repository into it instead.
                result = Update::clone_rules(rules_path);
            }
        }
        if result.is_ok() {
            let updated_modified_rules = Update::get_updated_rules(rule_path, stored_static);
            result = Update::print_diff_modified_rule_dates(
                prev_modified_rules,
                updated_modified_rules,
                stored_static.common_options.no_color,
            );
        }
        result
    }

    /// Hard resets the repository to the head of its local main branch, discarding any local
    /// changes.
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

    /// Pulls (fetches and fast-forward merges) the remote main branch into input_repo. Only
    /// fast-forward merges are supported; any other merge state is reported as an error.
    fn pull_repository(input_repo: &Repository) -> Result<String, git2::Error> {
        match input_repo
            .find_remote("origin")?
            .fetch(&["main"], None, None)
        {
            Ok(it) => it,
            Err(e) => {
                AlertMessage::alert(&format!("Failed git fetch to rules folder. {e}")).ok();
                return Err(git2::Error::from_str(&String::default()));
            }
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

    /// Function that git clones the hayabusa-rules repository into the rules folder.
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

    /// Collects the current rule files into a map of file path ->
    /// "[title]|[modified field, falling back to the date field]|[file path]|[rule type]|[parsed yaml]", used to diff
    /// the rule set before and after an update. The full parsed YAML is included so that any
    /// content change is detected even when the modified date stays the same.
    fn get_updated_rules(
        rule_folder_path: &str,
        stored_static: &StoredStatic,
    ) -> HashMap<String, String> {
        let mut rulefile_loader = ParseYaml::new(stored_static);
        // The level passed to read_dir is hardcoded to INFORMATIONAL so that every rule is
        // loaded.
        rulefile_loader
            .read_dir(
                rule_folder_path,
                "INFORMATIONAL",
                "",
                &filter::RuleExclude::new(),
                stored_static,
            )
            .ok();

        HashMap::from_iter(rulefile_loader.files.into_iter().map(|(filepath, yaml)| {
            let yaml_date = yaml["date"].as_str().unwrap_or("-");
            (
                filepath.clone(),
                format!(
                    "{}|{}|{}|{}|{:?}",
                    yaml["title"].as_str().unwrap_or(&String::default()),
                    yaml["modified"].as_str().unwrap_or(yaml_date),
                    &filepath,
                    yaml["ruletype"].as_str().unwrap_or("Other"),
                    yaml
                ),
            )
        }))
    }

    /// Prints the rule files that were added or changed by the update, followed by per-rule-type
    /// update counts. Returns a message describing whether anything was updated.
    fn print_diff_modified_rule_dates(
        prev_sets: HashMap<String, String>,
        updated_sets: HashMap<String, String>,
        no_color: bool,
    ) -> Result<String, git2::Error> {
        let diff = updated_sets.iter().filter_map(|(k, v)| {
            if let Some(prev_val) = prev_sets.get(k) {
                if prev_val != v { Some(v) } else { None }
            } else {
                Some(v)
            }
        });
        let mut update_count_by_rule_type: HashMap<String, u128> = HashMap::new();
        for diff_key in diff {
            let tmp: Vec<&str> = diff_key.split('|').collect();
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
        if !update_count_by_rule_type.is_empty() {
            println!();
        }
        for (key, value) in &update_count_by_rule_type {
            let msg = format!("Updated {key} rules: ");
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(Some(Color::Rgb(0, 255, 0)), no_color),
                msg.as_str(),
                false,
            )
            .ok();
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                None,
                value.to_string().as_str(),
                true,
            )
            .ok();
        }
        if !&update_count_by_rule_type.is_empty() {
            println!();
            Ok("Rule updated".to_string())
        } else {
            write_color_buffer(
                &BufferWriter::stdout(ColorChoice::Always),
                get_writable_color(Some(Color::Rgb(255, 175, 0)), no_color),
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
    use std::path::Path;

    #[test]
    fn test_get_updated_rules() {
        let mut dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
            })),
            debug: false,
        }));
        dummy_stored_static.include_status.insert("*".into());
        let prev_modified_rules =
            Update::get_updated_rules("test_files/rules/level_yaml", &dummy_stored_static);
        assert_eq!(prev_modified_rules.len(), 5);

        let prev_modified_rules2 =
            Update::get_updated_rules("test_files/rules/level_yaml", &dummy_stored_static);
        assert_eq!(prev_modified_rules2.len(), 5);
    }

    #[test]
    fn test_no_diff_print_diff_modified_rule_dates() {
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
            })),
            debug: false,
        }));
        let prev_modified_rules =
            Update::get_updated_rules("test_files/rules/level_yaml", &dummy_stored_static);
        let dummy_after_updated_rules = prev_modified_rules.clone();

        let actual = Update::print_diff_modified_rule_dates(
            prev_modified_rules,
            dummy_after_updated_rules,
            false,
        );
        assert!(actual.is_ok());
        assert_eq!(
            actual.unwrap(),
            "You currently have the latest rules.".to_string()
        );
    }

    #[test]
    fn test_diff_print_diff_modified_rule_dates() {
        let dummy_stored_static = StoredStatic::create_static_data(Some(Config {
            action: Some(Action::UpdateRules(UpdateOption {
                rules: Path::new("./rules").to_path_buf(),
                common_options: CommonOptions {
                    no_color: false,
                    quiet: false,
                    help: None,
                },
            })),
            debug: false,
        }));
        let prev_modified_rules =
            Update::get_updated_rules("test_files/rules/level_yaml", &dummy_stored_static);
        let mut dummy_after_updated_rules = prev_modified_rules.clone();
        dummy_after_updated_rules.insert(
            "test_files/rules/yaml/1.yml".to_string(),
            format!(
                "Dummy New|-|{}|Other|{}",
                Path::new("test_files/rules/yaml/1.yml").to_str().unwrap(),
                read_to_string(Path::new("test_files/rules/yaml/1.yml").to_str().unwrap())
                    .unwrap_or_default()
            ),
        );
        let actual = Update::print_diff_modified_rule_dates(
            prev_modified_rules,
            dummy_after_updated_rules,
            false,
        );
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), "Rule updated".to_string());
    }
}

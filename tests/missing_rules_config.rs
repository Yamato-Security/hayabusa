//! Exercise real CLI startup in isolated packages, without process-global cwd changes.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn copy_tree(source: &Path, target: &Path, excluded: &[&str]) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if excluded.iter().any(|excluded| name == *excluded) {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target.join(name), excluded);
        } else {
            fs::copy(entry.path(), target.join(name)).unwrap();
        }
    }
}

struct Package {
    _temp: TempDir,
    directory: PathBuf,
    cwd: PathBuf,
    binary: PathBuf,
}
impl Package {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("package");
        let cwd = temp.path().join("working-directory");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&cwd).unwrap();
        let binary = directory.join(format!("hayabusa{}", std::env::consts::EXE_SUFFIX));
        fs::hard_link(env!("CARGO_BIN_EXE_hayabusa"), &binary)
            .or_else(|_| fs::copy(env!("CARGO_BIN_EXE_hayabusa"), &binary).map(|_| ()))
            .unwrap();
        copy_tree(
            &source_root().join("config"),
            &directory.join("config"),
            &[],
        );
        Self {
            _temp: temp,
            directory,
            cwd,
            binary,
        }
    }

    fn install_configs(&self, excluded: &[&str]) {
        copy_tree(
            &source_root().join("rules/config"),
            &self.directory.join("rules/config"),
            excluded,
        );
    }

    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .current_dir(&self.cwd)
            .arg(action)
            .args(["-q", "-K"]);
        command
    }

    fn search(&self, output: &str, custom: Option<&Path>) -> (Output, PathBuf) {
        let target = self.cwd.join(output);
        let mut command = self.command("search");
        command
            .arg("-f")
            .arg(source_root().join("test_files/vhdx/Security.evtx"))
            .args(["-r", ".*", "--threads", "2", "-o"])
            .arg(&target);
        if let Some(custom) = custom {
            command.arg("-c").arg(custom);
        }
        let output = command.output().unwrap();
        (output, target)
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn success(output: &Output) {
    assert!(output.status.success(), "{}", text(output));
    assert!(
        !text(output).contains("Cannot open file"),
        "{}",
        text(output)
    );
}

#[test]
fn incomplete_or_missing_custom_config_folders_are_rejected() {
    let package = Package::new();
    package.install_configs(&[]);
    let (control, control_path) = package.search("control.csv", None);
    success(&control);
    assert!(
        csv::Reader::from_path(control_path)
            .unwrap()
            .records()
            .next()
            .is_some()
    );
    for variant in ["missing", "empty", "partial"] {
        let custom = package.cwd.join(variant);
        if variant != "missing" {
            fs::create_dir(&custom).unwrap();
        }
        if variant == "partial" {
            fs::copy(
                package.directory.join("rules/config/eventkey_alias.txt"),
                custom.join("eventkey_alias.txt"),
            )
            .unwrap();
        }
        // A -c folder is checked on its own; nothing is taken from the bundled copies.
        let (output, path) = package.search(&format!("{variant}.csv"), Some(&custom));
        let message = text(&output);
        assert_eq!(output.status.code(), Some(1), "{variant}: {message}");
        assert_eq!(
            message.matches("[ERROR]").count(),
            1,
            "{variant}: {message}"
        );
        assert!(
            message.contains("-c") && !message.contains("Cannot open file"),
            "{variant}: {message}"
        );
        if variant == "missing" {
            assert!(message.contains("was not found"), "{message}");
        } else {
            assert!(
                message.contains("missing the required config files")
                    && message.contains("channel_abbreviations.txt"),
                "{variant}: {message}"
            );
        }
        if variant == "partial" {
            assert!(!message.contains("eventkey_alias.txt"), "{message}");
        }
        assert!(!path.exists(), "{variant}");
    }
}

#[test]
fn a_complete_custom_config_folder_is_used() {
    let package = Package::new();
    package.install_configs(&[]);
    let custom = package.cwd.join("custom");
    copy_tree(&source_root().join("rules/config"), &custom, &[]);
    fs::write(
        custom.join("channel_abbreviations.txt"),
        "Channel,Abbreviation\nSecurity,CUSTOM\n",
    )
    .unwrap();
    let (output, path) = package.search("custom.csv", Some(&custom));
    success(&output);
    let mut reader = csv::Reader::from_path(path).unwrap();
    let channel = reader
        .headers()
        .unwrap()
        .iter()
        .position(|h| h == "Channel")
        .unwrap();
    let records: Vec<_> = reader.records().collect::<Result<_, _>>().unwrap();
    assert!(!records.is_empty());
    assert!(records.iter().all(|row| row.get(channel) == Some("CUSTOM")));
}

#[test]
fn missing_empty_and_incomplete_bundles_emit_one_actionable_error() {
    for state in [
        "missing",
        "empty",
        "incomplete",
        "directory-instead-of-file",
    ] {
        let package = Package::new();
        match state {
            "empty" => fs::create_dir_all(package.directory.join("rules/config")).unwrap(),
            // The abbreviation files were previously not validated, although startup reads them.
            "incomplete" => package.install_configs(&["provider_abbreviations.txt"]),
            "directory-instead-of-file" => {
                package.install_configs(&["provider_abbreviations.txt"]);
                fs::create_dir(
                    package
                        .directory
                        .join("rules/config/provider_abbreviations.txt"),
                )
                .unwrap();
            }
            _ => {}
        }
        for action in ["search", "eid-metrics", "logon-summary", "dfir-timeline"] {
            let mut command = package.command(action);
            command
                .arg("-f")
                .arg(source_root().join("test_files/vhdx/Security.evtx"));
            if action == "search" {
                command.args(["-r", ".*"]);
            }
            if action == "dfir-timeline" {
                // A missing core bundle must also suppress the optional proven_rules reader.
                command.args(["-w", "-P"]);
            }
            let output = command.output().unwrap();
            let message = text(&output);
            assert_eq!(output.status.code(), Some(1), "{state}/{action}: {message}");
            assert_eq!(
                message.matches("[ERROR]").count(),
                1,
                "{state}/{action}: {message}"
            );
            assert!(
                message.contains("update-rules"),
                "{state}/{action}: {message}"
            );
            assert!(
                !message.contains("Cannot open file"),
                "{state}/{action}: {message}"
            );
        }
        // Commands that do not use detection configuration must still work before download.
        success(&package.command("list-profiles").output().unwrap());
    }
}

fn append_bundle(source: &Path, prefix: &str, output: &mut String) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let relative = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().unwrap().is_dir() {
            append_bundle(&entry.path(), &format!("{relative}/"), output);
        } else {
            output.push_str(&format!(
                "---FILE_START---\npath: {relative}\n---CONTENT---\n{}\n---FILE_END---\n",
                fs::read_to_string(entry.path()).unwrap()
            ));
        }
    }
}

#[test]
fn live_response_bundle_works_without_an_on_disk_config_folder() {
    let package = Package::new();
    let mut bundle = String::new();
    append_bundle(&source_root().join("rules/config"), "", &mut bundle);
    fs::write(package.cwd.join("rules_config_files.txt"), bundle).unwrap();
    let (output, path) = package.search("embedded.csv", None);
    success(&output);
    let records = csv::Reader::from_path(path).unwrap().records().count();
    assert!(records > 0);
}

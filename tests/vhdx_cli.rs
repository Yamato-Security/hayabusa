//! End-to-end tests use public CC0 EVTX data; no private evidence is embedded.

use flate2::read::GzDecoder;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn unpack(dir: &Path, fixture: &str, filename: &str) -> PathBuf {
    let path = dir.join(filename);
    let mut reader =
        GzDecoder::new(fs::File::open(root().join("test_files/vhdx").join(fixture)).unwrap());
    std::io::copy(&mut reader, &mut fs::File::create(&path).unwrap()).unwrap();
    path
}
fn command(binary: &Path, mounts: &Path, subcommand: &str, input: &Path, image: bool) -> Command {
    let mut cmd = Command::new(binary);
    cmd.current_dir(root())
        .env("TMPDIR", mounts)
        .env("TEMP", mounts)
        .env("TMP", mounts)
        .arg(subcommand)
        .args(["-q", "-K"]);
    if image {
        cmd.arg("--vhdx");
    }
    cmd.arg(if input.is_dir() { "-d" } else { "-f" }).arg(input);
    cmd
}
fn success(cmd: &mut Command) -> Output {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{cmd:?}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn normalized(path: &Path, source: &Path, image: bool) -> String {
    let source = format!(
        "{}{}",
        source.display(),
        if image { "!/Security.evtx" } else { "" }
    );
    // JSON escapes Windows backslashes; CSV contains the literal path.
    let encoded = serde_json::to_string(&source).unwrap();
    fs::read_to_string(path)
        .unwrap()
        .replace(&encoded[1..encoded.len() - 1], "<SOURCE>/Security.evtx")
        .replace(&source, "<SOURCE>/Security.evtx")
}
fn empty_work_dir(path: &Path) {
    assert_eq!(
        fs::read_dir(path).unwrap().count(),
        0,
        "mount points were not cleaned up: {}",
        path.display()
    );
}
fn work_dir(temp: &TempDir) -> PathBuf {
    let dir = temp.path().join("mounts");
    fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn all_profiles_and_formats_match_extracted_evtx() {
    let temp = tempfile::tempdir().unwrap();
    let mounts = work_dir(&temp);
    let image = unpack(temp.path(), "logs.vhdx.gz", "logs.vhdx");
    let original = fs::read(&image).unwrap();
    let baseline = root().join("test_files/vhdx/Security.evtx");
    for profile in [
        "minimal",
        "standard",
        "verbose",
        "all-field-info",
        "all-field-info-verbose",
        "super-verbose",
        "timesketch-minimal",
        "timesketch-verbose",
    ] {
        for format in ["csv", "json", "jsonl"] {
            let mut outputs = Vec::new();
            for (input, vhdx) in [(&baseline, false), (&image, true)] {
                let out = temp
                    .path()
                    .join(format!("{profile}-{format}-{vhdx}.{format}"));
                success(
                    command(
                        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
                        &mounts,
                        "dfir-timeline",
                        input,
                        vhdx,
                    )
                    .args([
                        "-w",
                        "-A",
                        "-a",
                        "-U",
                        "-s",
                        "-r",
                        "test_files/vhdx/events.yml",
                        "-p",
                        profile,
                        "-t",
                        format,
                        "-o",
                    ])
                    .arg(&out),
                );
                let data = normalized(&out, input, vhdx);
                if format == "csv" {
                    let rows: Vec<_> = csv::Reader::from_reader(data.as_bytes())
                        .records()
                        .collect::<Result<_, _>>()
                        .unwrap();
                    assert!(!rows.is_empty(), "no detections for {profile}");
                } else {
                    let values: Vec<_> = serde_json::Deserializer::from_str(&data)
                        .into_iter::<serde_json::Value>()
                        .collect::<Result<_, _>>()
                        .unwrap();
                    assert!(!values.is_empty(), "no JSON detections for {profile}");
                }
                outputs.push(data);
                empty_work_dir(&mounts);
            }
            assert_eq!(outputs[0], outputs[1], "{profile}/{format}");
        }
    }
    assert_eq!(original, fs::read(&image).unwrap(), "source image changed");
}

#[test]
fn scanning_commands_match_extracted_logs() {
    let temp = tempfile::tempdir().unwrap();
    let mounts = work_dir(&temp);
    let image = unpack(temp.path(), "logs.vhdx.gz", "logs.vhdx");
    let baseline = root().join("test_files/vhdx/Security.evtx");
    for subcommand in [
        "eid-metrics",
        "log-metrics",
        "logon-summary",
        "computer-metrics",
        "extract-base64",
        "search",
        "pivot-keywords-list",
        "config-critical-systems",
    ] {
        let mut results = Vec::new();
        for (input, vhdx) in [(&baseline, false), (&image, true)] {
            let out = temp.path().join(format!("{subcommand}-{vhdx}.csv"));
            // Only this command writes beside its executable; isolate that config.
            let binary = if subcommand == "config-critical-systems" {
                let bin_dir = temp.path().join("critical-bin");
                fs::create_dir_all(bin_dir.join("config")).unwrap();
                let binary = bin_dir.join(format!("hayabusa{}", std::env::consts::EXE_SUFFIX));
                if !binary.exists() {
                    fs::copy(env!("CARGO_BIN_EXE_hayabusa"), &binary).unwrap();
                }
                fs::write(bin_dir.join("config/critical_systems.txt"), "").unwrap();
                binary
            } else {
                PathBuf::from(env!("CARGO_BIN_EXE_hayabusa"))
            };
            let mut cmd = command(&binary, &mounts, subcommand, input, vhdx);
            if subcommand != "config-critical-systems" {
                cmd.arg("-o").arg(&out);
            }
            if subcommand == "search" {
                cmd.args(["-r", ".*"]);
            }
            if subcommand == "pivot-keywords-list" {
                cmd.arg("-w");
            }
            let output = success(&mut cmd);
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .replace("\x1b[0m", "")
                    .contains("Total event log files: 1"),
                "{subcommand} did not scan one log: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let mut files: Vec<_> = fs::read_dir(temp.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.is_file()
                        && p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(&format!("{subcommand}-{vhdx}.csv"))
                })
                .collect();
            files.sort();
            results.push(
                files
                    .iter()
                    .map(|p| normalized(p, input, vhdx))
                    .collect::<Vec<_>>(),
            );
            empty_work_dir(&mounts);
        }
        assert_eq!(results[0], results[1], "{subcommand}");
    }
    // JSON event input inside the image uses the same reader as an extracted JSON file.
    let mut results = Vec::new();
    for (input, vhdx) in [
        (&root().join("test_files/evtx/test.json"), false),
        (&image, true),
    ] {
        let out = temp.path().join(format!("json-input-{vhdx}.csv"));
        success(
            command(
                Path::new(env!("CARGO_BIN_EXE_hayabusa")),
                &mounts,
                "eid-metrics",
                input,
                vhdx,
            )
            .args(["-J", "-o"])
            .arg(&out),
        );
        results.push(fs::read_to_string(out).unwrap());
        empty_work_dir(&mounts);
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn directory_depth_multiple_volumes_and_partial_failure() {
    let temp = tempfile::tempdir().unwrap();
    let mounts = work_dir(&temp);
    let inputs = temp.path().join("inputs");
    fs::create_dir_all(inputs.join("a/b/c/d")).unwrap();
    let first = unpack(&inputs, "logs.vhdx.gz", "one.vhdx");
    unpack(&inputs.join("a/b/c"), "logs.vhdx.gz", "two.VHDX");
    // Deliberately invalid image below the depth limit must not be opened.
    fs::write(inputs.join("a/b/c/d/ignored.vhdx"), b"not an image").unwrap();
    let out = temp.path().join("depth.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &mounts,
            "log-metrics",
            &inputs,
            true,
        )
        .arg("-o")
        .arg(&out),
    );
    assert_eq!(csv::Reader::from_path(&out).unwrap().records().count(), 2);
    empty_work_dir(&mounts);
    let multi = unpack(temp.path(), "two-volumes.vhdx.gz", "multi.vhdx");
    let multiout = temp.path().join("volumes.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &mounts,
            "search",
            &multi,
            true,
        )
        .args(["-r", ".*", "-o"])
        .arg(&multiout),
    );
    let data = fs::read_to_string(multiout).unwrap();
    assert!(data.contains("multi.vhdx!/Volume1/Security.evtx"));
    assert!(data.contains("multi.vhdx!/Volume2/Security.evtx"));
    empty_work_dir(&mounts);
    fs::write(inputs.join("broken.vhdx"), b"not an image").unwrap();
    let out = temp.path().join("partial.csv");
    let output = command(
        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
        &mounts,
        "log-metrics",
        &inputs,
        true,
    )
    .arg("-o")
    .arg(&out)
    .output()
    .unwrap();
    assert!(
        !output.status.success(),
        "partial failures must have a failing exit status"
    );
    assert_eq!(csv::Reader::from_path(out).unwrap().records().count(), 2);
    empty_work_dir(&mounts);
    let output = command(
        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
        &mounts,
        "log-metrics",
        &inputs.join("broken.vhdx"),
        true,
    )
    .arg("-o")
    .arg(temp.path().join("all-invalid.csv"))
    .output()
    .unwrap();
    assert!(!output.status.success());
    empty_work_dir(&mounts);
    assert!(first.is_file());
}

#[test]
fn output_aliases_cannot_overwrite_an_image() {
    let temp = tempfile::tempdir().unwrap();
    let mounts = work_dir(&temp);
    let image = unpack(temp.path(), "logs.vhdx.gz", "logs.vhdx");
    let original = fs::read(&image).unwrap();
    let link = temp.path().join("alias.csv");
    fs::hard_link(&image, &link).unwrap();
    for out in [&image, &link] {
        let output = command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &mounts,
            "log-metrics",
            &image,
            true,
        )
        .args(["-C", "-o"])
        .arg(out)
        .output()
        .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be overwritten"));
        assert_eq!(original, fs::read(&image).unwrap());
    }
    let output = command(
        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
        &mounts,
        "dfir-timeline",
        &image,
        true,
    )
    .args(["-w", "-C", "-r", "test_files/vhdx/events.yml", "-H"])
    .arg(&link)
    .arg("-o")
    .arg(temp.path().join("safe.csv"))
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert_eq!(original, fs::read(&image).unwrap());
    let prefix = temp.path().join("summary");
    fs::hard_link(&image, temp.path().join("summary-successful.csv")).unwrap();
    let output = command(
        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
        &mounts,
        "logon-summary",
        &image,
        true,
    )
    .args(["-C", "-o"])
    .arg(prefix)
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert_eq!(original, fs::read(&image).unwrap());
    empty_work_dir(&mounts);
}

#[test]
fn native_scan_uses_no_mount_helper_or_temporary_extraction() {
    let temp = tempfile::tempdir().unwrap();
    let scratch = work_dir(&temp);
    let image = unpack(temp.path(), "logs.vhdx.gz", "logs.vhdx");
    let original = fs::read(&image).unwrap();
    let out = temp.path().join("native.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &scratch,
            "log-metrics",
            &image,
            true,
        )
        .env("PATH", "")
        .env("FUSERMOUNT_PATH", "this-helper-must-not-be-used")
        .arg("-o")
        .arg(&out),
    );
    assert_eq!(csv::Reader::from_path(out).unwrap().records().count(), 1);
    empty_work_dir(&scratch);
    assert_eq!(original, fs::read(image).unwrap());
}

#[test]
fn native_inputs_work_with_default_channel_filtering() {
    let temp = tempfile::tempdir().unwrap();
    let scratch = work_dir(&temp);
    let image = unpack(temp.path(), "logs.vhdx.gz", "logs.vhdx");
    let baseline = root().join("test_files/vhdx/Security.evtx");
    let mut results = Vec::new();
    for (input, native) in [(&baseline, false), (&image, true)] {
        let out = temp.path().join(format!("filtered-{native}.csv"));
        success(
            command(
                Path::new(env!("CARGO_BIN_EXE_hayabusa")),
                &scratch,
                "dfir-timeline",
                input,
                native,
            )
            .args([
                "-w",
                "-U",
                "-s",
                "-r",
                "test_files/vhdx/events.yml",
                "-p",
                "verbose",
                "-o",
            ])
            .arg(&out),
        );
        let data = normalized(&out, input, native);
        assert!(csv::Reader::from_reader(data.as_bytes()).records().count() > 0);
        results.push(data);
    }
    assert_eq!(results[0], results[1]);
    let out = temp.path().join("security-only.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &scratch,
            "log-metrics",
            &image,
            true,
        )
        .args(["--include-channel", "Security", "-o"])
        .arg(&out),
    );
    assert_eq!(csv::Reader::from_path(out).unwrap().records().count(), 1);
    empty_work_dir(&scratch);
}

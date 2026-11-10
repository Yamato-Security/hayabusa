//! End-to-end tests use public CC0 EVTX data; no private evidence is embedded.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn unpack(dir: &Path, _fixture: &str, _filename: &str) -> PathBuf {
    for name in ["logs.E01", "logs.E02"] {
        fs::copy(root().join("test_files/e01").join(name), dir.join(name)).unwrap();
    }
    dir.join("logs.E01")
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
        cmd.arg("--e01");
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
            for (input, in_image) in [(&baseline, false), (&image, true)] {
                let out = temp
                    .path()
                    .join(format!("{profile}-{format}-{in_image}.{format}"));
                success(
                    command(
                        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
                        &mounts,
                        "dfir-timeline",
                        input,
                        in_image,
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
                let data = normalized(&out, input, in_image);
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
        for (input, in_image) in [(&baseline, false), (&image, true)] {
            let out = temp.path().join(format!("{subcommand}-{in_image}.csv"));
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
            let mut cmd = command(&binary, &mounts, subcommand, input, in_image);
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
                            .starts_with(&format!("{subcommand}-{in_image}.csv"))
                })
                .collect();
            files.sort();
            results.push(
                files
                    .iter()
                    .map(|p| normalized(p, input, in_image))
                    .collect::<Vec<_>>(),
            );
            empty_work_dir(&mounts);
        }
        assert_eq!(results[0], results[1], "{subcommand}");
    }
    // JSON event input inside the image uses the same reader as an extracted JSON file.
    let mut results = Vec::new();
    for (input, in_image) in [
        (&root().join("test_files/evtx/test.json"), false),
        (&image, true),
    ] {
        let out = temp.path().join(format!("json-input-{in_image}.csv"));
        success(
            command(
                Path::new(env!("CARGO_BIN_EXE_hayabusa")),
                &mounts,
                "eid-metrics",
                input,
                in_image,
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
fn recursive_mixed_inputs_stop_at_three_levels_and_preserve_volume_paths() {
    let temp = tempfile::tempdir().unwrap();
    let inputs = temp.path().join("images");
    fs::create_dir_all(inputs.join("a/b/c/d")).unwrap();
    for name in ["logs.E01", "logs.E02"] {
        fs::copy(root().join("test_files/e01").join(name), inputs.join(name)).unwrap();
    }
    fs::copy(
        root().join("test_files/e01/logs.Ex01"),
        inputs.join("a/b/c/upper.EX01"),
    )
    .unwrap();
    fs::write(
        inputs.join("a/b/c/d/ignored.E01"),
        b"unreadable image below depth limit",
    )
    .unwrap();
    let mut vhdx = flate2::read::GzDecoder::new(
        fs::File::open(root().join("test_files/vhdx/logs.vhdx.gz")).unwrap(),
    );
    std::io::copy(
        &mut vhdx,
        &mut fs::File::create(inputs.join("also.vhdx")).unwrap(),
    )
    .unwrap();
    let work = work_dir(&temp);
    for (mixed, count) in [(false, 2), (true, 3)] {
        let out = temp.path().join(format!("mixed-{mixed}.csv"));
        let mut cmd = command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &work,
            "log-metrics",
            &inputs,
            true,
        );
        if mixed {
            cmd.arg("--vhdx");
        }
        let result = success(cmd.arg("-o").arg(&out));
        assert_eq!(
            csv::Reader::from_path(&out).unwrap().records().count(),
            count,
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        let rows = fs::read_to_string(out).unwrap();
        assert!(!rows.contains("ignored.E01"));
        assert!(!rows.contains("logs.E02!/"));
    }
    let image = temp.path().join("two-volumes.Ex01");
    fs::copy(root().join("test_files/e01/two-volumes.Ex01"), &image).unwrap();
    let out = temp.path().join("volumes.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &work,
            "search",
            &image,
            true,
        )
        .args(["-r", ".*", "-o"])
        .arg(&out),
    );
    let text = fs::read_to_string(out).unwrap();
    assert!(text.contains("two-volumes.Ex01!/Volume1/Security.evtx"));
    assert!(text.contains("two-volumes.Ex01!/Volume2/Security.evtx"));
}

#[test]
fn segment_outputs_are_protected_even_when_the_segment_is_damaged_or_hard_linked() {
    let temp = tempfile::tempdir().unwrap();
    let image = unpack(temp.path(), "unused", "unused");
    let second = temp.path().join("logs.E02");
    fs::write(&second, b"damaged source segment").unwrap();
    let alias = temp.path().join("output.csv");
    fs::hard_link(&second, &alias).unwrap();
    let before = fs::read(&second).unwrap();
    let work = work_dir(&temp);
    for out in [&second, &alias] {
        let result = command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &work,
            "dfir-timeline",
            &image,
            true,
        )
        .args(["-w", "-C", "-r", "test_files/vhdx/events.yml", "-o"])
        .arg(out)
        .output()
        .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be overwritten"));
        assert_eq!(fs::read(&second).unwrap(), before);
    }
}

#[test]
fn incomplete_images_keep_csv_and_html_results_with_a_nonzero_status() {
    let temp = tempfile::tempdir().unwrap();
    let image = unpack(temp.path(), "unused", "unused");
    fs::OpenOptions::new()
        .write(true)
        .open(temp.path().join("logs.E02"))
        .unwrap()
        .set_len(400_000)
        .unwrap();
    let work = work_dir(&temp);
    let out = temp.path().join("timeline.csv");
    let report = temp.path().join("report.html");
    let result = command(
        Path::new(env!("CARGO_BIN_EXE_hayabusa")),
        &work,
        "dfir-timeline",
        &image,
        true,
    )
    .args([
        "-w",
        "-p",
        "verbose",
        "-r",
        "test_files/vhdx/events.yml",
        "-o",
    ])
    .arg(&out)
    .arg("-H")
    .arg(&report)
    .output()
    .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(fs::read_to_string(&out).unwrap().contains("Security.evtx"));
    assert!(
        fs::read_to_string(&report)
            .unwrap()
            .contains("Incomplete E01/Ex01 input")
    );
}

#[test]
fn e01_scanning_does_not_require_a_working_temporary_directory() {
    let temp = tempfile::tempdir().unwrap();
    let image = unpack(temp.path(), "unused", "unused");
    let unusable = temp.path().join("not-a-directory");
    fs::write(&unusable, b"cannot extract here").unwrap();
    let out = temp.path().join("metrics.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &unusable,
            "eid-metrics",
            &image,
            true,
        )
        .arg("-o")
        .arg(&out),
    );
    assert!(!fs::read_to_string(out).unwrap().is_empty());
    assert_eq!(fs::read(unusable).unwrap(), b"cannot extract here");
}

#[test]
fn case_aliases_of_the_first_segment_keep_the_original_family() {
    let temp = tempfile::tempdir().unwrap();
    unpack(temp.path(), "unused", "unused");
    let alias = temp.path().join("logs.e01");
    if !alias.is_file() {
        return;
    } // Exercise case-insensitive filesystems on macOS and Windows.
    let work = work_dir(&temp);
    let out = temp.path().join("metrics.csv");
    success(
        command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &work,
            "log-metrics",
            &alias,
            true,
        )
        .arg("-o")
        .arg(&out),
    );
    assert_eq!(csv::Reader::from_path(out).unwrap().records().count(), 1);
}

#[test]
fn logical_and_spoofed_inputs_are_rejected_without_creating_reports() {
    let temp = tempfile::tempdir().unwrap();
    let work = work_dir(&temp);
    for (name, signature) in [
        ("logical.E01", b"LVF\x09\x0d\x0a\xff\x00"),
        ("wrong.E01", b"vhdxfile"),
    ] {
        let image = temp.path().join(name);
        fs::write(&image, signature).unwrap();
        let out = temp.path().join(format!("{name}.csv"));
        let result = command(
            Path::new(env!("CARGO_BIN_EXE_hayabusa")),
            &work,
            "dfir-timeline",
            &image,
            true,
        )
        .args(["-w", "-r", "test_files/vhdx/events.yml", "-o"])
        .arg(&out)
        .output()
        .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let messages = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            messages.contains(if name.starts_with("logical") {
                "Logical L01/Lx01"
            } else {
                "Expected a physical E01/Ex01"
            }),
            "{messages}"
        );
        assert!(!out.exists());
    }
}

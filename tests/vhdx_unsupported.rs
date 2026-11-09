#![cfg(not(target_os = "linux"))]

#[test]
fn unsupported_platform_explains_read_only_mount_alternative() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hayabusa"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["log-metrics", "--vhdx", "-f", "example.vhdx", "-q", "-K"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("requires Linux and /dev/fuse"), "{error}");
    assert!(error.contains("Mount-DiskImage"), "{error}");
}

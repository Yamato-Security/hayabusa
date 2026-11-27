use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Give the CLI its own package directory without opening the executable for writing.
/// Copying a binary immediately before launching it can produce ETXTBSY in parallel tests.
pub fn isolated_package() -> (TempDir, PathBuf) {
    let source = Path::new(env!("CARGO_BIN_EXE_hayabusa"));
    // Keep the link on the same filesystem even when TMPDIR is on another volume.
    let temp = tempfile::tempdir_in(source.parent().unwrap()).unwrap();
    let package = temp.path().join("package");
    fs::create_dir_all(package.join("config")).unwrap();
    let binary = package.join(source.file_name().unwrap());
    fs::hard_link(source, &binary).unwrap();
    (temp, binary)
}

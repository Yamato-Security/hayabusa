use hayabusa::vhdx::Catalog;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[test]
fn native_catalogue_readers_preserve_source_names_sizes_and_lifetime() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image with spaces.vhdx");
    let file = fs::File::open(root.join("test_files/vhdx/logs.vhdx.gz")).unwrap();
    std::io::copy(
        &mut flate2::read::GzDecoder::new(file),
        &mut fs::File::create(&image).unwrap(),
    )
    .unwrap();
    let original = fs::read(&image).unwrap();
    let inputs = Catalog::collect(
        std::slice::from_ref(&image),
        &hashbrown::HashSet::from(["evtx".to_string()]),
    );
    assert!(inputs.problems.is_empty(), "{:?}", inputs.problems);
    assert_eq!(inputs.image_count, 1);
    let paths = inputs.paths();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0],
        std::path::PathBuf::from(format!("{}!/Security.evtx", image.display()))
    );
    let expected = fs::read(root.join("test_files/vhdx/Security.evtx")).unwrap();
    assert_eq!(inputs.size(&paths[0]), Some(expected.len() as u64));
    let mut reader = inputs.open(&paths[0]).unwrap();
    drop(inputs);
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut signature = [0; 8];
    reader.read_exact(&mut signature).unwrap();
    assert_eq!(&signature, b"ElfFile\0");
    assert_eq!(original, fs::read(image).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_image_names_cannot_merge_distinct_evidence_sources() {
    use std::os::unix::ffi::OsStringExt;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir().unwrap();
    let fixture = fs::File::open(root.join("test_files/vhdx/logs.vhdx.gz")).unwrap();
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(fixture)
        .read_to_end(&mut bytes)
        .unwrap();
    let first = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"image-\xff.vhdx".to_vec()));
    let second = temp
        .path()
        .join(std::ffi::OsString::from_vec(b"image-\xfe.vhdx".to_vec()));
    assert_eq!(first.display().to_string(), second.display().to_string());
    fs::write(&first, &bytes).unwrap();
    fs::write(&second, &bytes).unwrap();
    let inputs = Catalog::collect(
        &[first, second],
        &hashbrown::HashSet::from(["evtx".to_string()]),
    );
    assert!(inputs.paths().is_empty());
    assert_eq!(inputs.problems.len(), 2);
    assert!(
        inputs
            .problems
            .iter()
            .all(|p| p.contains("not valid UTF-8"))
    );
}

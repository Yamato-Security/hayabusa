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

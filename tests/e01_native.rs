//! Native readers are compared with the same public EVTX stored outside images.
use hayabusa::vhdx::Catalog;
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

fn fixtures(destination: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/e01");
    for name in ["logs.E01", "logs.E02", "logs.Ex01", "two-volumes.Ex01"] {
        fs::copy(source.join(name), destination.join(name)).unwrap();
    }
}

#[test]
fn ewf1_ewf2_and_partitioned_images_provide_seekable_unchanged_evtx() {
    let temp = tempfile::tempdir().unwrap();
    fixtures(temp.path());
    let expected =
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/Security.evtx"))
            .unwrap();
    for (name, count) in [("logs.E01", 1), ("logs.Ex01", 1), ("two-volumes.Ex01", 2)] {
        let image = temp.path().join(name);
        let before: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect();
        let catalog = Catalog::collect(&[image], &hashbrown::HashSet::from(["evtx".into()]));
        assert!(catalog.problems.is_empty(), "{:?}", catalog.problems);
        let paths = catalog.paths();
        assert_eq!(paths.len(), count);
        for path in paths {
            assert!(path.to_string_lossy().contains(name));
            assert_eq!(catalog.size(&path), Some(expected.len() as u64));
            let mut reader = catalog.open(&path).unwrap();
            reader.seek(SeekFrom::Start(37)).unwrap();
            let mut part = [0; 73];
            reader.read_exact(&mut part).unwrap();
            assert_eq!(&part, &expected[37..110]);
            reader.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, expected);
        }
        assert!(catalog.late_problems().is_empty());
        for (path, bytes) in before {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

#[test]
fn failures_discovered_during_reads_are_not_lost() {
    let temp = tempfile::tempdir().unwrap();
    fixtures(temp.path());
    let image = temp.path().join("logs.Ex01");
    let catalog = Catalog::collect(
        std::slice::from_ref(&image),
        &hashbrown::HashSet::from(["evtx".into()]),
    );
    assert!(catalog.problems.is_empty());
    let paths = catalog.paths();
    assert_eq!(paths.len(), 1);
    let mut reader = catalog.open(&paths[0]).unwrap();
    // A private fixture copy becomes unavailable after discovery, before its data is read.
    fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(reader.read_to_end(&mut Vec::new()).is_err());
    assert!(!catalog.late_problems().is_empty());
}

#[test]
fn incomplete_tail_retains_logs_but_reports_acquisition_damage() {
    let temp = tempfile::tempdir().unwrap();
    fixtures(temp.path());
    fs::OpenOptions::new()
        .write(true)
        .open(temp.path().join("logs.E02"))
        .unwrap()
        .set_len(400_000)
        .unwrap();
    let catalog = Catalog::collect(
        &[temp.path().join("logs.E01")],
        &hashbrown::HashSet::from(["evtx".into()]),
    );
    assert!(!catalog.problems.is_empty());
    let paths = catalog.paths();
    assert_eq!(paths.len(), 1, "{:?}", catalog.problems);
    let mut actual = Vec::new();
    catalog
        .open(&paths[0])
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(
        actual,
        fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_files/vhdx/Security.evtx"))
            .unwrap()
    );
}

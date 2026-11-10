//! Read-only EWF container adapter for the shared native NTFS reader.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use ys_vhdx_mount::image::Image;

pub(crate) struct Opened {
    pub image: Image,
    pub status: ewf_image::Image,
}

pub(crate) fn is_first_segment(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("e01") || ext.eq_ignore_ascii_case("ex01"))
}

/// Resolve case aliases without canonicalizing a symlink into another segment family.
fn selected_name(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("Missing image filename"))?;
    let entries = fs::read_dir(parent)?.collect::<io::Result<Vec<_>>>()?;
    if let Some(entry) = entries.iter().find(|entry| entry.file_name() == name) {
        return Ok(entry.path());
    }
    let mut aliases = Vec::new();
    for entry in entries {
        if entry.path().is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case(path.extension().unwrap_or_default()))
            && same_file::is_same_file(path, entry.path())?
        {
            aliases.push(entry.path());
        }
    }
    match aliases.as_slice() {
        [alias] => Ok(alias.clone()),
        [] => Err(io::Error::other(
            "The first E01/Ex01 segment does not exist",
        )),
        _ => Err(io::Error::other(
            "Ambiguous first segment; use its exact filename",
        )),
    }
}

/// Same first-segment bytes may be linked into different companion families.
pub(crate) fn family_path(path: &Path) -> io::Result<PathBuf> {
    let selected = selected_name(path)?;
    Ok(selected
        .parent()
        .unwrap_or(Path::new("."))
        .canonicalize()?
        .join(selected.file_name().unwrap()))
}

fn segment_suffix(extension: &str, ewf2: bool) -> bool {
    let extension = extension.as_bytes();
    let pair = |bytes: &[u8]| {
        bytes.iter().all(u8::is_ascii_digit) || bytes.iter().all(u8::is_ascii_alphabetic)
    };
    if ewf2 {
        extension.len() == 4
            && extension[0].eq_ignore_ascii_case(&b'e')
            && match extension[1].to_ascii_lowercase() {
                b'x' => pair(&extension[2..]),
                b'y' | b'z' => extension[2..].iter().all(u8::is_ascii_alphabetic),
                _ => false,
            }
    } else {
        extension.len() == 3
            && match extension[0].to_ascii_lowercase() {
                b'e' => pair(&extension[1..]),
                b'f'..=b'z' => extension[1..].iter().all(u8::is_ascii_alphabetic),
                _ => false,
            }
    }
}

/// Protect even malformed companions: decoding failure does not make a source writable.
pub(crate) fn source_paths(path: &Path) -> io::Result<Vec<PathBuf>> {
    if !is_first_segment(path) {
        return Ok(vec![path.to_path_buf()]);
    }
    let first = selected_name(path)?;
    let parent = first.parent().unwrap_or(Path::new("."));
    let ewf2 = first
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ex01"));
    let mut paths = vec![first.clone()];
    for entry in fs::read_dir(parent)? {
        let candidate = entry?.path();
        if candidate.is_file()
            && candidate.file_stem() == first.file_stem()
            && candidate
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| segment_suffix(ext, ewf2))
        {
            paths.push(candidate);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(crate) fn open(path: &Path) -> io::Result<Opened> {
    let selected = selected_name(path)?;
    let mut signature = [0; 8];
    fs::File::open(&selected)?.read_exact(&mut signature)?;
    if &signature == b"LVF\x09\x0d\x0a\xff\x00" || &signature == b"LEF2\x0d\x0a\x81\x00" {
        return Err(io::Error::other(
            "Logical L01/Lx01 images are not supported; provide a physical E01/Ex01 image",
        ));
    }
    if &signature != b"EVF\x09\x0d\x0a\xff\x00" && &signature != b"EVF2\x0d\x0a\x81\x00" {
        return Err(io::Error::other(
            "Expected a physical E01/Ex01 image signature",
        ));
    }
    // Default lenient mode reports recoverable structural damage. A failed
    // chunk read remains an error; zero-substitution is deliberately disabled.
    let options = ewf_image::OpenOptions::default().with_chunk_cache_size_bytes(8 * 1024 * 1024);
    let status = ewf_image::Image::open_with_options(selected, options)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    if status.info().single_files.is_some() {
        return Err(io::Error::other(
            "Logical L01/Lx01 images are not supported; provide a physical E01/Ex01 image",
        ));
    }
    let image = Image::from_disk(
        Box::new(status.cursor()),
        status.media_size(),
        status.bytes_per_sector().unwrap_or(512),
    )?;
    Ok(Opened { image, status })
}

pub(crate) fn warnings(image: &ewf_image::Image) -> Vec<String> {
    let mut warnings = Vec::new();
    let info = image.info();
    if !info.acquisition_complete {
        warnings.push("EWF acquisition did not finish".to_string());
    }
    let unreadable = info.acquisition_errors.iter().fold(0u64, |total, range| {
        total.saturating_add(range.sector_count)
    });
    if unreadable > 0 {
        warnings.push(format!(
            "EWF acquisition contains {unreadable} unreadable sectors recorded as zeros"
        ));
    }
    warnings.extend(
        image
            .lenient_findings()
            .into_iter()
            .map(|finding| finding.message),
    );
    warnings.sort();
    warnings.dedup();
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_segment_names_and_companions() {
        for name in ["a.E01", "a.e01", "a.Ex01", "a.EX01"] {
            assert!(is_first_segment(Path::new(name)));
        }
        for name in ["a.E02", "a.Ex02", "a.L01", "a.E01.old"] {
            assert!(!is_first_segment(Path::new(name)));
        }
        let temp = tempfile::tempdir().unwrap();
        for name in [
            "case.E01",
            "case.E02",
            "case.EAA",
            "case.FAA",
            "case.Ex01",
            "case.csv",
            "other.E02",
        ] {
            fs::write(
                temp.path().join(name),
                b"malformed source still needs protection",
            )
            .unwrap();
        }
        let paths = source_paths(&temp.path().join("case.E01")).unwrap();
        assert_eq!(paths.len(), 4);
        assert!(!paths.contains(&temp.path().join("case.Ex01")));
        let paths = source_paths(&temp.path().join("case.Ex01")).unwrap();
        assert_eq!(paths.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn source_symlinks_do_not_select_another_family() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["real.E01", "real.E02", "alias.E02"] {
            fs::write(temp.path().join(name), b"source").unwrap();
        }
        std::os::unix::fs::symlink("real.E01", temp.path().join("alias.E01")).unwrap();
        let paths = source_paths(&temp.path().join("alias.E01")).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&temp.path().join("alias.E02")));
        assert!(!paths.contains(&temp.path().join("real.E02")));
        assert_ne!(
            family_path(&temp.path().join("real.E01")).unwrap(),
            family_path(&temp.path().join("alias.E01")).unwrap()
        );
    }
}

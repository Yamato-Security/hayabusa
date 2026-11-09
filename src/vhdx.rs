//! Read-only image inputs shared by the event-log scanning commands.

use crate::detections::configs::InputOption;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use ys_vhdx_mount::image::{Image, ROOT_RECORD};

/// Root-level images and images in at most three nested directories are considered.
pub const IMAGE_SEARCH_DEPTH: usize = 3;

fn is_image(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("vhdx"))
}

/// Discover only images, without following directory symlinks or repeating overlapping inputs.
pub fn discover(input: &InputOption) -> io::Result<Vec<PathBuf>> {
    fn visit(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) -> io::Result<()> {
        let mut entries = fs::read_dir(dir)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() && depth < IMAGE_SEARCH_DEPTH {
                visit(&path, depth + 1, files)?;
            } else if (kind.is_file() || (kind.is_symlink() && path.is_file())) && is_image(&path) {
                files.push(path);
            }
        }
        Ok(())
    }
    if input.live_analysis {
        return Err(io::Error::other(
            "--vhdx cannot be combined with --live-analysis",
        ));
    }
    let mut files = Vec::new();
    if let Some(path) = &input.filepath {
        if !path.is_file() || !is_image(path) {
            return Err(io::Error::other(format!(
                "Not a VHDX file: {}",
                path.display()
            )));
        }
        files.push(path.clone());
    } else if let Some(dirs) = &input.directory {
        for dir in dirs {
            visit(dir, 0, &mut files)?;
        }
    } else {
        return Err(io::Error::other("--vhdx requires -f <FILE> or -d <DIR>"));
    }
    files.sort();
    let mut unique = HashSet::new();
    let mut result = Vec::new();
    for path in files {
        if unique.insert(path.canonicalize()?) {
            result.push(path);
        }
    }
    if result.is_empty() {
        return Err(io::Error::other(
            "No .vhdx images found within three subdirectory levels",
        ));
    }
    Ok(result)
}

/// An output must never truncate an input image, even through a symbolic or hard link.
pub fn protect_outputs(images: &[PathBuf], outputs: &[PathBuf]) -> io::Result<()> {
    for output in outputs {
        match fs::metadata(output) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        for image in images {
            let same = same_file::is_same_file(output, image)?;
            if same {
                return Err(io::Error::other(format!(
                    "Output {} is also a VHDX input and cannot be overwritten",
                    output.display()
                )));
            }
        }
    }
    Ok(())
}

/// Include generated output filenames as well as the user's base path.
pub fn output_paths(stored: &crate::detections::configs::StoredStatic) -> Vec<PathBuf> {
    use crate::detections::configs::{Action, CURRENT_EXE_PATH};
    let mut paths: Vec<_> = stored.output_path.iter().cloned().collect();
    if let Some(options) = &stored.output_option {
        paths.extend(options.html_report.iter().cloned());
    }
    if let Some(base) = &stored.output_path {
        match stored.config.action.as_ref() {
            Some(Action::LogonSummary(_)) => {
                for suffix in ["-successful.csv", "-failed.csv"] {
                    let mut path = base.as_os_str().to_os_string();
                    path.push(suffix);
                    paths.push(path.into());
                }
            }
            Some(Action::PivotKeywordsList(_)) => {
                for category in stored.pivot_keyword.read().unwrap().keys() {
                    paths.push(PathBuf::from(format!("{}-{category}.txt", base.display())));
                }
            }
            _ => {}
        }
    }
    if matches!(stored.config.action, Some(Action::ConfigCriticalSystems(_))) {
        paths.push(CURRENT_EXE_PATH.join("config/critical_systems.txt"));
    }
    paths
}

/// Read-only native inputs, indexed by a stable `image.vhdx!/path` evidence name.
/// Cloning a scan snapshot shares this table and the images; it never copies log contents.
#[derive(Clone, Default)]
pub struct Catalog {
    files: Arc<std::collections::HashMap<PathBuf, NativeFile>>,
    pub problems: Arc<Vec<String>>,
    pub image_count: usize,
}

#[derive(Clone)]
struct NativeFile {
    image: Arc<Image>,
    volume: usize,
    record: u64,
    size: u64,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalog")
            .field("images", &self.image_count)
            .field("files", &self.files.len())
            .finish()
    }
}

impl Catalog {
    pub fn collect(images: &[PathBuf], extensions: &hashbrown::HashSet<String>) -> Self {
        let mut files = std::collections::HashMap::new();
        let mut problems = Vec::new();
        let mut image_count = 0;
        for path in images {
            let image = match Image::open(path) {
                Ok(image) => Arc::new(image),
                Err(e) => {
                    problems.push(format!("Could not open {}: {e}", path.display()));
                    continue;
                }
            };
            image_count += 1;
            problems.extend(
                image
                    .problems
                    .iter()
                    .map(|e| format!("{}: {e}", path.display())),
            );
            for (volume, selected) in image.volumes.iter().enumerate() {
                let root = if image.volumes.len() == 1 {
                    String::new()
                } else {
                    format!("Volume{}/", volume + 1)
                };
                let mut pending = vec![(ROOT_RECORD, root)];
                let mut visited = HashSet::new();
                while let Some((record, directory)) = pending.pop() {
                    if !visited.insert(record) {
                        continue;
                    }
                    let entries = match selected.list(record) {
                        Ok(entries) => entries,
                        Err(e) => {
                            problems.push(format!("{}!/{directory}: {e}", path.display()));
                            continue;
                        }
                    };
                    for entry in entries.iter() {
                        let relative = format!("{directory}{}", entry.name);
                        if entry.directory {
                            pending.push((entry.record, format!("{relative}/")));
                        } else if !entry.name.starts_with('.')
                            && Path::new(&entry.name)
                                .extension()
                                .and_then(|x| x.to_str())
                                .is_some_and(|x| extensions.contains(&x.to_ascii_lowercase()))
                        {
                            let logical = PathBuf::from(format!("{}!/{relative}", path.display()));
                            match selected.stat(entry.record) {
                                Ok(stat) => {
                                    files.insert(
                                        logical,
                                        NativeFile {
                                            image: image.clone(),
                                            volume,
                                            record: entry.record,
                                            size: stat.size,
                                        },
                                    );
                                }
                                Err(e) => problems.push(format!("{}: {e}", logical.display())),
                            }
                        }
                    }
                }
            }
        }
        Self {
            files: Arc::new(files),
            problems: Arc::new(problems),
            image_count,
        }
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = self.files.keys().cloned().collect();
        paths.sort();
        paths
    }

    pub fn size(&self, path: &Path) -> Option<u64> {
        self.files.get(path).map(|f| f.size)
    }

    pub fn open(&self, path: &Path) -> io::Result<InputReader> {
        if let Some(file) = self.files.get(path) {
            file.image
                .file_reader(file.volume, file.record)
                .map(InputReader::Image)
        } else {
            fs::File::open(path.canonicalize()?).map(InputReader::File)
        }
    }
}

pub enum InputReader {
    File(fs::File),
    Image(ys_vhdx_mount::image::FileReader),
}
impl Read for InputReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buffer),
            Self::Image(f) => f.read(buffer),
        }
    }
}
impl Seek for InputReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(to),
            Self::Image(f) => f.seek(to),
        }
    }
}

pub fn parser(path: &Path, inputs: &Catalog) -> Result<evtx::EvtxParser<InputReader>, String> {
    let reader = inputs.open(path).map_err(|e| e.to_string())?;
    evtx::EvtxParser::from_read_seek(reader).map_err(|e| e.to_string())
}

pub fn file_size(path: &Path, stored: &crate::detections::configs::StoredStatic) -> u64 {
    stored.vhdx_files.size(path).unwrap_or_else(|| {
        crate::detections::utils::get_file_size(
            path,
            stored.verbose_flag,
            stored.quiet_errors_flag,
            &stored.error_log_stack,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_depth_case_order_and_overlapping_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("a/b/c/d")).unwrap();
        for path in [
            "z.vhdx",
            "a/b/c/at-limit.VHDX",
            "a/b/c/d/too-deep.vhdx",
            "ordinary.evtx",
        ] {
            fs::write(root.join(path), b"fixture").unwrap();
        }
        let input = InputOption {
            directory: Some(vec![root.into(), root.join("a")]),
            ..Default::default()
        };
        // Each supplied directory has its own depth limit; the overlapping inputs are deduplicated.
        let found = discover(&input).unwrap();
        assert_eq!(found.len(), 3);
        let input = InputOption {
            directory: Some(vec![root.into()]),
            ..Default::default()
        };
        assert_eq!(
            discover(&input).unwrap(),
            vec![root.join("a/b/c/at-limit.VHDX"), root.join("z.vhdx")]
        );
    }

    #[test]
    fn single_image_and_invalid_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("image.VHDX");
        fs::write(&path, b"fixture").unwrap();
        let mut input = InputOption {
            filepath: Some(path.clone()),
            ..Default::default()
        };
        assert_eq!(discover(&input).unwrap(), vec![path]);
        input.filepath = Some(temp.path().join("missing.vhdx"));
        assert!(discover(&input).is_err());
        input.filepath = None;
        input.directory = Some(vec![temp.path().join("missing")]);
        assert!(discover(&input).is_err());
        assert!(discover(&InputOption::default()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_symlinks_do_not_escape_the_depth_limit_or_loop() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("sub")).unwrap();
        fs::write(temp.path().join("image.vhdx"), b"fixture").unwrap();
        symlink(temp.path(), temp.path().join("sub/loop")).unwrap();
        let input = InputOption {
            directory: Some(vec![temp.path().into()]),
            ..Default::default()
        };
        assert_eq!(discover(&input).unwrap().len(), 1);
    }

    #[test]
    fn outputs_cannot_overwrite_images_or_their_hard_links() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("input.vhdx");
        fs::write(&image, b"source image").unwrap();
        assert!(
            protect_outputs(std::slice::from_ref(&image), std::slice::from_ref(&image)).is_err()
        );
        let alias = temp.path().join("output.csv");
        fs::hard_link(&image, &alias).unwrap();
        assert!(protect_outputs(std::slice::from_ref(&image), &[alias]).is_err());
        assert!(protect_outputs(&[image], &[temp.path().join("new.csv")]).is_ok());
    }
}

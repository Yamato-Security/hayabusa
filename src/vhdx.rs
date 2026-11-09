//! Read-only image inputs shared by the event-log scanning commands.

use crate::detections::configs::InputOption;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Root-level images and images in at most three nested directories are considered.
pub const IMAGE_SEARCH_DEPTH: usize = 3;

pub const UNSUPPORTED: &str = "Automatic VHDX mounting requires Linux and /dev/fuse, as in Juntei. On Windows, attach the image read-only with Mount-DiskImage -ImagePath <IMAGE> -Access ReadOnly, then scan the mounted log directory with -d.";

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

/// A mounted image and its stable evidence name. Outputs use `image.vhdx!/path/in/volume`;
/// the temporary mount directory is only used to read the files during the scan.
#[derive(Debug, Clone)]
pub struct Source {
    pub root: PathBuf,
    pub image: PathBuf,
}

pub fn display_path(path: &Path, sources: &[Source]) -> PathBuf {
    for source in sources {
        if let Ok(inner) = path.strip_prefix(&source.root) {
            return PathBuf::from(format!("{}!/{}", source.image.display(), inner.display()));
        }
    }
    path.to_path_buf()
}

pub fn read_path(path: &Path, sources: &[Source]) -> PathBuf {
    // Match the longest image name first, including unusual directory names containing `!`.
    let mut ordered: Vec<_> = sources.iter().collect();
    ordered.sort_by_key(|source| std::cmp::Reverse(source.image.as_os_str().len()));
    for source in ordered {
        let prefix = format!("{}!/", source.image.display());
        if let Some(inner) = path.to_str().and_then(|s| s.strip_prefix(&prefix)) {
            return source.root.join(inner);
        }
    }
    path.to_path_buf()
}

/// An output must never truncate an input image, even through a symbolic or hard link.
pub fn protect_outputs(images: &[PathBuf], outputs: &[PathBuf]) -> io::Result<()> {
    for output in outputs {
        let meta = match fs::metadata(output) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for image in images {
            let same = output.canonicalize()? == image.canonicalize()?;
            #[cfg(unix)]
            let same = {
                use std::os::unix::fs::MetadataExt;
                let input = fs::metadata(image)?;
                same || (meta.dev(), meta.ino()) == (input.dev(), input.ino())
            };
            #[cfg(not(unix))]
            let _ = &meta;
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

#[cfg(unix)]
type DirectoryKey = (u64, u64);
#[cfg(not(unix))]
type DirectoryKey = PathBuf;

fn directory_key(path: &Path) -> io::Result<DirectoryKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)?;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    path.canonicalize()
}

/// Search every mounted volume, without an image-discovery depth limit. Inode tracking also
/// prevents a malformed NTFS directory graph from recursing forever.
pub fn collect_logs(
    roots: &[PathBuf],
    extensions: &hashbrown::HashSet<String>,
) -> io::Result<Vec<PathBuf>> {
    let mut pending = roots.to_vec();
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        if !seen.insert(directory_key(&dir)?) {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| extensions.contains(&e.to_ascii_lowercase()))
                && !path
                    .file_stem()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Mounts live for the whole scan, including output generation. Cleanup only removes empty
/// directories; it never recursively deletes through a mount that could not be closed.
#[cfg(target_os = "linux")]
pub struct MountedImages {
    base: PathBuf,
    mounts: Vec<vhdx_mount::image_mount::Mounted>,
    pub sources: Vec<Source>,
    pub problems: Vec<String>,
}

#[cfg(target_os = "linux")]
impl MountedImages {
    /// One group per command invocation; installs a process-wide interrupt handler.
    pub fn open(images: &[PathBuf]) -> io::Result<Self> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use vhdx_mount::image_mount;

        // Keep ownership explicitly: TempDir's recursive Drop would be unsafe if unmounting
        // failed. The SDK's cleanup removes empty mount points only.
        let base = tempfile::Builder::new()
            .prefix("hayabusa-vhdx-")
            .tempdir()?
            .keep();
        let mut group = Self {
            base,
            mounts: Vec::new(),
            sources: Vec::new(),
            problems: Vec::new(),
        };
        let unmounters = Arc::new(Mutex::new(Vec::new()));
        let mount_points = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let mount_gate = Arc::new(Mutex::new(()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let (stop, gate, mounts, base) = (
            cancelled.clone(),
            mount_gate.clone(),
            mount_points.clone(),
            group.base.clone(),
        );
        ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
            // Finish registering an in-progress mount before cancellation walks the list.
            // Keep the gate until exit, preventing any later image from being attached.
            let _gate = gate.lock().unwrap_or_else(|e| e.into_inner());
            let mounts = mounts.lock().unwrap_or_else(|e| e.into_inner());
            // The SDK registers SessionUnmounter before Session::spawn, but fuser moves
            // mount ownership into BackgroundSession on spawn. Those callbacks can then
            // be empty. Unmount our registered paths with the runtime helper instead.
            for point in mounts.iter().rev() {
                let result = std::process::Command::new("fusermount3")
                    // Detach even when scan workers still have an event log open.
                    .args(["-u", "-z", "--"])
                    .arg(point)
                    .status();
                if !result.is_ok_and(|status| status.success()) {
                    eprintln!("Could not unmount {} after interruption", point.display());
                }
            }
            image_mount::remove_mount_points(&base);
            std::process::exit(130);
        })
        .map_err(io::Error::other)?;
        for (index, image) in images.iter().enumerate() {
            let _gate = mount_gate.lock().unwrap_or_else(|e| e.into_inner());
            if cancelled.load(Ordering::SeqCst) {
                // Let the handler own cancellation. Joining background sessions here
                // could wait for open log handles while also blocking the handler's gate.
                drop(_gate);
                loop {
                    std::thread::park();
                }
            }
            if image.to_str().is_none() {
                group.problems.push(format!(
                    "The image path is not valid UTF-8: {}",
                    image.display()
                ));
                continue;
            }
            let point = group.base.join(format!("image-{index}"));
            let mounted = fs::create_dir(&point)
                .and_then(|()| image_mount::mount(image, &point, &unmounters));
            match mounted {
                Ok(mounted) => {
                    mount_points
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(point.clone());
                    group.problems.extend(
                        mounted
                            .problems
                            .iter()
                            .map(|e| format!("{}: {e}", image.display())),
                    );
                    group.sources.push(Source {
                        root: point,
                        image: image.clone(),
                    });
                    group.mounts.push(mounted);
                }
                Err(e) => group
                    .problems
                    .push(format!("Could not mount {}: {e}", image.display())),
            }
        }
        if group.sources.is_empty() {
            return Err(io::Error::other(group.problems.join("\n")));
        }
        Ok(group)
    }

    pub fn roots(&self) -> Vec<PathBuf> {
        self.sources
            .iter()
            .map(|source| source.root.clone())
            .collect()
    }

    fn cleanup(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for mounted in self.mounts.drain(..) {
            let point = mounted.mount_point.clone();
            if let Err(e) = mounted.unmount() {
                errors.push(format!("Could not unmount {}: {e}", point.display()));
            }
        }
        vhdx_mount::image_mount::remove_mount_points(&self.base);
        errors
    }

    pub fn close(mut self) -> Vec<String> {
        self.cleanup()
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountedImages {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
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
    fn source_paths_survive_unmount_and_keep_volume_names() {
        let sources = vec![Source {
            root: PathBuf::from("mounted/0"),
            image: PathBuf::from("evidence/host.vhdx"),
        }];
        let path = PathBuf::from("mounted/0/Volume2/Windows/System.evtx");
        let shown = display_path(&path, &sources);
        assert_eq!(
            shown,
            PathBuf::from("evidence/host.vhdx!/Volume2/Windows/System.evtx")
        );
        assert_eq!(read_path(&shown, &sources), path);
        let ordinary = PathBuf::from("ordinary.evtx");
        assert_eq!(display_path(&ordinary, &sources), ordinary);
    }

    #[test]
    fn logs_inside_an_image_are_not_limited_to_three_directories() {
        let temp = tempfile::tempdir().unwrap();
        let logs = temp.path().join("Volume1/C/Windows/System32/winevt/Logs");
        fs::create_dir_all(&logs).unwrap();
        for name in ["Security.EVTX", ".hidden.evtx", "notes.txt"] {
            fs::write(logs.join(name), b"fixture").unwrap();
        }
        let extensions = hashbrown::HashSet::from(["evtx".to_string()]);
        assert_eq!(
            collect_logs(&[temp.path().into()], &extensions).unwrap(),
            vec![logs.join("Security.EVTX")]
        );
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
        #[cfg(unix)]
        assert!(protect_outputs(std::slice::from_ref(&image), &[alias]).is_err());
        assert!(protect_outputs(&[image], &[temp.path().join("new.csv")]).is_ok());
    }
}

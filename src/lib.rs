use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use xxhash_rust::xxh3::Xxh3;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

pub mod monitor;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: i64,
    pub message: String,
}

pub const DEFAULT_CRITICAL_DIRS: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
    "/root",
];

pub fn get_critical_dirs_in_scope(scan_root: &Path, critical_dirs: &[String]) -> Vec<PathBuf> {
    critical_dirs
        .iter()
        .filter_map(|dir| {
            let dir_path = PathBuf::from(dir);
            if dir_path.starts_with(scan_root) {
                Some(dir_path)
            } else {
                None
            }
        })
        .collect()
}

// Helper function to get extended attributes
#[cfg(unix)]
pub fn get_xattrs(path: &Path) -> HashMap<String, Vec<u8>> {
    let mut attrs = HashMap::new();

    if let Ok(list) = xattr::list(path) {
        for name in list {
            if let Ok(value) = xattr::get(path, &name) {
                if let Some(data) = value {
                    attrs.insert(name.to_string_lossy().to_string(), data);
                }
            }
        }
    }

    attrs
}

// Helper function to get Linux file flags via ioctl
#[cfg(target_os = "linux")]
pub fn get_linux_flags(path: &Path) -> u32 {
    use std::fs::File;

    // FS_IOC_GETFLAGS constant
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;

    if let Ok(file) = File::open(path) {
        let fd = file.as_raw_fd();
        let mut flags: libc::c_long = 0;

        unsafe {
            if libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) == 0 {
                return flags as u32;
            }
        }
    }

    0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileNode {
    pub path: PathBuf,
    pub hash: u64,
    pub size: u64,
    pub is_dir: bool,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    #[cfg(unix)]
    pub mode: u32,
    #[cfg(unix)]
    pub mtime: i64,
    #[cfg(unix)]
    pub atime: i64,
    #[cfg(unix)]
    pub ctime: i64,
    #[cfg(unix)]
    pub nlink: u64,
    #[cfg(unix)]
    pub xattrs: HashMap<String, Vec<u8>>,
    #[cfg(target_os = "macos")]
    pub flags: u32,  // BSD st_flags (chflags)
    #[cfg(target_os = "linux")]
    pub flags: u32,  // Linux file attributes (chattr)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: i64,
    pub root: PathBuf,
    pub nodes: HashMap<PathBuf, FileNode>,
}

pub fn hash_file(path: &Path) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 65536];
    let mut hasher = Xxh3::new();

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.digest())
}

pub fn hash_directory(entries: &[&FileNode]) -> u64 {
    let mut hasher = Xxh3::new();

    for entry in entries {
        hasher.update(&entry.hash.to_le_bytes());
        hasher.update(entry.path.to_string_lossy().as_bytes());
    }

    hasher.digest()
}

pub fn create_snapshot(
    root: &str,
    skip_dirs: &[String],
    max_size_mb: u64,
) -> std::io::Result<Snapshot> {
    let skip_paths: Vec<PathBuf> = skip_dirs.iter().map(PathBuf::from).collect();
    let max_bytes = max_size_mb * 1024 * 1024;

    let files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            if let Ok(path) = std::fs::canonicalize(e.path()) {
                if skip_paths.iter().any(|d| path.starts_with(d)) {
                    return false;
                }

                if e.file_type().is_file() {
                    if let Ok(meta) = e.metadata() {
                        return meta.len() < max_bytes;
                    }
                    return false;
                }

                // Include directories
                return e.file_type().is_dir();
            }
            false
        })
        .map(|e| std::fs::canonicalize(e.into_path()).unwrap())
        .collect();

    let file_nodes: HashMap<PathBuf, FileNode> = files
        .par_iter()
        .filter_map(|path| {
            let hash = hash_file(path).ok()?;
            let metadata = path.metadata().ok()?;

            Some((
                path.clone(),
                FileNode {
                    path: path.clone(),
                    hash,
                    size: metadata.len(),
                    is_dir: false,
                    #[cfg(unix)]
                    uid: metadata.uid(),
                    #[cfg(unix)]
                    gid: metadata.gid(),
                    #[cfg(unix)]
                    mode: metadata.mode(),
                    #[cfg(unix)]
                    mtime: metadata.mtime(),
                    #[cfg(unix)]
                    atime: metadata.atime(),
                    #[cfg(unix)]
                    ctime: metadata.ctime(),
                    #[cfg(unix)]
                    nlink: metadata.nlink(),
                    #[cfg(unix)]
                    xattrs: get_xattrs(path),
                    #[cfg(target_os = "macos")]
                    flags: metadata.st_flags(),
                    #[cfg(target_os = "linux")]
                    flags: get_linux_flags(path),
                },
            ))
        })
        .collect();

    let mut all_nodes = file_nodes.clone();
    let mut dir_children: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    for file_path in file_nodes.keys() {
        let mut current = file_path.parent();
        while let Some(dir) = current {
            dir_children
                .entry(dir.to_path_buf())
                .or_insert_with(Vec::new)
                .push(file_path.clone());
            current = dir.parent();
        }
    }

    let mut dirs: Vec<PathBuf> = dir_children.keys().cloned().collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    for dir_path in dirs {
        let mut children: Vec<&FileNode> = dir_children[&dir_path]
            .iter()
            .filter_map(|p| all_nodes.get(p))
            .collect();

        children.sort_by(|a, b| a.path.cmp(&b.path));

        let hash = hash_directory(&children);
        let size = children.iter().map(|n| n.size).sum();

        let metadata = dir_path.metadata().ok();

        all_nodes.insert(
            dir_path.clone(),
            FileNode {
                path: dir_path.clone(),
                hash,
                size,
                is_dir: true,
                #[cfg(unix)]
                uid: metadata.as_ref().map(|m| m.uid()).unwrap_or(0),
                #[cfg(unix)]
                gid: metadata.as_ref().map(|m| m.gid()).unwrap_or(0),
                #[cfg(unix)]
                mode: metadata.as_ref().map(|m| m.mode()).unwrap_or(0),
                #[cfg(unix)]
                mtime: metadata.as_ref().map(|m| m.mtime()).unwrap_or(0),
                #[cfg(unix)]
                atime: metadata.as_ref().map(|m| m.atime()).unwrap_or(0),
                #[cfg(unix)]
                ctime: metadata.as_ref().map(|m| m.ctime()).unwrap_or(0),
                #[cfg(unix)]
                nlink: metadata.as_ref().map(|m| m.nlink()).unwrap_or(0),
                #[cfg(unix)]
                xattrs: get_xattrs(&dir_path),
                #[cfg(target_os = "macos")]
                flags: metadata.as_ref().map(|m| m.st_flags()).unwrap_or(0),
                #[cfg(target_os = "linux")]
                flags: get_linux_flags(&dir_path),
            },
        );
    }

    // Canonicalize root path to ensure it's always stored as absolute path
    let root_path = std::fs::canonicalize(root)
        .unwrap_or_else(|_| PathBuf::from(root));

    Ok(Snapshot {
        timestamp: jiff::Timestamp::now().as_second(),
        root: root_path,
        nodes: all_nodes,
    })
}

pub fn save_snapshot(snapshot: &Snapshot, filename: &str) -> std::io::Result<()> {
    let file = File::create(filename)?;
    let compressed = zstd::stream::write::Encoder::new(file, 3)?;
    bincode::serialize_into(compressed, snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

pub fn load_snapshot(filename: &str) -> std::io::Result<Snapshot> {
    let file = File::open(filename)?;
    let decompressed = zstd::stream::read::Decoder::new(file)?;
    bincode::deserialize_from(decompressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified,
    PermChanged,
    Unchanged,
}

#[derive(Debug, Clone)]
pub struct DiffNode {
    pub path: PathBuf,
    pub status: DiffStatus,
    pub old_node: Option<FileNode>,
    pub new_node: Option<FileNode>,
    pub is_dir: bool,
    pub change_time: Option<i64>,
}

impl DiffNode {
    #[cfg(unix)]
    pub fn has_suid_change(&self) -> bool {
        if let (Some(old), Some(new)) = (&self.old_node, &self.new_node) {
            let old_suid = old.mode & 0o4000 != 0;
            let new_suid = new.mode & 0o4000 != 0;
            old_suid != new_suid
        } else {
            false
        }
    }

    #[cfg(unix)]
    pub fn has_sgid_change(&self) -> bool {
        if let (Some(old), Some(new)) = (&self.old_node, &self.new_node) {
            let old_sgid = old.mode & 0o2000 != 0;
            let new_sgid = new.mode & 0o2000 != 0;
            old_sgid != new_sgid
        } else {
            false
        }
    }

    #[cfg(unix)]
    pub fn is_now_suid(&self) -> bool {
        if let Some(new) = &self.new_node {
            new.mode & 0o4000 != 0
        } else {
            false
        }
    }
}

pub fn merge_snapshots(base: &mut Snapshot, new: &Snapshot) {
    for (path, node) in &new.nodes {
        base.nodes.insert(path.clone(), node.clone());
    }

    base.timestamp = new.timestamp;

    let mut all_dirs: std::collections::HashSet<PathBuf> = base
        .nodes
        .values()
        .filter(|n| n.is_dir)
        .map(|n| n.path.clone())
        .collect();

    for path in base.nodes.keys() {
        let mut current = path.parent();
        while let Some(dir) = current {
            all_dirs.insert(dir.to_path_buf());
            current = dir.parent();
        }
    }

    let mut dirs: Vec<PathBuf> = all_dirs.into_iter().collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    for dir_path in dirs {
        let children: Vec<&FileNode> = base
            .nodes
            .values()
            .filter(|n| {
                if let Some(parent) = n.path.parent() {
                    parent == dir_path && !n.is_dir
                } else {
                    false
                }
            })
            .collect();

        if !children.is_empty() {
            let mut sorted_children = children;
            sorted_children.sort_by(|a, b| a.path.cmp(&b.path));

            let hash = hash_directory(&sorted_children);
            let size = sorted_children.iter().map(|n| n.size).sum();

            let metadata = dir_path.metadata().ok();

            base.nodes.insert(
                dir_path.clone(),
                FileNode {
                    path: dir_path.clone(),
                    hash,
                    size,
                    is_dir: true,
                    #[cfg(unix)]
                    uid: metadata.as_ref().map(|m| m.uid()).unwrap_or(0),
                    #[cfg(unix)]
                    gid: metadata.as_ref().map(|m| m.gid()).unwrap_or(0),
                    #[cfg(unix)]
                    mode: metadata.as_ref().map(|m| m.mode()).unwrap_or(0),
                    #[cfg(unix)]
                    mtime: metadata.as_ref().map(|m| m.mtime()).unwrap_or(0),
                    #[cfg(unix)]
                    atime: metadata.as_ref().map(|m| m.atime()).unwrap_or(0),
                    #[cfg(unix)]
                    ctime: metadata.as_ref().map(|m| m.ctime()).unwrap_or(0),
                    #[cfg(unix)]
                    nlink: metadata.as_ref().map(|m| m.nlink()).unwrap_or(0),
                    #[cfg(unix)]
                    xattrs: get_xattrs(&dir_path),
                    #[cfg(target_os = "macos")]
                    flags: metadata.as_ref().map(|m| m.st_flags()).unwrap_or(0),
                    #[cfg(target_os = "linux")]
                    flags: get_linux_flags(&dir_path),
                },
            );
        }
    }
}

pub fn diff_snapshots(old: &Snapshot, new: &Snapshot) -> Vec<DiffNode> {
    let mut diffs = Vec::new();
    let all_paths: std::collections::HashSet<_> = old
        .nodes
        .keys()
        .chain(new.nodes.keys())
        .cloned()
        .collect();

    for path in all_paths {
        let old_node = old.nodes.get(&path);
        let new_node = new.nodes.get(&path);

        let diff = match (old_node, new_node) {
            (None, Some(new)) => DiffNode {
                path: path.clone(),
                status: DiffStatus::Added,
                old_node: None,
                new_node: Some(new.clone()),
                is_dir: new.is_dir,
                #[cfg(unix)]
                change_time: Some(new.ctime),
                #[cfg(not(unix))]
                change_time: None,
            },
            (Some(old), None) => DiffNode {
                path: path.clone(),
                status: DiffStatus::Removed,
                old_node: Some(old.clone()),
                new_node: None,
                is_dir: old.is_dir,
                #[cfg(unix)]
                change_time: Some(old.ctime),
                #[cfg(not(unix))]
                change_time: None,
            },
            (Some(old), Some(new)) => {
                let hash_changed = old.hash != new.hash;

                #[cfg(unix)]
                let perm_changed = old.mode != new.mode || old.uid != new.uid || old.gid != new.gid;
                #[cfg(not(unix))]
                let perm_changed = false;

                let status = if hash_changed {
                    DiffStatus::Modified
                } else if perm_changed {
                    DiffStatus::PermChanged
                } else {
                    DiffStatus::Unchanged
                };

                DiffNode {
                    path: path.clone(),
                    status,
                    old_node: Some(old.clone()),
                    new_node: Some(new.clone()),
                    is_dir: new.is_dir,
                    #[cfg(unix)]
                    change_time: Some(new.ctime),
                    #[cfg(not(unix))]
                    change_time: None,
                }
            }
            _ => continue,
        };

        diffs.push(diff);
    }

    diffs.sort_by(|a, b| a.path.cmp(&b.path));
    diffs
}

pub fn compute_sha256(path: &Path) -> std::io::Result<String> {
    use sha2::{Sha256, Digest};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

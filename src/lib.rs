use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use xxhash_rust::xxh3::Xxh3;
use memmap2::Mmap;

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

// Helper function to get extended attributes hash
#[cfg(unix)]
pub fn get_xattrs_hash(path: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;

    let mut hasher = Xxh3::new();

    if let Ok(list) = xattr::list(path) {
        let mut names: Vec<_> = list.collect();
        names.sort(); // Ensure consistent ordering

        for name in names {
            if let Ok(value) = xattr::get(path, &name) {
                if let Some(data) = value {
                    hasher.update(name.as_bytes());
                    hasher.update(&data);
                }
            }
        }
    }

    hasher.digest()
}

// Helper function to get extended attributes keys for display
#[cfg(unix)]
pub fn get_xattrs_keys(path: &Path) -> Vec<String> {
    let mut keys = Vec::new();

    if let Ok(list) = xattr::list(path) {
        for name in list {
            keys.push(name.to_string_lossy().to_string());
        }
    }

    keys.sort();
    keys
}

// Helper function to get LSM (Linux Security Module) context
// Checks for SELinux first, then AppArmor (they're mutually exclusive)
#[cfg(target_os = "linux")]
pub fn get_lsm_context(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;

    // Try SELinux first
    if let Ok(Some(value)) = xattr::get(path, "security.selinux") {
        let context = value.iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();

        if let Ok(ctx) = String::from_utf8(context) {
            return Some(ctx);
        }
    }

    // Try AppArmor
    if let Ok(Some(value)) = xattr::get(path, "security.apparmor") {
        let context = value.iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();

        if let Ok(ctx) = String::from_utf8(context) {
            return Some(ctx);
        }
    }

    None
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
    #[serde(skip, default)]
    pub atime: i64,
    #[cfg(unix)]
    pub ctime: i64,
    #[cfg(unix)]
    pub nlink: u16,
    #[cfg(unix)]
    pub xattrs_hash: u64,
    #[cfg(target_os = "linux")]
    pub lsm_context: Option<String>,  // SELinux or AppArmor context
    #[cfg(target_os = "macos")]
    pub flags: u32,  // BSD st_flags (chflags)
    #[cfg(target_os = "linux")]
    pub flags: u32,  // Linux file attributes (chattr)
}

pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Schema version for compatibility checking
    pub version: u32,
    /// Unix timestamp when snapshot was created
    pub timestamp: i64,
    /// Root path that was scanned
    pub root: PathBuf,
    /// All file and directory nodes
    pub nodes: HashMap<PathBuf, FileNode>,
}

impl Snapshot {
    /// Check if snapshot version is compatible
    pub fn check_version(&self) -> Result<(), String> {
        if self.version > SNAPSHOT_VERSION {
            Err(format!(
                "Snapshot version {} is newer than supported version {}. Please upgrade diffie.",
                self.version, SNAPSHOT_VERSION
            ))
        } else if self.version < SNAPSHOT_VERSION {
            eprintln!(
                "[WARN] Snapshot version {} is older than current version {}. Some features may not work correctly.",
                self.version, SNAPSHOT_VERSION
            );
            Ok(())
        } else {
            Ok(())
        }
    }
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

pub fn hash_directory(entries: &[(&Path, &FileNode)]) -> u64 {
    let mut hasher = Xxh3::new();

    for (path, entry) in entries {
        hasher.update(&entry.hash.to_le_bytes());
        hasher.update(path.to_string_lossy().as_bytes());
    }

    hasher.digest()
}

pub fn create_snapshot(
    root: &str,
    skip_dirs: &[String],
    max_size_mb: u64,
) -> std::io::Result<Snapshot> {
    create_snapshot_with_progress(root, skip_dirs, max_size_mb, None::<fn(usize, usize)>)
}

pub fn create_snapshot_with_progress<F>(
    root: &str,
    skip_dirs: &[String],
    max_size_mb: u64,
    progress_callback: Option<F>,
) -> std::io::Result<Snapshot>
where
    F: Fn(usize, usize) + Send + Sync,
{
    let skip_paths: Vec<PathBuf> = skip_dirs.iter().map(PathBuf::from).collect();
    let max_bytes = max_size_mb * 1024 * 1024;

    // Report progress: collecting files (0%)
    if let Some(ref cb) = progress_callback {
        cb(0, 100);
    }

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

    let total_files = files.len();

    // Report progress: files collected (10%)
    if let Some(ref cb) = progress_callback {
        cb(10, 100);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    let processed = AtomicUsize::new(0);

    let file_nodes: HashMap<PathBuf, FileNode> = files
        .par_iter()
        .filter_map(|path| {
            let hash = hash_file(path).ok()?;
            let metadata = path.metadata().ok()?;

            // Update progress (10% to 80% range for file processing)
            let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(ref cb) = progress_callback {
                let progress = 10 + ((current * 70) / total_files.max(1));
                cb(progress, 100);
            }

            Some((
                path.clone(),
                FileNode {
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
                    nlink: metadata.nlink().min(u16::MAX as u64) as u16,
                    #[cfg(unix)]
                    xattrs_hash: get_xattrs_hash(path),
                    #[cfg(target_os = "linux")]
                    lsm_context: get_lsm_context(path),
                    #[cfg(target_os = "macos")]
                    flags: metadata.st_flags(),
                    #[cfg(target_os = "linux")]
                    flags: get_linux_flags(path),
                },
            ))
        })
        .collect();

    // Report progress: hashing directories (80%)
    if let Some(ref cb) = progress_callback {
        cb(80, 100);
    }

    let mut all_nodes = file_nodes.clone();

    // Build parent-child relationships for directories
    // Each directory should only include its DIRECT children (files + subdirs)
    let mut dir_children: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    // Add file children - files only know their immediate parent
    for file_path in file_nodes.keys() {
        if let Some(parent) = file_path.parent() {
            dir_children
                .entry(parent.to_path_buf())
                .or_insert_with(Vec::new)
                .push(file_path.clone());
        }
    }

    let mut dirs: Vec<PathBuf> = dir_children.keys().cloned().collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    let total_dirs = dirs.len();
    let mut processed_dirs = 0;

    for dir_path in dirs {
        processed_dirs += 1;
        // Update progress (80% to 95% range for directory processing)
        if let Some(ref cb) = progress_callback {
            let progress = 80 + ((processed_dirs * 15) / total_dirs.max(1));
            cb(progress, 100);
        }
        let mut children: Vec<(&Path, &FileNode)> = dir_children[&dir_path]
            .iter()
            .filter_map(|p| all_nodes.get(p).map(|n| (p.as_path(), n)))
            .collect();

        children.sort_by(|a, b| a.0.cmp(b.0));

        let hash = hash_directory(&children);
        let size = children.iter().map(|n| n.1.size).sum();

        let metadata = dir_path.metadata().ok();

        all_nodes.insert(
            dir_path.clone(),
            FileNode {
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
                nlink: metadata.as_ref().map(|m| m.nlink().min(u16::MAX as u64) as u16).unwrap_or(0),
                #[cfg(unix)]
                xattrs_hash: get_xattrs_hash(&dir_path),
                #[cfg(target_os = "linux")]
                lsm_context: get_lsm_context(&dir_path),
                #[cfg(target_os = "macos")]
                flags: metadata.as_ref().map(|m| m.st_flags()).unwrap_or(0),
                #[cfg(target_os = "linux")]
                flags: get_linux_flags(&dir_path),
            },
        );

        // Add this directory as a child to its parent (for proper merkle tree)
        if let Some(parent) = dir_path.parent() {
            dir_children
                .entry(parent.to_path_buf())
                .or_insert_with(Vec::new)
                .push(dir_path.clone());
        }
    }

    // Report progress: finalizing (95%)
    if let Some(ref cb) = progress_callback {
        cb(95, 100);
    }

    // Canonicalize root path to ensure it's always stored as absolute path
    let root_path = std::fs::canonicalize(root)
        .unwrap_or_else(|_| PathBuf::from(root));

    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        timestamp: jiff::Timestamp::now().as_second(),
        root: root_path,
        nodes: all_nodes,
    };

    // Report progress: complete (100%)
    if let Some(ref cb) = progress_callback {
        cb(100, 100);
    }

    Ok(snapshot)
}

pub fn save_snapshot(snapshot: &Snapshot, filename: &str) -> std::io::Result<()> {
    let file = File::create(filename)?;
    let mut compressed = zstd::stream::write::Encoder::new(file, 10)?;
    bincode::serialize_into(&mut compressed, snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    compressed.finish()?;
    Ok(())
}

/// Load snapshot using memory-mapped file for better performance with large snapshots
/// This avoids loading the entire compressed data into memory before decompression
pub fn load_snapshot_mmap(filename: &str) -> std::io::Result<Snapshot> {
    let file = File::open(filename)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let decompressed = zstd::decode_all(&mmap[..])?;
    let snapshot: Snapshot = bincode::deserialize(&decompressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Validate version
    snapshot.check_version()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(snapshot)
}

pub fn load_snapshot(filename: &str) -> std::io::Result<Snapshot> {
    let file = File::open(filename)?;
    let decompressed = zstd::stream::read::Decoder::new(file)?;
    let snapshot: Snapshot = bincode::deserialize_from(decompressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Validate version
    snapshot.check_version()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(snapshot)
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
        .iter()
        .filter(|(_, n)| n.is_dir)
        .map(|(p, _)| p.clone())
        .collect();

    for path in base.nodes.keys() {
        let mut current = path.parent();
        while let Some(dir) = current {
            all_dirs.insert(dir.to_path_buf());
            current = dir.parent();
        }
    }

    let mut dirs: Vec<PathBuf> = all_dirs.into_iter().collect();
    dirs.sort_by_key(|p: &PathBuf| std::cmp::Reverse(p.components().count()));

    for dir_path in &dirs {
        let children: Vec<(&Path, &FileNode)> = base
            .nodes
            .iter()
            .filter(|(path, n)| {
                if let Some(parent) = path.parent() {
                    parent == dir_path && !n.is_dir
                } else {
                    false
                }
            })
            .map(|(p, n)| (p.as_path(), n))
            .collect();

        if !children.is_empty() {
            let mut sorted_children = children;
            sorted_children.sort_by(|a, b| a.0.cmp(b.0));

            let hash = hash_directory(&sorted_children);
            let size = sorted_children.iter().map(|n| n.1.size).sum();

            let metadata: Option<std::fs::Metadata> = dir_path.metadata().ok();

            base.nodes.insert(
                dir_path.clone(),
                FileNode {
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
                    nlink: metadata.as_ref().map(|m| m.nlink().min(u16::MAX as u64) as u16).unwrap_or(0),
                    #[cfg(unix)]
                    xattrs_hash: get_xattrs_hash(dir_path),
                    #[cfg(target_os = "linux")]
                    lsm_context: get_lsm_context(dir_path),
                    #[cfg(target_os = "macos")]
                    flags: metadata.as_ref().map(|m| m.st_flags()).unwrap_or(0),
                    #[cfg(target_os = "linux")]
                    flags: get_linux_flags(dir_path),
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

                #[cfg(all(unix, not(target_os = "linux")))]
                let perm_changed = old.mode != new.mode || old.uid != new.uid || old.gid != new.gid || old.xattrs_hash != new.xattrs_hash;
                #[cfg(target_os = "linux")]
                let perm_changed = old.mode != new.mode || old.uid != new.uid || old.gid != new.gid || old.xattrs_hash != new.xattrs_hash || old.lsm_context != new.lsm_context;
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

pub fn compute_md5(path: &Path) -> std::io::Result<String> {
    use md5::{Md5, Digest};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
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

pub fn compute_blake3(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

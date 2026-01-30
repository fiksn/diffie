use crate::{hash_directory, hash_file, FileNode, LogEntry, Snapshot};
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::collections::{HashMap, HashSet};
#[allow(unused_imports)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;

#[cfg(target_os = "linux")]
use walkdir;

#[derive(Debug, Clone)]
pub enum FileEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Removed(PathBuf),
}

#[cfg(target_os = "linux")]
use inotify::{Inotify, WatchMask};

#[derive(Debug, Clone)]
pub struct InotifyLimits {
    pub max_user_watches: usize,
    pub max_user_instances: usize,
    pub max_queued_events: usize,
}

impl InotifyLimits {
    #[cfg(target_os = "linux")]
    pub fn read_from_procfs() -> std::io::Result<Self> {
        let max_user_watches = fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")?
            .trim()
            .parse()
            .unwrap_or(8192);

        let max_user_instances = fs::read_to_string("/proc/sys/fs/inotify/max_user_instances")?
            .trim()
            .parse()
            .unwrap_or(128);

        let max_queued_events = fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")?
            .trim()
            .parse()
            .unwrap_or(16384);

        Ok(InotifyLimits {
            max_user_watches,
            max_user_instances,
            max_queued_events,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_from_procfs() -> std::io::Result<Self> {
        Ok(InotifyLimits {
            max_user_watches: 0,
            max_user_instances: 0,
            max_queued_events: 0,
        })
    }
}

pub struct Monitor {
    snapshot: Arc<Mutex<Snapshot>>,
    #[allow(dead_code)]
    critical_dirs: Vec<PathBuf>,
    watched_dirs: HashSet<PathBuf>,
    #[allow(dead_code)]
    watch_budget: usize,
    watches_used: usize,
    max_size_bytes: u64,
    change_times: Arc<Mutex<HashMap<PathBuf, i64>>>,
    log_buffer: Option<Arc<Mutex<Vec<LogEntry>>>>,
    #[cfg(target_os = "linux")]
    inotify: Option<Inotify>,
    #[cfg(target_os = "linux")]
    watch_map: HashMap<i32, PathBuf>, // Map watch descriptor to directory path
    #[cfg(not(target_os = "linux"))]
    watcher: Option<Box<dyn Watcher + Send>>,
    #[cfg(not(target_os = "linux"))]
    event_rx: Option<Receiver<Result<Event, notify::Error>>>,
}

impl Monitor {
    fn log(&self, message: String) {
        if let Some(ref log_buffer) = self.log_buffer {
            let mut log = log_buffer.lock().unwrap();
            log.push(LogEntry {
                timestamp: jiff::Timestamp::now().as_second(),
                message,
            });
        } else {
            println!("{}", message);
        }
    }

    pub fn new(snapshot: Snapshot, critical_dirs: Vec<PathBuf>, log_buffer: Option<Arc<Mutex<Vec<LogEntry>>>>, max_size_mb: u64) -> std::io::Result<Self> {
        let max_size_bytes = max_size_mb * 1024 * 1024;

        #[cfg(target_os = "linux")]
        {
            let inotify = Some(Inotify::init()?);
            let limits = InotifyLimits::read_from_procfs()?;
            let watch_budget = (limits.max_user_watches as f64 * 0.7) as usize;

            let monitor = Self {
                snapshot: Arc::new(Mutex::new(snapshot)),
                critical_dirs,
                watched_dirs: HashSet::new(),
                watch_budget,
                watches_used: 0,
                max_size_bytes,
                change_times: Arc::new(Mutex::new(HashMap::new())),
                log_buffer,
                inotify,
                watch_map: HashMap::new(),
            };

            monitor.log("Platform: Linux (inotify)".to_string());
            monitor.log("inotify limits:".to_string());
            monitor.log(format!("  max_user_watches: {}", limits.max_user_watches));
            monitor.log(format!("  max_user_instances: {}", limits.max_user_instances));
            monitor.log(format!("  max_queued_events: {}", limits.max_queued_events));
            monitor.log(format!("  Using 70% budget: {} watches", watch_budget));
            monitor.log(format!("  Max file size: {} MB", max_size_mb));

            Ok(monitor)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let watch_budget = 10000;

            let (tx, rx) = channel();
            let watcher = notify::recommended_watcher(tx)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let monitor = Self {
                snapshot: Arc::new(Mutex::new(snapshot)),
                critical_dirs,
                watched_dirs: HashSet::new(),
                watch_budget,
                watches_used: 0,
                max_size_bytes,
                change_times: Arc::new(Mutex::new(HashMap::new())),
                log_buffer,
                watcher: Some(Box::new(watcher)),
                event_rx: Some(rx),
            };

            monitor.log("Platform: macOS/BSD (FSEvents via notify)".to_string());
            monitor.log(format!("Max file size: {} MB", max_size_mb));
            monitor.log(format!("  Watch budget: {} (FSEvents doesn't have hard limits)", watch_budget));

            Ok(monitor)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn setup_watches(&mut self, scan_root: &Path) -> std::io::Result<()> {
        // Linux inotify: Watch as many directories as budget allows
        // Priority: critical_dirs first, then depth-first traversal
        self.log(format!("Setting up inotify watches (budget: {})", self.watch_budget));

        let mut log_messages = Vec::new();

        if let Some(ref mut inotify) = self.inotify {
            let watch_mask = WatchMask::MODIFY
                | WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::ATTRIB
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO;

            // Build list of directories to watch: critical dirs + all subdirs of root
            let mut to_watch: Vec<PathBuf> = Vec::new();

            // Priority 1: Critical directories that are in scope
            for critical_dir in &self.critical_dirs {
                if critical_dir.exists() && critical_dir.starts_with(scan_root) {
                    to_watch.push(critical_dir.clone());
                }
            }

            // Priority 2: All subdirectories of root (depth-first, up to depth 10)
            for entry in walkdir::WalkDir::new(scan_root)
                .max_depth(10)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_dir())
            {
                let path = entry.path().to_path_buf();
                if !to_watch.contains(&path) {
                    to_watch.push(path);
                }
            }

            log_messages.push(format!("Found {} directories to watch", to_watch.len()));

            // Add watches until budget exhausted
            for dir in to_watch {
                if self.watches_used >= self.watch_budget {
                    log_messages.push("⚠ Watch budget exhausted".to_string());
                    break;
                }

                match inotify.watches().add(&dir, watch_mask) {
                    Ok(wd) => {
                        self.watched_dirs.insert(dir.clone());
                        self.watch_map.insert(wd.get_watch_descriptor_id(), dir);
                        self.watches_used += 1;
                    }
                    Err(e) => {
                        log_messages.push(format!("✗ Failed to watch {}: {}", dir.display(), e));
                    }
                }
            }

            log_messages.push(format!("\n=== Watch Summary ==="));
            log_messages.push(format!("Total watches used: {} / {}", self.watches_used, self.watch_budget));
            log_messages.push(format!("Watched directories: {}", self.watched_dirs.len()));
        }

        for msg in log_messages {
            self.log(msg);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn setup_watches(&mut self, scan_root: &Path) -> std::io::Result<()> {
        // macOS FSEvents: One recursive watch on root covers everything
        self.log(format!("Setting up FSEvents watch on: {}", scan_root.display()));

        if let Some(ref mut watcher) = self.watcher {
            match watcher.watch(scan_root, RecursiveMode::Recursive) {
                Ok(_) => {
                    self.watched_dirs.insert(scan_root.to_path_buf());
                    self.watches_used = 1;
                    self.log("✓ FSEvents watching entire tree recursively".to_string());
                }
                Err(e) => {
                    self.log(format!("✗ Failed to setup FSEvents watch: {}", e));
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }
            }
        }

        self.log("\n=== Watch Summary ===".to_string());
        self.log("Total watches used: 1 (recursive FSEvents)".to_string());
        self.log(format!("Watched root: {}", scan_root.display()));

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn process_events(&self) -> Vec<FileEvent> {
        let mut events = Vec::new();

        if let Some(ref inotify) = self.inotify {
            let mut buffer = [0u8; 4096];
            // Use read_events_blocking with a zero timeout for non-blocking read
            match inotify.read_events(&mut buffer) {
                Ok(events_iter) => {
                    for event in events_iter {
                        let wd_id = event.wd.get_watch_descriptor_id();

                        // Look up the directory path from the watch descriptor
                        if let Some(dir_path) = self.watch_map.get(&wd_id) {
                            // Construct the full path
                            let path = if let Some(name) = event.name {
                                dir_path.join(name.to_string_lossy().as_ref())
                            } else {
                                // Event is for the directory itself
                                dir_path.clone()
                            };

                            if event.mask.contains(WatchMask::DELETE) || event.mask.contains(WatchMask::DELETE_SELF) {
                                events.push(FileEvent::Removed(path));
                            } else if event.mask.contains(WatchMask::CREATE) {
                                if path.is_file() {
                                    events.push(FileEvent::Created(path));
                                }
                            } else if event.mask.contains(WatchMask::MODIFY) || event.mask.contains(WatchMask::ATTRIB) {
                                if path.is_file() {
                                    events.push(FileEvent::Modified(path));
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // No events available (non-blocking read)
                }
            }
        }

        events
    }

    #[cfg(not(target_os = "linux"))]
    pub fn process_events(&self) -> Vec<FileEvent> {
        let mut events = Vec::new();

        if let Some(ref rx) = self.event_rx {
            while let Ok(result) = rx.try_recv() {
                match result {
                    Ok(event) => {
                        for path in event.paths {
                            match event.kind {
                                EventKind::Remove(_) => {
                                    // For remove events, the file no longer exists, so we can't check is_file()
                                    events.push(FileEvent::Removed(path));
                                }
                                EventKind::Create(_) => {
                                    // For create, only process if it's a file
                                    if path.is_file() {
                                        events.push(FileEvent::Created(path));
                                    }
                                }
                                EventKind::Modify(_) => {
                                    // For modify, only process if it's a file
                                    if path.is_file() {
                                        events.push(FileEvent::Modified(path));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_e) => {
                        // Silently ignore errors during TUI operation
                    }
                }
            }
        }

        events
    }

    pub fn update_file(&self, path: &Path) -> std::io::Result<(bool, Option<i64>, bool)> {
        let file_metadata = path.metadata()?;

        if !file_metadata.is_file() {
            return Ok((false, None, false));
        }

        // Skip files that exceed size limit (consistent with initial snapshot)
        if file_metadata.len() >= self.max_size_bytes {
            return Ok((false, None, false));
        }

        let hash = hash_file(path)?;
        let now = jiff::Timestamp::now().as_second();

        let mut snapshot = self.snapshot.lock().unwrap();

        let (content_changed, metadata_changed) = if let Some(existing) = snapshot.nodes.get(path) {
            let content = existing.hash != hash;

            #[cfg(unix)]
            let mut metadata = existing.mtime != file_metadata.mtime()
                || existing.mode != file_metadata.mode()
                || existing.uid != file_metadata.uid()
                || existing.gid != file_metadata.gid()
                || existing.nlink != file_metadata.nlink();

            #[cfg(unix)]
            {
                let current_xattrs = crate::get_xattrs(path);
                metadata = metadata || existing.xattrs != current_xattrs;
            }

            #[cfg(target_os = "macos")]
            {
                metadata = metadata || existing.flags != file_metadata.st_flags();
            }

            #[cfg(target_os = "linux")]
            {
                let current_flags = crate::get_linux_flags(path);
                metadata = metadata || existing.flags != current_flags;
            }

            #[cfg(not(unix))]
            let metadata = false;

            (content, metadata)
        } else {
            (true, true)  // New file - both content and metadata are "new"
        };

        let updated = content_changed || metadata_changed;

        if updated {
            snapshot.nodes.insert(
                path.to_path_buf(),
                FileNode {
                    path: path.to_path_buf(),
                    hash,
                    size: file_metadata.len(),
                    is_dir: false,
                    #[cfg(unix)]
                    uid: file_metadata.uid(),
                    #[cfg(unix)]
                    gid: file_metadata.gid(),
                    #[cfg(unix)]
                    mode: file_metadata.mode(),
                    #[cfg(unix)]
                    mtime: file_metadata.mtime(),
                    #[cfg(unix)]
                    atime: file_metadata.atime(),
                    #[cfg(unix)]
                    ctime: file_metadata.ctime(),
                    #[cfg(unix)]
                    nlink: file_metadata.nlink(),
                    #[cfg(unix)]
                    xattrs: crate::get_xattrs(path),
                    #[cfg(target_os = "macos")]
                    flags: file_metadata.st_flags(),
                    #[cfg(target_os = "linux")]
                    flags: crate::get_linux_flags(path),
                },
            );

            // Bubble up changes to parent directories
            // content_changed: recalculate parent hashes
            // metadata_changed: just mark parents as changed (for ⚡ indicator)
            self.recalculate_parent_hashes(&mut snapshot, path, content_changed, true);

            let mut change_times = self.change_times.lock().unwrap();
            change_times.insert(path.to_path_buf(), now);

            Ok((true, Some(now), content_changed))
        } else {
            Ok((false, None, false))
        }
    }

    pub fn get_change_time(&self, path: &Path) -> Option<i64> {
        let change_times = self.change_times.lock().unwrap();
        change_times.get(path).copied()
    }

    pub fn get_all_change_times(&self) -> HashMap<PathBuf, i64> {
        let change_times = self.change_times.lock().unwrap();
        change_times.clone()
    }

    pub fn remove_file(&self, path: &Path) -> bool {
        let mut snapshot = self.snapshot.lock().unwrap();

        if snapshot.nodes.remove(path).is_some() {
            // File removed = content change, so recalculate parent hashes and mark parents
            self.recalculate_parent_hashes(&mut snapshot, path, true, true);
            true
        } else {
            false
        }
    }

    fn recalculate_parent_hashes(
        &self,
        snapshot: &mut Snapshot,
        file_path: &Path,
        content_changed: bool,
        mark_parents: bool,
    ) {
        let mut current = file_path.parent();
        let now = jiff::Timestamp::now().as_second();
        let watch_root = &snapshot.root;

        while let Some(dir) = current {
            // Stop if we've gone outside the watch root
            if !dir.starts_with(watch_root) {
                break;
            }

            let mut children: Vec<&FileNode> = snapshot
                .nodes
                .values()
                .filter(|n| {
                    if let Some(parent) = n.path.parent() {
                        parent == dir && !n.is_dir
                    } else {
                        false
                    }
                })
                .collect();

            if !children.is_empty() {
                children.sort_by(|a, b| a.path.cmp(&b.path));

                if content_changed {
                    // Recalculate directory hash because child content changed
                    let hash = hash_directory(&children);
                    let size = children.iter().map(|n| n.size).sum();

                    let metadata = dir.metadata().ok();

                    // Check if hash actually changed before updating change_time
                    let hash_changed = snapshot.nodes.get(dir)
                        .map(|existing| existing.hash != hash)
                        .unwrap_or(true);

                    snapshot.nodes.insert(
                        dir.to_path_buf(),
                        FileNode {
                            path: dir.to_path_buf(),
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
                            xattrs: crate::get_xattrs(dir),
                            #[cfg(target_os = "macos")]
                            flags: metadata.as_ref().map(|m| m.st_flags()).unwrap_or(0),
                            #[cfg(target_os = "linux")]
                            flags: crate::get_linux_flags(dir),
                        },
                    );

                    // Record change time for the directory if its hash changed
                    if hash_changed && mark_parents {
                        let mut change_times = self.change_times.lock().unwrap();
                        change_times.insert(dir.to_path_buf(), now);
                    }
                } else if mark_parents {
                    // Content didn't change but metadata did (mtime, permissions, etc.)
                    // Don't recalculate hash, just mark directory as changed for ⚡ indicator
                    let mut change_times = self.change_times.lock().unwrap();
                    change_times.insert(dir.to_path_buf(), now);
                }
            }

            current = dir.parent();
        }
    }

    pub fn verify_all_files(&self) -> std::io::Result<Vec<PathBuf>> {
        // Lock briefly to get list of files to check, then release
        let files_to_check: Vec<(PathBuf, FileNode)> = {
            let snapshot = self.snapshot.lock().unwrap();
            snapshot.nodes.iter()
                .filter(|(_, node)| !node.is_dir)
                .map(|(path, node)| (path.clone(), node.clone()))
                .collect()
        };

        // Now do expensive operations without holding the lock
        let mut changed = Vec::new();

        for (path, node) in files_to_check {
            // Check if file still exists
            if let Ok(metadata) = path.metadata() {
                // Re-hash the file to check for changes
                if let Ok(current_hash) = hash_file(&path) {
                    #[cfg(unix)]
                    let mut has_changes = current_hash != node.hash
                        || metadata.mtime() != node.mtime
                        || metadata.mode() != node.mode
                        || metadata.uid() != node.uid
                        || metadata.gid() != node.gid
                        || metadata.nlink() != node.nlink;

                    #[cfg(unix)]
                    {
                        let current_xattrs = crate::get_xattrs(&path);
                        has_changes = has_changes || current_xattrs != node.xattrs;
                    }

                    #[cfg(target_os = "macos")]
                    {
                        has_changes = has_changes || metadata.st_flags() != node.flags;
                    }

                    #[cfg(target_os = "linux")]
                    {
                        let current_flags = crate::get_linux_flags(&path);
                        has_changes = has_changes || current_flags != node.flags;
                    }

                    #[cfg(not(unix))]
                    let has_changes = current_hash != node.hash;

                    if has_changes {
                        changed.push(path);
                    }
                }
            } else {
                // File no longer exists
                changed.push(path);
            }
        }

        Ok(changed)
    }

    #[cfg(target_os = "linux")]
    pub fn scan_for_new_files(&self) -> std::io::Result<Vec<PathBuf>> {
        // Lock briefly to get list of directories to scan, then release
        let (watch_root, dirs): (PathBuf, Vec<PathBuf>) = {
            let snapshot = self.snapshot.lock().unwrap();
            let root = snapshot.root.clone();
            let dirs = snapshot.nodes.iter()
                .filter(|(path, node)| node.is_dir && path.starts_with(&root))
                .map(|(path, _)| path.clone())
                .collect();
            (root, dirs)
        };

        // Scan directories without holding the lock
        let mut found_files = Vec::new();
        for dir in dirs {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        found_files.push(path);
                    }
                }
            }
        }

        // Lock once to filter out files we already know about
        let new_files = {
            let snapshot = self.snapshot.lock().unwrap();
            found_files.into_iter()
                .filter(|path| !snapshot.nodes.contains_key(path))
                .collect()
        };

        Ok(new_files)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn scan_for_new_files(&self) -> std::io::Result<Vec<PathBuf>> {
        // macOS FSEvents covers everything recursively, so scanning is redundant
        Ok(Vec::new())
    }

    pub fn get_snapshot(&self) -> Snapshot {
        self.snapshot.lock().unwrap().clone()
    }
}

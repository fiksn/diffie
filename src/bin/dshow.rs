use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use diffie::{
    compute_sha256, get_critical_dirs_in_scope, get_xattrs_keys, load_snapshot, load_snapshot_mmap,
    monitor::{Monitor, FileEvent}, save_snapshot, DiffNode, DiffStatus, LogEntry, Snapshot, DEFAULT_CRITICAL_DIRS,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(help = "Reference snapshot file (optional with --live)")]
    snapshot1: Option<String>,

    #[arg(help = "Second snapshot file")]
    snapshot2: Option<String>,

    #[arg(long, value_name = "PATH", help = "Live monitoring mode: monitor path and show real-time changes (defaults to / if not specified)")]
    live: Option<Option<String>>,

    #[arg(long, help = "Persist changes to snapshot file on save (use with --live)")]
    persist: bool,

    #[arg(
        long,
        value_name = "DIR",
        num_args = 0..,
        default_values = DEFAULT_CRITICAL_DIRS,
        help = "Critical directories to watch with inotify/FSEvents"
    )]
    critical: Vec<String>,

    #[arg(long, default_value = "30", help = "Polling interval in seconds")]
    poll_interval: u64,

    #[arg(long, default_value = "150", help = "Maximum file size in MB to include in snapshot")]
    max_size: u64,

    #[arg(long, help = "Number of threads for parallel file verification (default: 90% of CPU cores)")]
    threads: Option<usize>,

    #[arg(long, help = "Brief mode: print changes to stdout instead of launching TUI")]
    brief: bool,

    #[arg(long, help = "Use memory-mapped file loading for large snapshots (reduces memory usage)")]
    mmap: bool,
}

fn add_log_entry(log_buffer: &Arc<Mutex<Vec<LogEntry>>>, message: String) {
    let mut log = log_buffer.lock().unwrap();
    log.push(LogEntry {
        timestamp: jiff::Timestamp::now().as_second(),
        message,
    });
}

struct App {
    old_snapshot: Snapshot,
    new_snapshot: Snapshot,
    current_dir: PathBuf,
    selected: usize,
    show_unchanged: bool,
    live_mode: bool,
    monitor: Option<Arc<Mutex<Monitor>>>,
    time_window: i64,
    navigation_root: PathBuf, // The topmost directory we can navigate to
    show_hash_popup: bool,
    log_buffer: Arc<Mutex<Vec<LogEntry>>>,
    show_log: bool,
    log_selected: usize,
    sha256_cache: HashMap<PathBuf, String>, // Cache SHA256 hashes separately
    show_save_popup: bool,
    save_filename: String,
}

impl App {
    fn new(old_snapshot: Snapshot, new_snapshot: Snapshot, live_mode: bool, monitor: Option<Arc<Mutex<Monitor>>>, navigation_root: PathBuf, log_buffer: Arc<Mutex<Vec<LogEntry>>>) -> Self {
        let current_dir = old_snapshot.root.clone();
        Self {
            old_snapshot,
            new_snapshot,
            current_dir,
            selected: 0,
            show_unchanged: true, // Default to showing all files like a file explorer
            live_mode,
            monitor,
            time_window: 30,
            navigation_root,
            show_hash_popup: false,
            log_buffer,
            show_log: false,
            log_selected: 0,
            sha256_cache: HashMap::new(),
            show_save_popup: false,
            save_filename: String::new(),
        }
    }

    fn cycle_time_window(&mut self) {
        self.time_window = match self.time_window {
            10 => 30,
            30 => 60,
            60 => 300,
            300 => 0,
            _ => 10,
        };
    }

    fn add_log(&self, message: String) {
        add_log_entry(&self.log_buffer, message);
    }

    fn refresh_live_snapshot(&mut self) {
        // Don't refresh every frame - UI doesn't need full snapshot clone
        // The get_filtered_items will fetch what it needs directly from monitor
    }

    fn refresh_full_snapshot(&mut self) {
        // Only use this when we need the full snapshot (e.g., for saving)
        if let Some(ref monitor) = self.monitor {
            let monitor = monitor.lock().unwrap();
            self.new_snapshot = monitor.get_snapshot();
        }
    }

    fn get_filtered_items(&self) -> Vec<DiffNode> {
        // Get all items in the current directory from the new snapshot
        let mut items: Vec<DiffNode> = Vec::new();

        // Get current directory nodes from monitor (fast - only clones ~50 nodes)
        let current_nodes = if let Some(ref monitor_arc) = self.monitor {
            let monitor = monitor_arc.lock().unwrap();
            let (_root, nodes) = monitor.get_directory_snapshot(&self.current_dir);
            nodes
        } else {
            self.new_snapshot.nodes.clone()
        };

        // Collect all files/dirs that are children of current_dir
        for (path, node) in &current_nodes {
            if let Some(parent) = path.parent() {
                if parent == self.current_dir {
                    // Check if this path exists in old snapshot for comparison
                    let old_node = self.old_snapshot.nodes.get(path);

                    let status = if let Some(old) = old_node {
                        if old.hash != node.hash {
                            DiffStatus::Modified
                        } else {
                            #[cfg(unix)]
                            let metadata_changed = old.mode != node.mode
                                || old.uid != node.uid
                                || old.gid != node.gid
                                || old.nlink != node.nlink
                                || old.xattrs_hash != node.xattrs_hash;

                            #[cfg(any(target_os = "macos", target_os = "linux"))]
                            let metadata_changed = metadata_changed || old.flags != node.flags;

                            #[cfg(not(unix))]
                            let metadata_changed = false;

                            if metadata_changed {
                                DiffStatus::PermChanged
                            } else {
                                DiffStatus::Unchanged
                            }
                        }
                    } else {
                        DiffStatus::Added
                    };

                    let mut diff_node = DiffNode {
                        path: path.clone(),
                        old_node: old_node.cloned(),
                        new_node: Some(node.clone()),
                        status,
                        is_dir: node.is_dir,
                        change_time: None,
                    };

                    // Add change time from monitor only if status is not Unchanged
                    // (i.e., the file/dir actually differs from old snapshot)
                    if status != DiffStatus::Unchanged {
                        if let Some(ref monitor_arc) = self.monitor {
                            let monitor = monitor_arc.lock().unwrap();
                            diff_node.change_time = monitor.get_change_time(&diff_node.path);
                        }
                    }

                    items.push(diff_node);
                }
            }
        }

        // Also check for removed items (in old but not in current view)
        for (path, old_node) in &self.old_snapshot.nodes {
            if let Some(parent) = path.parent() {
                if parent == self.current_dir && !current_nodes.contains_key(path) {
                    let mut diff_node = DiffNode {
                        path: path.clone(),
                        old_node: Some(old_node.clone()),
                        new_node: None,
                        status: DiffStatus::Removed,
                        is_dir: old_node.is_dir,
                        change_time: None,
                    };

                    // Always add change time for removed files
                    if let Some(ref monitor_arc) = self.monitor {
                        let monitor = monitor_arc.lock().unwrap();
                        diff_node.change_time = monitor.get_change_time(&diff_node.path);
                    }

                    items.push(diff_node);
                }
            }
        }

        // Check for files that were added and then removed (exist in change_times but nowhere else)
        if let Some(ref monitor_arc) = self.monitor {
            let monitor = monitor_arc.lock().unwrap();
            let change_times = monitor.get_all_change_times();

            for (path, _change_time) in change_times.iter() {
                if let Some(parent) = path.parent() {
                    if parent == self.current_dir
                        && !current_nodes.contains_key(path)
                        && !self.old_snapshot.nodes.contains_key(path)
                    {
                        // This file was added after the initial snapshot and then removed
                        // We don't have old_node or new_node, but we know it was there
                        let diff_node = DiffNode {
                            path: path.clone(),
                            old_node: None,
                            new_node: None,
                            status: DiffStatus::Removed,
                            is_dir: false, // Assume file, could be improved
                            change_time: Some(*_change_time),
                        };

                        // Only add if not already in items
                        if !items.iter().any(|item| item.path == *path) {
                            items.push(diff_node);
                        }
                    }
                }
            }
        }

        // Filter by show_unchanged setting
        let mut items: Vec<_> = items
            .into_iter()
            .filter(|diff| {
                self.show_unchanged || diff.status != DiffStatus::Unchanged
            })
            .collect();

        // Add . and .. entries at the beginning (like a file explorer)
        let mut nav_items = Vec::new();


        // Add . (current directory) - check if it exists in either snapshot
        let current_in_old = self.old_snapshot.nodes.get(&self.current_dir);
        let current_in_new = current_nodes.get(&self.current_dir);

        nav_items.push(DiffNode {
            path: self.current_dir.clone(),
            old_node: current_in_old.cloned(),
            new_node: current_in_new.cloned(),
            status: DiffStatus::Unchanged,
            is_dir: true,
            change_time: None,
        });

        // Add .. (parent directory) only if we're not at the navigation root
        // Also check that parent is not above navigation root
        if let Some(parent) = self.current_dir.parent() {
            // Only add .. if current_dir is below navigation_root
            if self.current_dir != self.navigation_root && parent >= self.navigation_root.as_path() {
                let parent_in_old = self.old_snapshot.nodes.get(parent);
                let parent_in_new = current_nodes.get(parent);

                nav_items.push(DiffNode {
                    path: parent.to_path_buf(),
                    old_node: parent_in_old.cloned(),
                    new_node: parent_in_new.cloned(),
                    status: DiffStatus::Unchanged,
                    is_dir: true,
                    change_time: None,
                });
            }
        }

        items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.path.cmp(&b.path),
        });

        // Prepend navigation items
        nav_items.extend(items);
        nav_items
    }

    fn navigate_into(&mut self) {
        let items = self.get_filtered_items();
        if self.selected < items.len() {
            let item = &items[self.selected];
            if item.is_dir {
                self.current_dir = item.path.clone();
                self.selected = 0;
            }
        }
    }

    fn navigate_up(&mut self) {
        if self.current_dir != self.navigation_root {
            if let Some(parent) = self.current_dir.parent() {
                self.current_dir = parent.to_path_buf();
                self.selected = 0;
            }
        }
    }

    fn compute_hash_for_selected(&mut self) {
        let items = self.get_filtered_items();
        if self.selected < items.len() {
            let item = &items[self.selected];

            if !item.is_dir && item.path.exists() {
                let path = item.path.clone();
                self.add_log(format!("Computing SHA-256 for: {}", path.display()));

                match compute_sha256(&path) {
                    Ok(hash) => {
                        // Store the hash in the separate cache
                        self.sha256_cache.insert(path.clone(), hash.clone());
                        self.add_log(format!("SHA-256 computed: {} = {}", path.display(), hash));
                        self.show_hash_popup = true;
                    }
                    Err(e) => {
                        // Store the error in the cache
                        self.sha256_cache.insert(path.clone(), format!("Error: {}", e));
                        self.add_log(format!("SHA-256 error for {}: {}", path.display(), e));
                        self.show_hash_popup = true;
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn format_mode(mode: u32) -> String {
    let perms = mode & 0o777;
    let suid = if mode & 0o4000 != 0 { "s" } else { "" };
    let sgid = if mode & 0o2000 != 0 { "g" } else { "" };
    let sticky = if mode & 0o1000 != 0 { "t" } else { "" };
    format!("{:o}{}{}{}", perms, suid, sgid, sticky)
}

#[cfg(target_os = "macos")]
fn format_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    // User flags (UF_*)
    if flags & 0x00000001 != 0 { parts.push("nodump"); }
    if flags & 0x00000002 != 0 { parts.push("immutable"); }
    if flags & 0x00000004 != 0 { parts.push("append"); }
    if flags & 0x00000008 != 0 { parts.push("opaque"); }
    if flags & 0x00000020 != 0 { parts.push("compressed"); }
    if flags & 0x00000040 != 0 { parts.push("tracked"); }
    if flags & 0x00008000 != 0 { parts.push("hidden"); }

    // System flags (SF_*)
    if flags & 0x00010000 != 0 { parts.push("archived"); }
    if flags & 0x00020000 != 0 { parts.push("sys-immutable"); }
    if flags & 0x00040000 != 0 { parts.push("sys-append"); }

    if parts.is_empty() {
        format!("0x{:08x}", flags)
    } else {
        format!("0x{:08x} ({})", flags, parts.join(", "))
    }
}

#[cfg(target_os = "linux")]
fn format_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    if flags & 0x00000010 != 0 { parts.push("immutable"); }
    if flags & 0x00000020 != 0 { parts.push("append"); }
    if flags & 0x00000040 != 0 { parts.push("nodump"); }
    if flags & 0x00000080 != 0 { parts.push("noatime"); }
    if flags & 0x00001000 != 0 { parts.push("compr"); }
    if flags & 0x00008000 != 0 { parts.push("sync"); }
    if flags & 0x00010000 != 0 { parts.push("nocomp"); }
    if flags & 0x00040000 != 0 { parts.push("encrypt"); }

    if parts.is_empty() {
        format!("0x{:08x}", flags)
    } else {
        format!("0x{:08x} ({})", flags, parts.join(", "))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn format_flags(flags: u32) -> String {
    format!("0x{:08x}", flags)
}

fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    // Configure rayon thread pool for parallel file verification
    let num_threads = args.threads.unwrap_or_else(|| {
        let cpus = num_cpus::get();
        ((cpus as f64 * 0.9).ceil() as usize).max(1)
    });

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    // Validate argument combinations
    if args.live.is_some() && args.snapshot2.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cannot use snapshot2 with --live mode. Valid usages:\n  \
             1. Compare snapshots: dshow snapshot1 snapshot2\n  \
             2. Live mode: dshow --live /path\n  \
             3. Live with reference: dshow snapshot1 --live /path"
        ));
    }

    let log_buffer = Arc::new(Mutex::new(Vec::new()));

    let (old_snapshot, new_snapshot, live_mode, monitor, has_reference_snapshot) = if let Some(live_path_opt) = &args.live {
        let live_path = live_path_opt.as_ref().map(|s| s.as_str()).unwrap_or("/");
        let root_path = PathBuf::from(live_path).canonicalize()
            .unwrap_or_else(|_| PathBuf::from(live_path));

        let has_ref = args.snapshot1.is_some();

        let reference_snapshot = if let Some(ref snap1) = args.snapshot1 {
            if args.mmap {
                load_snapshot_mmap(snap1)?
            } else {
                load_snapshot(snap1)?
            }
        } else {
            // Create an initial snapshot of the current state
            use diffie::create_snapshot;
            create_snapshot(
                live_path,
                &Vec::new(), // No skip dirs
                args.max_size,
            )?
        };

        let mut critical_paths = get_critical_dirs_in_scope(&root_path, &args.critical);

        // Always watch the root path itself
        if !critical_paths.contains(&root_path) {
            critical_paths.push(root_path.clone());
        }

        let mut monitor = Monitor::new(reference_snapshot.clone(), critical_paths, Some(Arc::clone(&log_buffer)), args.max_size)?;
        monitor.setup_watches(&root_path)?;

        add_log_entry(&log_buffer, format!("Using {} threads for parallel verification", num_threads));

        let monitor_arc = Arc::new(Mutex::new(monitor));
        let monitor_clone = Arc::clone(&monitor_arc);
        let log_clone = Arc::clone(&log_buffer);

        let poll_interval = args.poll_interval;
        thread::spawn(move || {
            let mut poll_counter = 0;
            loop {
                // Check FSEvents/inotify every 100ms for responsive updates
                thread::sleep(Duration::from_millis(100));
                poll_counter += 1;

                // Process inotify/FSEvents - batch processing for efficiency
                let fs_events = {
                    let monitor = monitor_clone.lock().unwrap();
                    monitor.process_events()
                    // Lock automatically released here
                };

                if !fs_events.is_empty() {
                    // Separate events into created/modified vs removed
                    let mut to_update = Vec::new();
                    let mut to_remove = Vec::new();

                    for event in fs_events {
                        match event {
                            FileEvent::Created(path) | FileEvent::Modified(path) => {
                                to_update.push(path);
                            }
                            FileEvent::Removed(path) => {
                                to_remove.push(path);
                            }
                        }
                    }

                    // Batch update all created/modified files at once
                    if !to_update.is_empty() {
                        let results = {
                            let monitor = monitor_clone.lock().unwrap();
                            monitor.update_files_batch(to_update)
                            // Lock automatically released here
                        };

                        if let Ok(results) = results {
                            for (path, updated, _, _, details) in results {
                                if updated {
                                    add_log_entry(&log_clone, format!("Updated ({}): {}", details, path.display()));
                                }
                            }
                        }
                    }

                    // Process removals in batch (lock once for all removals)
                    if !to_remove.is_empty() {
                        let monitor = monitor_clone.lock().unwrap();
                        for path in to_remove {
                            if monitor.remove_file(&path) {
                                add_log_entry(&log_clone, format!("Removed: {}", path.display()));
                            }
                        }
                        // Lock automatically released here
                    }
                }

                // Only do expensive polling operations every poll_interval seconds
                if poll_counter * 100 < poll_interval * 1000 {
                    continue;
                }
                poll_counter = 0;

                // Run expensive polling operations in background thread
                let monitor_bg = Arc::clone(&monitor_clone);
                let log_bg = Arc::clone(&log_clone);
                thread::spawn(move || {
                    let poll_start = std::time::Instant::now();

                    // Verify all files by re-hashing and comparing metadata
                    let changed_files = {
                        let monitor = monitor_bg.lock().unwrap();
                        monitor.verify_all_files()
                    };

                    if let Ok(changed_files) = changed_files {
                        let total_files = changed_files.len();
                        if total_files > 0 {
                            add_log_entry(&log_bg, format!("Verify found {} changed files", total_files));

                            // Batch update all changed files - locks only once!
                            let monitor = monitor_bg.lock().unwrap();
                            let results = monitor.update_files_batch(changed_files);
                            drop(monitor);

                            if let Ok(results) = results {
                                for (path, updated, _, _, details) in results {
                                    if updated {
                                        add_log_entry(&log_bg, format!("Updated ({}): {}", details, path.display()));
                                    }
                                }
                            }
                        }
                    }

                    let new_files = {
                        let monitor = monitor_bg.lock().unwrap();
                        monitor.scan_for_new_files()
                    };

                    if let Ok(new_files) = new_files {
                        if !new_files.is_empty() {
                            add_log_entry(&log_bg, format!("Found {} new files", new_files.len()));

                            // Batch update all new files - locks only once!
                            let monitor = monitor_bg.lock().unwrap();
                            let results = monitor.update_files_batch(new_files);
                            drop(monitor);

                            if let Ok(results) = results {
                                for (path, updated, _, _, details) in results {
                                    if updated {
                                        add_log_entry(&log_bg, format!("New file ({}): {}", details, path.display()));
                                    }
                                }
                            }
                        }
                    }

                    // Clean up old change_times entries (keep last 24 hours)
                    {
                        let monitor = monitor_bg.lock().unwrap();
                        monitor.cleanup_old_change_times(86400); // 24 hours
                    }

                    let poll_duration = poll_start.elapsed();
                    add_log_entry(&log_bg, format!("Poll cycle completed in {:.2}s", poll_duration.as_secs_f64()));
                });
            }
        });

        let current_snapshot = {
            let m = monitor_arc.lock().unwrap();
            m.get_snapshot()
        };

        (reference_snapshot, current_snapshot, true, Some(monitor_arc), has_ref)
    } else {
        let snapshot1 = args.snapshot1.as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Must provide snapshot1 or --live"))?;
        let snapshot2 = args.snapshot2.as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Must provide snapshot2 or --live"))?;

        let old_snapshot = if args.mmap {
            load_snapshot_mmap(snapshot1)?
        } else {
            load_snapshot(snapshot1)?
        };
        let new_snapshot = if args.mmap {
            load_snapshot_mmap(snapshot2)?
        } else {
            load_snapshot(snapshot2)?
        };

        // Determine the overlapping scope for comparison
        // Only compare files within the narrower of the two snapshot roots
        let compare_scope = if new_snapshot.root.starts_with(&old_snapshot.root) {
            // new is subset of old (e.g., old=/, new=/etc) - compare only /etc
            new_snapshot.root.clone()
        } else if old_snapshot.root.starts_with(&new_snapshot.root) {
            // old is subset of new (e.g., old=/etc, new=/) - compare only /etc
            old_snapshot.root.clone()
        } else {
            // Different paths - use new snapshot's root
            new_snapshot.root.clone()
        };

        // Populate log with all changes between snapshots (only within compare_scope)
        for (path, new_node) in &new_snapshot.nodes {
            if !path.starts_with(&compare_scope) {
                continue; // Skip files outside comparison scope
            }

            if let Some(old_node) = old_snapshot.nodes.get(path) {
                // File exists in both - check what changed
                let mut changes = Vec::new();

                if old_node.hash != new_node.hash {
                    changes.push("content");
                }

                #[cfg(unix)]
                {
                    if old_node.mode != new_node.mode {
                        changes.push("mode");
                    }
                    if old_node.uid != new_node.uid {
                        changes.push("uid");
                    }
                    if old_node.gid != new_node.gid {
                        changes.push("gid");
                    }
                    if old_node.nlink != new_node.nlink {
                        changes.push("nlink");
                    }
                    if old_node.mtime != new_node.mtime {
                        changes.push("mtime");
                    }
                    if old_node.xattrs_hash != new_node.xattrs_hash {
                        changes.push("xattrs");
                    }
                }

                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    if old_node.flags != new_node.flags {
                        changes.push("flags");
                    }
                }

                if !changes.is_empty() {
                    let details = changes.join("+");
                    add_log_entry(&log_buffer, format!("Modified ({}): {}", details, path.display()));
                }
            } else {
                // New file (exists in new but not old)
                add_log_entry(&log_buffer, format!("Added: {}", path.display()));
            }
        }

        // Check for removed files (exists in old but not new, within compare scope)
        for (path, _old_node) in &old_snapshot.nodes {
            if !path.starts_with(&compare_scope) {
                continue; // Skip files outside comparison scope
            }
            if !new_snapshot.nodes.contains_key(path) {
                add_log_entry(&log_buffer, format!("Removed: {}", path.display()));
            }
        }

        (old_snapshot, new_snapshot, false, None, true)
    };

    // Determine navigation root based on context
    let navigation_root = if live_mode && !has_reference_snapshot {
        // Pure live mode: use the live path as the navigation root
        if let Some(live_path_opt) = &args.live {
            let live_path = live_path_opt.as_ref().map(|s| s.as_str()).unwrap_or("/");
            PathBuf::from(live_path).canonicalize()
                .unwrap_or_else(|_| PathBuf::from(live_path))
        } else {
            old_snapshot.root.clone()
        }
    } else {
        // Comparing snapshots: find the common ancestor or use the higher-level root
        let mut root = old_snapshot.root.clone();
        if new_snapshot.root.starts_with(&old_snapshot.root) {
            root = old_snapshot.root.clone();
        } else if old_snapshot.root.starts_with(&new_snapshot.root) {
            root = new_snapshot.root.clone();
        } else {
            // Find common ancestor
            let mut old_ancestors: Vec<PathBuf> = Vec::new();
            let mut current = Some(old_snapshot.root.as_path());
            while let Some(p) = current {
                old_ancestors.push(p.to_path_buf());
                current = p.parent();
            }

            let mut new_current = Some(new_snapshot.root.as_path());
            while let Some(p) = new_current {
                if old_ancestors.contains(&p.to_path_buf()) {
                    root = p.to_path_buf();
                    break;
                }
                new_current = p.parent();
            }
        }
        root
    };

    // Brief mode: just print logs to stdout (either requested or if TUI fails)
    let terminal_result = if !args.brief {
        enable_raw_mode()
            .and_then(|_| {
                let mut stdout = io::stdout();
                execute!(stdout, EnterAlternateScreen)?;
                let backend = CrosstermBackend::new(stdout);
                Terminal::new(backend)
            })
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Brief mode requested"))
    };

    let mut terminal = match terminal_result {
        Ok(term) => term,
        Err(e) => {
            // Brief mode or TUI failed to launch - print logs to stdout instead
            if !args.brief {
                eprintln!("Warning: Could not initialize TUI: {}", e);
                eprintln!("Printing changes to stdout instead:\n");
            }

            let log = log_buffer.lock().unwrap();
            if log.is_empty() {
                println!("No changes detected.");
            } else {
                for entry in log.iter() {
                    let time_str = jiff::Timestamp::from_second(entry.timestamp)
                        .ok()
                        .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| format!("{}", entry.timestamp));
                    println!("[{}] {}", time_str, entry.message);
                }
            }

            return Ok(());
        }
    };

    let mut app = App::new(old_snapshot, new_snapshot, live_mode, monitor, navigation_root, log_buffer);
    let persist = args.persist;
    let snapshot1_path = args.snapshot1.clone();

    loop {
        if app.live_mode {
            app.refresh_live_snapshot();
        }

        let items = app.get_filtered_items();

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(0), Constraint::Length(15)])
                .split(f.area());

            let now = jiff::Timestamp::now().as_second();

            let list_items: Vec<ListItem> = items
                .iter()
                .map(|diff| {
                    // Handle . and .. entries
                    let filename = if diff.path == app.current_dir {
                        ".".to_string()
                    } else if app.current_dir.parent().is_some() && diff.path == app.current_dir.parent().unwrap() {
                        "..".to_string()
                    } else {
                        diff.path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "/".to_string())
                    };

                    let prefix = if diff.is_dir { "📁 " } else { "📄 " };

                    let is_recent = if let Some(change_time) = diff.change_time {
                        app.time_window == 0 || (now - change_time) <= app.time_window
                    } else {
                        false
                    };

                    let recent_badge = if is_recent { " ⚡" } else { "" };

                    let (text, mut style) = match &diff.status {
                        DiffStatus::Added => (
                            format!("{}{} [+]{}", prefix, filename, recent_badge),
                            if is_recent {
                                Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                            },
                        ),
                        DiffStatus::Removed => (
                            format!("{}{} [-]{}", prefix, filename, recent_badge),
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                        DiffStatus::Modified => (
                            format!("{}{} [~]{}", prefix, filename, recent_badge),
                            if is_recent {
                                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                            },
                        ),
                        DiffStatus::PermChanged => (
                            format!("{}{} [p]{}", prefix, filename, recent_badge),
                            if is_recent {
                                Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
                            },
                        ),
                        DiffStatus::Unchanged => (
                            format!("{}{}", prefix, filename),
                            Style::default().fg(Color::Gray),
                        ),
                    };

                    #[cfg(unix)]
                    {
                        if diff.has_suid_change() || diff.has_sgid_change() {
                            style = Style::default()
                                .fg(Color::Red)
                                .bg(Color::Yellow)
                                .add_modifier(Modifier::BOLD);
                        }
                    }

                    ListItem::new(text).style(style)
                })
                .collect();

            let time_window_str = match app.time_window {
                0 => "all".to_string(),
                n if n < 60 => format!("{}s", n),
                n => format!("{}m", n / 60),
            };

            let current_dir_display = if app.current_dir == app.old_snapshot.root {
                format!("{} (root)", app.current_dir.display())
            } else {
                app.current_dir.display().to_string()
            };

            let title = if app.live_mode {
                format!(
                    "📂 {} | {} items | LIVE ⚡ {} | [t]ime:{} [↵]enter [←/backspace]up [s]ave [h]ash [l]og [u]nchanged [q/^C]uit",
                    current_dir_display,
                    items.len(),
                    if items.iter().any(|d| d.change_time.is_some()) { "monitoring" } else { "waiting" },
                    time_window_str
                )
            } else {
                format!(
                    "📂 {} | {} items | [↵]enter [←/backspace]up [h]ash [l]og [u]nchanged [q/^C]uit",
                    current_dir_display,
                    items.len()
                )
            };

            let list = List::new(list_items)
                .block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL),
                )
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                );

            f.render_stateful_widget(
                list,
                chunks[0],
                &mut ratatui::widgets::ListState::default().with_selected(Some(app.selected)),
            );

            let mut detail_lines = Vec::new();

            if app.selected < items.len() {
                let diff = &items[app.selected];

                detail_lines.push(Line::from(vec![
                    Span::styled("Path: ", Style::default().fg(Color::Cyan)),
                    Span::raw(diff.path.display().to_string()),
                ]));

                #[cfg(unix)]
                {
                    if let Some(old) = &diff.old_node {
                        let mtime_readable = jiff::Timestamp::from_second(old.mtime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", old.mtime));
                        let atime_readable = jiff::Timestamp::from_second(old.atime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", old.atime));
                        let ctime_readable = jiff::Timestamp::from_second(old.ctime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", old.ctime));

                        detail_lines.push(Line::from(vec![
                            Span::styled("OLD: ", Style::default().fg(Color::Yellow)),
                            Span::raw(format!(
                                "uid:{} gid:{} mode:{} size:{} nlink:{}",
                                old.uid,
                                old.gid,
                                format_mode(old.mode),
                                old.size,
                                old.nlink
                            )),
                        ]));
                        detail_lines.push(Line::from(vec![
                            Span::raw(format!(
                                "     mtime:{} atime:{} ctime:{}",
                                mtime_readable,
                                atime_readable,
                                ctime_readable
                            )),
                        ]));
                        #[cfg(any(target_os = "macos", target_os = "linux"))]
                        detail_lines.push(Line::from(vec![
                            Span::raw(format!("     flags:{}", format_flags(old.flags))),
                        ]));
                        if old.xattrs_hash != 0 {
                            let xattr_keys = get_xattrs_keys(&diff.path);
                            if !xattr_keys.is_empty() {
                                detail_lines.push(Line::from(vec![
                                    Span::raw(format!("     xattrs: {}", xattr_keys.join(", "))),
                                ]));
                            } else {
                                detail_lines.push(Line::from(vec![
                                    Span::raw(format!("     xattrs_hash: {:016x}", old.xattrs_hash)),
                                ]));
                            }
                        }
                    }

                    if let Some(new) = &diff.new_node {
                        let mtime_readable = jiff::Timestamp::from_second(new.mtime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", new.mtime));
                        let atime_readable = jiff::Timestamp::from_second(new.atime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", new.atime));
                        let ctime_readable = jiff::Timestamp::from_second(new.ctime)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", new.ctime));

                        detail_lines.push(Line::from(vec![
                            Span::styled("NEW: ", Style::default().fg(Color::Green)),
                            Span::raw(format!(
                                "uid:{} gid:{} mode:{} size:{} nlink:{}",
                                new.uid,
                                new.gid,
                                format_mode(new.mode),
                                new.size,
                                new.nlink
                            )),
                        ]));
                        detail_lines.push(Line::from(vec![
                            Span::raw(format!(
                                "     mtime:{} atime:{} ctime:{}",
                                mtime_readable,
                                atime_readable,
                                ctime_readable
                            )),
                        ]));
                        #[cfg(any(target_os = "macos", target_os = "linux"))]
                        detail_lines.push(Line::from(vec![
                            Span::raw(format!("     flags:{}", format_flags(new.flags))),
                        ]));
                        if new.xattrs_hash != 0 {
                            let xattr_keys = get_xattrs_keys(&diff.path);
                            if !xattr_keys.is_empty() {
                                detail_lines.push(Line::from(vec![
                                    Span::raw(format!("     xattrs: {}", xattr_keys.join(", "))),
                                ]));
                            } else {
                                detail_lines.push(Line::from(vec![
                                    Span::raw(format!("     xattrs_hash: {:016x}", new.xattrs_hash)),
                                ]));
                            }
                        }
                        if !new.is_dir {
                            if let Some(sha256) = app.sha256_cache.get(&diff.path) {
                                detail_lines.push(Line::from(vec![
                                    Span::raw(format!("     sha256:{}", sha256)),
                                ]));
                            }
                        }
                    }
                }
            }

            let detail = Paragraph::new(detail_lines)
                .block(
                    Block::default()
                        .title("Details")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: true });

            f.render_widget(detail, chunks[1]);

            // Render hash popup overlay if enabled
            if app.show_hash_popup {
                let popup_width = 70u16.min(f.area().width.saturating_sub(6));
                let popup_height = 8u16.min(f.area().height.saturating_sub(6));

                let popup_area = ratatui::layout::Rect {
                    x: (f.area().width.saturating_sub(popup_width)) / 2,
                    y: (f.area().height.saturating_sub(popup_height)) / 2,
                    width: popup_width,
                    height: popup_height,
                };

                let items = app.get_filtered_items();
                let selected_file = if app.selected < items.len() {
                    items[app.selected].path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                let mut popup_lines = vec![
                    Line::from(vec![
                        Span::styled("File: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::raw(selected_file),
                    ]),
                    Line::from(""),
                ];

                if app.selected < items.len() {
                    let item_path = &items[app.selected].path;
                    if let Some(hash) = app.sha256_cache.get(item_path) {
                        popup_lines.push(Line::from(vec![
                            Span::styled("SHA256:", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                        ]));
                        popup_lines.push(Line::from(Span::raw(hash.clone())));
                    }
                }

                popup_lines.push(Line::from(""));
                popup_lines.push(Line::from(vec![
                    Span::styled("[Press any key to close]", Style::default().fg(Color::DarkGray)),
                ]));

                let popup = Paragraph::new(popup_lines)
                    .block(
                        Block::default()
                            .title("SHA256 Hash")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                            .style(Style::default().bg(Color::Black))
                    )
                    .wrap(Wrap { trim: false })
                    .alignment(Alignment::Left);

                f.render_widget(Clear, popup_area);
                f.render_widget(popup, popup_area);
            }

            // Render log overlay if enabled
            if app.show_log {
                let popup_width = f.area().width.saturating_sub(4);
                let popup_height = f.area().height.saturating_sub(4);

                let popup_area = ratatui::layout::Rect {
                    x: (f.area().width.saturating_sub(popup_width)) / 2,
                    y: (f.area().height.saturating_sub(popup_height)) / 2,
                    width: popup_width,
                    height: popup_height,
                };

                let log = app.log_buffer.lock().unwrap();
                let log_items: Vec<ListItem> = log
                    .iter()
                    .rev() // Most recent first
                    .map(|entry| {
                        let time_str = jiff::Timestamp::from_second(entry.timestamp)
                            .ok()
                            .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{}", entry.timestamp));

                        let text = format!("[{}] {}", time_str, entry.message);
                        ListItem::new(text).style(Style::default().fg(Color::White))
                    })
                    .collect();
                drop(log);

                let log_list = List::new(log_items)
                    .block(
                        Block::default()
                            .title("Activity Log [↵]goto [PgUp/PgDn]scroll [j/k]navigate [l]close [q/^C]quit")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                            .style(Style::default().bg(Color::Black))
                    )
                    .highlight_style(
                        Style::default()
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    );

                f.render_widget(Clear, popup_area);
                f.render_stateful_widget(
                    log_list,
                    popup_area,
                    &mut ratatui::widgets::ListState::default().with_selected(Some(app.log_selected)),
                );
            }

            // Render save popup if enabled
            if app.show_save_popup {
                let popup_width = 60u16.min(f.area().width.saturating_sub(6));
                let popup_height = 7u16;

                let popup_area = ratatui::layout::Rect {
                    x: (f.area().width.saturating_sub(popup_width)) / 2,
                    y: (f.area().height.saturating_sub(popup_height)) / 2,
                    width: popup_width,
                    height: popup_height,
                };

                let popup_lines = vec![
                    Line::from(vec![
                        Span::styled("Enter filename to save snapshot:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::raw(&app.save_filename),
                        Span::styled("█", Style::default().fg(Color::White)),  // Cursor
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("[Enter]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                        Span::raw(" Save  "),
                        Span::styled("[Esc]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                        Span::raw(" Cancel"),
                    ]),
                ];

                let popup = Paragraph::new(popup_lines)
                    .block(
                        Block::default()
                            .title("Save Snapshot")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                            .style(Style::default().bg(Color::Black))
                    )
                    .alignment(Alignment::Left);

                f.render_widget(Clear, popup_area);
                f.render_widget(popup, popup_area);
            }
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // If hash popup is showing, close it on any key press
                if app.show_hash_popup {
                    app.show_hash_popup = false;
                    continue;
                }

                // If save popup is showing, handle text input
                if app.show_save_popup {
                    match key.code {
                        KeyCode::Enter => {
                            // Save the file
                            let save_path = app.save_filename.clone();
                            app.show_save_popup = false;

                            // Refresh full snapshot before saving
                            app.refresh_full_snapshot();

                            app.add_log(format!("Saving snapshot to: {}", save_path));
                            match save_snapshot(&app.new_snapshot, &save_path) {
                                Ok(_) => {
                                    app.add_log(format!("Snapshot saved successfully to: {}", save_path));
                                }
                                Err(e) => {
                                    app.add_log(format!("Error saving snapshot: {}", e));
                                }
                            }
                        }
                        KeyCode::Esc => {
                            // Cancel save
                            app.show_save_popup = false;
                            app.save_filename.clear();
                        }
                        KeyCode::Backspace => {
                            app.save_filename.pop();
                        }
                        KeyCode::Char(c) => {
                            app.save_filename.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                // If log is showing, handle log-specific navigation
                if app.show_log {
                    match key.code {
                        KeyCode::Char('l') | KeyCode::Char('L') => {
                            app.show_log = false;
                            app.log_selected = 0;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let log = app.log_buffer.lock().unwrap();
                            let max_idx = log.len().saturating_sub(1);
                            drop(log);
                            app.log_selected = (app.log_selected + 1).min(max_idx);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.log_selected = app.log_selected.saturating_sub(1);
                        }
                        KeyCode::PageDown => {
                            let log = app.log_buffer.lock().unwrap();
                            let max_idx = log.len().saturating_sub(1);
                            drop(log);
                            app.log_selected = (app.log_selected + 10).min(max_idx);
                        }
                        KeyCode::PageUp => {
                            app.log_selected = app.log_selected.saturating_sub(10);
                        }
                        KeyCode::Enter => {
                            // Try to extract file path from selected log entry and navigate to it
                            let path_to_navigate = {
                                let log = app.log_buffer.lock().unwrap();
                                if app.log_selected < log.len() {
                                    let entry = &log[log.len() - 1 - app.log_selected]; // Reversed list
                                    let message = &entry.message;

                                    // Extract path from messages like "Created: /path/to/file" or "Modified: /path"
                                    let path_str = if let Some(colon_pos) = message.find(':') {
                                        message[colon_pos + 1..].trim()
                                    } else {
                                        ""
                                    };

                                    if !path_str.is_empty() {
                                        let path = PathBuf::from(path_str);
                                        // Get parent directory if it's a file
                                        path.parent().map(|p| p.to_path_buf())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            };

                            // Navigate if we found a valid path
                            if let Some(parent) = path_to_navigate {
                                if parent.starts_with(&app.navigation_root) {
                                    app.current_dir = parent;
                                    app.selected = 0;
                                    app.show_log = false;
                                    app.log_selected = 0;
                                }
                            }
                        }
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        app.show_log = !app.show_log;
                        app.log_selected = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.selected = (app.selected + 1).min(items.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected = app.selected.saturating_sub(1);
                    }
                    KeyCode::Enter | KeyCode::Right => {
                        app.navigate_into();
                    }
                    KeyCode::Backspace | KeyCode::Left => {
                        app.navigate_up();
                    }
                    KeyCode::Char('h') | KeyCode::Char('H') => {
                        app.compute_hash_for_selected();
                    }
                    KeyCode::Char('u') | KeyCode::Char('U') => {
                        app.show_unchanged = !app.show_unchanged;
                        app.selected = 0;
                    }
                    KeyCode::Char('t') | KeyCode::Char('T') => {
                        app.cycle_time_window();
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        if app.live_mode {
                            // Show save popup with default filename
                            let default_filename = if persist {
                                snapshot1_path.clone().unwrap_or_else(|| "snapshot.snap".to_string())
                            } else {
                                let now = jiff::Zoned::now();
                                format!("snapshot-{}.snap", now.strftime("%Y%m%d-%H%M%S"))
                            };
                            app.save_filename = default_filename;
                            app.show_save_popup = true;
                        }
                    }
                    _ => {}
                }
            }
        } else if app.live_mode {
            thread::sleep(Duration::from_millis(500));
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}

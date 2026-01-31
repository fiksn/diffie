use clap::Parser;
use diffie::{
    get_critical_dirs_in_scope, load_snapshot, load_snapshot_mmap,
    monitor::{Monitor, FileEvent}, DEFAULT_CRITICAL_DIRS,
};
use glob::Pattern;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "dwatch")]
#[command(about = "Watch files for changes and alert to stdout", long_about = None)]
struct Args {
    #[arg(help = "Reference snapshot file")]
    snapshot: String,

    #[arg(help = "Directory to monitor")]
    path: String,

    #[arg(long, default_value = "30", help = "Polling interval in seconds for full verification")]
    poll_interval: u64,

    #[arg(
        long,
        value_name = "DIR",
        num_args = 0..,
        default_values = DEFAULT_CRITICAL_DIRS,
        help = "Critical directories to watch with inotify/FSEvents"
    )]
    critical: Vec<String>,

    #[arg(long, default_value = "150", help = "Maximum file size in MB to include")]
    max_size: u64,

    #[arg(long, help = "Number of threads for parallel verification (default: 90% of CPU cores)")]
    threads: Option<usize>,

    #[arg(long, help = "Ignore changes to files matching these glob patterns (can be specified multiple times, e.g., '*.log', '/tmp/**')")]
    ignore_file: Vec<String>,

    #[arg(long, help = "Ignore changes to files in these directories (supports glob patterns, can be specified multiple times, e.g., '/var/cache', '/tmp/**')")]
    ignore_dir: Vec<String>,

    #[arg(long, help = "Save updated snapshot to this file on exit (SIGTERM/SIGINT)")]
    save_on_exit: Option<String>,

    #[arg(long, help = "Suppress informational messages, only output changes")]
    quiet: bool,

    #[arg(long, help = "Use memory-mapped file loading for large snapshots (reduces memory usage)")]
    mmap: bool,

    #[arg(long, value_name = "SECONDS", help = "Debounce time in seconds - only alert if file unchanged for this duration (reduces noise for frequently changing files)")]
    debounce: Option<u64>,

    #[arg(long, help = "Disable periodic polling/scanning - rely only on inotify/FSEvents (faster but may miss changes outside watched directories)")]
    no_scan: bool,
}

struct IgnoreFilter {
    file_patterns: Vec<Pattern>,
    dir_patterns: Vec<Pattern>,
}

impl IgnoreFilter {
    fn new(ignore_files: Vec<String>, ignore_dirs: Vec<String>) -> Self {
        let file_patterns = ignore_files
            .into_iter()
            .filter_map(|s| {
                Pattern::new(&s).map_err(|e| {
                    eprintln!("[WARN] Invalid file pattern '{}': {}", s, e);
                    e
                }).ok()
            })
            .collect();

        let dir_patterns = ignore_dirs
            .into_iter()
            .filter_map(|s| {
                Pattern::new(&s).map_err(|e| {
                    eprintln!("[WARN] Invalid directory pattern '{}': {}", s, e);
                    e
                }).ok()
            })
            .collect();

        Self {
            file_patterns,
            dir_patterns,
        }
    }

    fn should_ignore(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check if path matches any file glob pattern
        if self.file_patterns.iter().any(|p| p.matches(&path_str)) {
            return true;
        }

        // Check if path is within any directory pattern
        for dir_pattern in &self.dir_patterns {
            // Try exact match first
            if dir_pattern.matches(&path_str) {
                return true;
            }

            // Check if path starts with the directory
            // Convert glob pattern to prefix check
            let pattern_str = dir_pattern.as_str();
            // Remove trailing wildcards for prefix matching
            let prefix = pattern_str.trim_end_matches("**").trim_end_matches('*');
            if path_str.starts_with(prefix) {
                return true;
            }
        }

        false
    }
}

struct DebounceTracker {
    pending: HashMap<PathBuf, (Instant, String)>,  // path -> (last_change_time, details)
    debounce_duration: Duration,
}

impl DebounceTracker {
    fn new(debounce_seconds: u64) -> Self {
        Self {
            pending: HashMap::new(),
            debounce_duration: Duration::from_secs(debounce_seconds),
        }
    }

    /// Record a change. Returns true if we should alert now (no debounce)
    fn record_change(&mut self, path: PathBuf, details: String) -> bool {
        self.pending.insert(path, (Instant::now(), details));
        false  // Don't alert immediately when debouncing
    }

    /// Get changes that have been stable for debounce_duration
    fn get_stable_changes(&mut self) -> Vec<(PathBuf, String)> {
        let now = Instant::now();
        let debounce_duration = self.debounce_duration;

        let stable: Vec<(PathBuf, String)> = self.pending
            .iter()
            .filter(|(_, (last_change, _))| now.duration_since(*last_change) >= debounce_duration)
            .map(|(path, (_, details))| (path.clone(), details.clone()))
            .collect();

        // Remove stable entries
        for (path, _) in &stable {
            self.pending.remove(path);
        }

        stable
    }
}

fn output_change(path: &Path, details: &str, filter: &IgnoreFilter, _quiet: bool) {
    if filter.should_ignore(path) {
        return;
    }

    println!("{}: {}", path.display(), details);
    io::stdout().flush().unwrap();
}

fn output_info(message: &str, quiet: bool) {
    if !quiet {
        eprintln!("[INFO] {}", message);
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // Configure thread pool
    let num_threads = args.threads.unwrap_or_else(|| {
        let cores = num_cpus::get();
        (cores as f64 * 0.9).ceil() as usize
    });
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    let root_path = PathBuf::from(&args.path).canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&args.path));

    output_info(&format!("Loading reference snapshot: {}", args.snapshot), args.quiet);
    let reference_snapshot = if args.mmap {
        output_info("Using memory-mapped loading", args.quiet);
        load_snapshot_mmap(&args.snapshot)?
    } else {
        load_snapshot(&args.snapshot)?
    };

    output_info(&format!("Monitoring: {}", root_path.display()), args.quiet);
    output_info(&format!("Using {} threads for verification", num_threads), args.quiet);

    let mut critical_paths = get_critical_dirs_in_scope(&root_path, &args.critical);

    // Always watch the root path itself
    if !critical_paths.contains(&root_path) {
        critical_paths.push(root_path.clone());
    }

    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let mut monitor = Monitor::new(
        reference_snapshot.clone(),
        critical_paths,
        Some(Arc::clone(&log_buffer)),
        args.max_size
    )?;
    monitor.setup_watches(&root_path)?;

    // Check if watch budget was exceeded and warn the user
    let (watches_used, watch_budget, watched_dirs) = monitor.get_watch_stats();
    if monitor.is_watch_budget_exceeded() {
        eprintln!("⚠️  WARNING: inotify/FSEvents watch budget exceeded! ({}/{} watches used)", watches_used, watch_budget);
        eprintln!("Only {} directories are being watched", watched_dirs);

        if args.no_scan {
            eprintln!("⚠️  --no-scan enabled but not all directories can be watched!");
            eprintln!("Changes in unwatched directories will NOT be detected!");
            eprintln!("Consider removing --no-scan or increasing inotify limits.");
        } else {
            eprintln!("Periodic polling will catch changes in unwatched directories.");
        }
    } else if args.no_scan {
        output_info(&format!("--no-scan enabled: relying only on inotify/FSEvents ({}/{} watches)", watches_used, watch_budget), args.quiet);
    }

    output_info("Watch setup complete", args.quiet);
    output_info(&format!("Poll interval: {}s", args.poll_interval), args.quiet);

    if let Some(debounce_secs) = args.debounce {
        output_info(&format!("Debounce: {}s", debounce_secs), args.quiet);
    }

    // Setup signal handling for graceful shutdown
    let running = Arc::new(Mutex::new(true));
    let running_clone = Arc::clone(&running);
    let running_signal = Arc::clone(&running);

    ctrlc::set_handler(move || {
        let mut r = running_signal.lock().unwrap();
        *r = false;
    }).expect("Error setting Ctrl-C handler");

    let monitor_arc = Arc::new(Mutex::new(monitor));
    let monitor_clone = Arc::clone(&monitor_arc);
    let poll_interval = args.poll_interval;
    let quiet = args.quiet;
    let debounce_opt = args.debounce;
    let no_scan = args.no_scan;

    // Spawn monitoring thread
    let ignore_filter_clone = IgnoreFilter::new(
        args.ignore_file.clone(),
        args.ignore_dir.clone()
    );

    thread::spawn(move || {
        let mut poll_counter = 0;
        let mut debounce_tracker = debounce_opt.map(DebounceTracker::new);

        loop {
            // Check if we should exit
            {
                let r = running.lock().unwrap();
                if !*r {
                    break;
                }
            }

            thread::sleep(Duration::from_millis(100));
            poll_counter += 1;

            // Process FSEvents/inotify every 100ms
            let fs_events = {
                let monitor = monitor_clone.lock().unwrap();
                monitor.process_events()
            };

            if !fs_events.is_empty() {
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

                // Batch update
                if !to_update.is_empty() {
                    let results = {
                        let monitor = monitor_clone.lock().unwrap();
                        monitor.update_files_batch(to_update)
                    };

                    if let Ok(results) = results {
                        for (path, updated, _, _, details) in results {
                            if updated && !details.is_empty() {
                                if let Some(ref mut tracker) = debounce_tracker {
                                    // Record change, don't output yet
                                    tracker.record_change(path, details);
                                } else {
                                    // No debounce, output immediately
                                    output_change(&path, &details, &ignore_filter_clone, quiet);
                                }
                            }
                        }
                    }
                }

                // Process removals (no debounce for removals - always immediate)
                if !to_remove.is_empty() {
                    let monitor = monitor_clone.lock().unwrap();
                    for path in to_remove {
                        if monitor.remove_file(&path) {
                            output_change(&path, "removed", &ignore_filter_clone, quiet);
                        }
                    }
                }

                // Check for stable changes (debounce)
                if let Some(ref mut tracker) = debounce_tracker {
                    for (path, details) in tracker.get_stable_changes() {
                        output_change(&path, &details, &ignore_filter_clone, quiet);
                    }
                }
            }

            // Full verification every poll_interval seconds
            // Skip if --no-scan is enabled
            if no_scan || poll_counter * 100 < poll_interval * 1000 {
                continue;
            }
            poll_counter = 0;

            // Verify all files
            let changed_files = {
                let monitor = monitor_clone.lock().unwrap();
                monitor.verify_all_files()
            };

            if let Ok(changed_files) = changed_files {
                if !changed_files.is_empty() && !quiet {
                    eprintln!("[INFO] Verification found {} changed files", changed_files.len());
                }

                if !changed_files.is_empty() {
                    let results = {
                        let monitor = monitor_clone.lock().unwrap();
                        monitor.update_files_batch(changed_files)
                    };

                    if let Ok(results) = results {
                        for (path, updated, _, _, details) in results {
                            if updated && !details.is_empty() {
                                if let Some(ref mut tracker) = debounce_tracker {
                                    tracker.record_change(path, details);
                                } else {
                                    output_change(&path, &details, &ignore_filter_clone, quiet);
                                }
                            }
                        }
                    }
                }
            }

            // Scan for new files
            let new_files = {
                let monitor = monitor_clone.lock().unwrap();
                monitor.scan_for_new_files()
            };

            if let Ok(new_files) = new_files {
                if !new_files.is_empty() && !quiet {
                    eprintln!("[INFO] Found {} new files", new_files.len());
                }

                if !new_files.is_empty() {
                    let results = {
                        let monitor = monitor_clone.lock().unwrap();
                        monitor.update_files_batch(new_files)
                    };

                    if let Ok(results) = results {
                        for (path, updated, _, _, details) in results {
                            if updated && !details.is_empty() {
                                if let Some(ref mut tracker) = debounce_tracker {
                                    tracker.record_change(path, details);
                                } else {
                                    output_change(&path, &details, &ignore_filter_clone, quiet);
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup old change times
            {
                let monitor = monitor_clone.lock().unwrap();
                monitor.cleanup_old_change_times(86400);
            }
        }
    });

    // Main thread waits for signal
    loop {
        thread::sleep(Duration::from_millis(500));

        let r = running_clone.lock().unwrap();
        if !*r {
            break;
        }
    }

    output_info("Received shutdown signal", args.quiet);

    // Save snapshot on exit if requested
    if let Some(save_path) = args.save_on_exit {
        output_info(&format!("Saving snapshot to: {}", save_path), args.quiet);
        let monitor = monitor_arc.lock().unwrap();
        let snapshot = monitor.get_snapshot();
        diffie::save_snapshot(&snapshot, &save_path)?;
        output_info("Snapshot saved", args.quiet);
    }

    output_info("Shutdown complete", args.quiet);
    Ok(())
}

use clap::Parser;
use diffie::{
    get_critical_dirs_in_scope, load_snapshot,
    monitor::{Monitor, FileEvent}, DEFAULT_CRITICAL_DIRS,
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

    #[arg(long, help = "Ignore changes to files matching these paths (can be specified multiple times)")]
    ignore_file: Vec<String>,

    #[arg(long, help = "Ignore changes to files in these directories (can be specified multiple times)")]
    ignore_dir: Vec<String>,

    #[arg(long, help = "Save updated snapshot to this file on exit (SIGTERM/SIGINT)")]
    save_on_exit: Option<String>,

    #[arg(long, help = "Suppress informational messages, only output changes")]
    quiet: bool,
}

struct IgnoreFilter {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl IgnoreFilter {
    fn new(ignore_files: Vec<String>, ignore_dirs: Vec<String>) -> Self {
        Self {
            files: ignore_files.into_iter().map(PathBuf::from).collect(),
            dirs: ignore_dirs.into_iter().map(PathBuf::from).collect(),
        }
    }

    fn should_ignore(&self, path: &Path) -> bool {
        // Check if path exactly matches an ignored file
        if self.files.iter().any(|f| path == f) {
            return true;
        }

        // Check if path is within an ignored directory
        for ignored_dir in &self.dirs {
            if path.starts_with(ignored_dir) {
                return true;
            }
        }

        false
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
    let reference_snapshot = load_snapshot(&args.snapshot)?;

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

    output_info("Watch setup complete", args.quiet);
    output_info(&format!("Poll interval: {}s", args.poll_interval), args.quiet);

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

    // Spawn monitoring thread
    let ignore_filter_clone = IgnoreFilter::new(
        args.ignore_file.clone(),
        args.ignore_dir.clone()
    );

    thread::spawn(move || {
        let mut poll_counter = 0;

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
                                output_change(&path, &details, &ignore_filter_clone, quiet);
                            }
                        }
                    }
                }

                // Process removals
                if !to_remove.is_empty() {
                    let monitor = monitor_clone.lock().unwrap();
                    for path in to_remove {
                        if monitor.remove_file(&path) {
                            output_change(&path, "removed", &ignore_filter_clone, quiet);
                        }
                    }
                }
            }

            // Full verification every poll_interval seconds
            if poll_counter * 100 < poll_interval * 1000 {
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
                                output_change(&path, &details, &ignore_filter_clone, quiet);
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
                                output_change(&path, &details, &ignore_filter_clone, quiet);
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

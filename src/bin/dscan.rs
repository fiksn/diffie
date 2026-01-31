use clap::Parser;
use diffie::{get_critical_dirs_in_scope, load_snapshot, merge_snapshots, monitor::{Monitor, FileEvent}, save_snapshot, DEFAULT_CRITICAL_DIRS};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(default_value = "/")]
    root: String,

    #[arg(short, long, default_value = "150")]
    size: u64,

    #[arg(long, value_name = "DIR", num_args = 0.., default_values = ["/dev", "/sys", "/mnt", "/Volumes", "/nix", "/.resolve", "/home", "/run", "/var/log", "/proc"])]
    skip: Vec<String>,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(short, long, help = "Append to existing snapshot file (scans subdirectory and merges)")]
    append: Option<String>,

    #[arg(short, long, help = "Interactive mode: monitor changes in real-time using inotify (critical dirs) and polling")]
    interactive: bool,

    #[arg(long, value_name = "DIR", num_args = 0.., default_values = DEFAULT_CRITICAL_DIRS, help = "Critical directories to watch")]
    critical: Vec<String>,

    #[arg(long, default_value = "30", help = "Polling interval in seconds")]
    poll_interval: u64,

    #[arg(long, default_value = "150", help = "Maximum file size in MB to include in snapshot")]
    max_size: u64,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    println!("Scanning {} ...", args.root);
    println!("Skipping: {:?}", args.skip);
    println!("Max file size: {} MB", args.size);

    use diffie::create_snapshot_with_progress;
    use std::sync::{Arc, Mutex};

    let last_reported = Arc::new(Mutex::new(0));
    let last_reported_clone = Arc::clone(&last_reported);

    let mut snapshot = create_snapshot_with_progress(&args.root, &args.skip, args.size, Some(move |current, total| {
        let mut last = last_reported_clone.lock().unwrap();
        let percentage = (current * 100) / total;

        // Report every 5% or at 100%
        if percentage >= *last + 5 || percentage == 100 {
            *last = percentage;
            let bar_width = 50;
            let filled = (bar_width * current) / total;
            let bar: String = std::iter::repeat('█')
                .take(filled)
                .chain(std::iter::repeat('░').take(bar_width - filled))
                .collect();
            println!("Progress: [{}] {}%", bar, percentage);
        }
    }))?;

    let output_file = if let Some(append_file) = args.append.clone() {
        println!("\nLoading existing snapshot from: {}", append_file);
        let mut base_snapshot = load_snapshot(&append_file)?;

        println!("Base snapshot nodes: {}", base_snapshot.nodes.len());
        println!("New scan nodes: {}", snapshot.nodes.len());

        merge_snapshots(&mut base_snapshot, &snapshot);
        snapshot = base_snapshot;

        println!("Merged snapshot nodes: {}", snapshot.nodes.len());

        append_file
    } else {
        args.output.unwrap_or_else(|| {
            format!(
                "snapshot-{}.snap",
                jiff::Zoned::now().strftime("%Y%m%d-%H%M%S")
            )
        })
    };

    save_snapshot(&snapshot, &output_file)?;

    println!("\nSnapshot saved to: {}", output_file);
    println!("Total nodes: {}", snapshot.nodes.len());
    println!(
        "Files: {}",
        snapshot.nodes.values().filter(|n| !n.is_dir).count()
    );
    println!(
        "Directories: {}",
        snapshot.nodes.values().filter(|n| n.is_dir).count()
    );

    if args.interactive {
        println!("\n=== Entering interactive mode ===");
        run_interactive_mode(snapshot, &args.root, &output_file, args.critical, args.poll_interval, args.max_size)?;
    }

    Ok(())
}

fn run_interactive_mode(
    snapshot: diffie::Snapshot,
    scan_root: &str,
    output_file: &str,
    critical_dirs: Vec<String>,
    poll_interval_secs: u64,
    max_size_bytes: u64,
) -> std::io::Result<()> {
    let root_path = PathBuf::from(scan_root);
    let critical_paths = get_critical_dirs_in_scope(&root_path, &critical_dirs);

    println!("Critical directories to watch:");
    for dir in &critical_paths {
        println!("  - {}", dir.display());
    }
    println!("All other files will be polled every {} seconds", poll_interval_secs);
    println!("Press Ctrl+C to stop and save...\n");

    let mut monitor = Monitor::new(snapshot, critical_paths, None, max_size_bytes)?;
    monitor.setup_watches(&root_path)?;

    let mut save_counter = 0;
    let save_interval = 10;

    loop {
        thread::sleep(Duration::from_secs(poll_interval_secs));

        println!("[{}] Checking for changes...", jiff::Zoned::now().strftime("%H:%M:%S"));

        // Process inotify/FSEvents
        {
            let fs_events = monitor.process_events();
            if !fs_events.is_empty() {
                println!("Detected {} changes", fs_events.len());
                for event in fs_events {
                    match event {
                        FileEvent::Created(path) => {
                            match monitor.update_file(&path) {
                                Ok((true, _, _, details)) => println!("  ✓ Created ({}): {}", details, path.display()),
                                Ok((false, _, _, _)) => {},
                                Err(e) => println!("  ✗ Error updating {}: {}", path.display(), e),
                            }
                        }
                        FileEvent::Modified(path) => {
                            match monitor.update_file(&path) {
                                Ok((true, _, _, details)) => println!("  ✓ Modified ({}): {}", details, path.display()),
                                Ok((false, _, _, _)) => {},
                                Err(e) => println!("  ✗ Error updating {}: {}", path.display(), e),
                            }
                        }
                        FileEvent::Removed(path) => {
                            if monitor.remove_file(&path) {
                                println!("  ✓ Removed: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        match monitor.verify_all_files() {
            Ok(changed_files) => {
                if !changed_files.is_empty() {
                    println!("Verification found {} changed files", changed_files.len());
                    for path in changed_files {
                        match monitor.update_file(&path) {
                            Ok((true, _, _, details)) => println!("  ✓ Updated ({}): {}", details, path.display()),
                            Ok((false, _, _, _)) => {},
                            Err(e) => println!("  ✗ Error updating {}: {}", path.display(), e),
                        }
                    }
                }
            }
            Err(e) => println!("Error verifying files: {}", e),
        }

        save_counter += 1;
        if save_counter >= save_interval {
            let current_snapshot = monitor.get_snapshot();
            if let Err(e) = save_snapshot(&current_snapshot, output_file) {
                println!("Error saving snapshot: {}", e);
            } else {
                println!("Snapshot auto-saved to {}", output_file);
            }
            save_counter = 0;
        }
    }
}

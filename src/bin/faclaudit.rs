//! Audit POSIX/Darwin ACLs for unexpected permission grants.
//!
//! On Linux checks `setfacl`-style POSIX ACLs; on macOS checks Darwin ACLs
//! (`chmod +a`). Any named user or group that receives access beyond what the
//! file's regular chmod bits already allow is reported.

use clap::Parser;
use exacl::{AclEntryKind, Perm};
use nix::unistd::{Gid, Group, Uid, User};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "faclaudit", about = "Audit file ACLs for unexpected permissions")]
struct Args {
    #[arg(default_value = "/", help = "Root directory to scan")]
    root: String,

    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..,
        default_values = ["/dev"],
        help = "Files or directories to skip entirely; directories apply recursively (default: /dev)"
    )]
    ignore: Vec<String>,

    #[arg(
        long = "do-not-report",
        value_name = "PATH",
        num_args = 0..,
        help = "Paths whose findings are suppressed (not printed, not counted in exit code)"
    )]
    do_not_report: Vec<String>,
}

fn uid_to_name(uid: u32) -> String {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

fn gid_to_name(gid: u32) -> String {
    Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string())
}

/// Convert the three-bit POSIX permission octet (r=4,w=2,x=1) to a `Perm`.
///
/// Works on both Linux and macOS since READ/WRITE/EXECUTE are defined on both.
fn mode_octet_to_perm(bits: u32) -> Perm {
    let mut p = Perm::empty();
    if bits & 4 != 0 {
        p |= Perm::READ;
    }
    if bits & 2 != 0 {
        p |= Perm::WRITE;
    }
    if bits & 1 != 0 {
        p |= Perm::EXECUTE;
    }
    p
}

fn perm_display(perms: Perm) -> String {
    let s = perms.to_string();
    if s.is_empty() {
        "none".to_string()
    } else {
        s
    }
}

/// Check ACL entries on a single path, returning human-readable findings.
///
/// A finding is produced when a named user/group receives access beyond
/// what the file's regular chmod bits (owner/group baselines) already allow.
/// Deny entries are ignored. On Linux, directory default-ACL entries are
/// also ignored (they only affect newly created children).
fn audit_path(path: &Path) -> Vec<String> {
    let meta = match path.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    // symlinks themselves don't carry meaningful ACLs; skip them
    if meta.file_type().is_symlink() {
        return Vec::new();
    }

    let mode = meta.mode();
    let owner_name = uid_to_name(meta.uid());
    let group_name = gid_to_name(meta.gid());

    let entries = match exacl::getfacl(path, None) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    // Derive baselines and effective-permission mask from the ACL entry list.
    //
    // Linux: UserObj/GroupObj entries hold the "real" owner/group perms;
    //        the Mask entry caps what named users and named groups can actually get.
    //        Both default to the chmod bits if the entry is absent.
    //
    // macOS: No UserObj/GroupObj/Mask concepts — derive directly from mode.
    //        We use Perm::all() as the mask (identity under intersection).
    #[cfg(target_os = "linux")]
    let (user_baseline, group_baseline, mask) = {
        let no_default = |e: &&exacl::AclEntry| !e.flags.contains(exacl::Flag::DEFAULT);
        let user_base = entries
            .iter()
            .filter(no_default)
            .find(|e| matches!(e.kind, AclEntryKind::User) && e.name.is_empty())
            .map_or_else(|| mode_octet_to_perm((mode >> 6) & 7), |e| e.perms);
        let group_base = entries
            .iter()
            .filter(no_default)
            .find(|e| matches!(e.kind, AclEntryKind::Group) && e.name.is_empty())
            .map_or_else(|| mode_octet_to_perm((mode >> 3) & 7), |e| e.perms);
        let mask_perm = entries
            .iter()
            .filter(no_default)
            .find(|e| matches!(e.kind, AclEntryKind::Mask))
            .map_or(Perm::READ | Perm::WRITE | Perm::EXECUTE, |e| e.perms);
        (user_base, group_base, mask_perm)
    };

    #[cfg(target_os = "macos")]
    let (user_baseline, group_baseline, mask) = (
        mode_octet_to_perm((mode >> 6) & 7),
        mode_octet_to_perm((mode >> 3) & 7),
        Perm::all(),
    );

    let mut findings = Vec::new();

    for entry in &entries {
        if !entry.allow {
            continue; // ignore deny rules
        }

        // Skip directory default-ACL entries — they propagate to new children,
        // not to the directory itself.
        #[cfg(target_os = "linux")]
        if entry.flags.contains(exacl::Flag::DEFAULT) {
            continue;
        }

        // Effective perms after applying the mask (on macOS mask == Perm::all(),
        // so this is a no-op there).
        let effective = entry.perms.intersection(mask);
        if effective.is_empty() {
            continue;
        }

        match entry.kind {
            AclEntryKind::User => {
                if entry.name.is_empty() {
                    continue; // UserObj — owner baseline, skip
                }
                // Skip if this is the file owner and the ACL grants nothing extra.
                if entry.name == owner_name && effective.difference(user_baseline).is_empty() {
                    continue;
                }
                findings.push(format!(
                    "user {} has {} permissions",
                    entry.name,
                    perm_display(effective)
                ));
            }
            AclEntryKind::Group => {
                if entry.name.is_empty() {
                    continue; // GroupObj — owning-group baseline, skip
                }
                // Skip if this is the owning group and the ACL grants nothing extra.
                if entry.name == group_name && effective.difference(group_baseline).is_empty() {
                    continue;
                }
                findings.push(format!(
                    "group {} has {} permissions",
                    entry.name,
                    perm_display(effective)
                ));
            }
            // Mask and Other mirror chmod bits — they grant no additional access.
            #[cfg(target_os = "linux")]
            AclEntryKind::Mask | AclEntryKind::Other => {}
            AclEntryKind::Unknown => {}
        }
    }

    findings
}

fn is_under_any(path: &Path, dirs: &[PathBuf]) -> bool {
    dirs.iter().any(|d| path.starts_with(d))
}

fn main() {
    let args = Args::parse();

    let root = PathBuf::from(&args.root);
    let ignore: Vec<PathBuf> = args.ignore.iter().map(PathBuf::from).collect();
    let do_not_report: Vec<PathBuf> = args.do_not_report.iter().map(PathBuf::from).collect();

    let mut found_reportable = false;

    // filter_entry handles both files and dirs: a dir match prunes all descendants,
    // a file match skips just that file. starts_with is component-wise so /dev
    // won't accidentally match /develop.
    let walker = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_under_any(e.path(), &ignore));

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        let findings = audit_path(path);

        if findings.is_empty() || is_under_any(path, &do_not_report) {
            continue;
        }

        println!("{}", path.display());
        for finding in &findings {
            println!("\t{finding}");
        }
        found_reportable = true;
    }

    if found_reportable {
        std::process::exit(1);
    }
}

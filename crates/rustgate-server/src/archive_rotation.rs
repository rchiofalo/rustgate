// Copyright © 2026 Roberto Chiofalo.

//! Size- and time-based retention for the CoT event archive.
//!
//! Operators previously had to use `cron` (or similar) to keep the
//! archive directory bounded. This module exposes a single rotation
//! pass plus a background task that runs the pass on a fixed interval.
//!
//! The rotation rules are intentionally simple:
//!
//! * `max_age` — files whose mtime is older than `now - max_age` are
//!   deleted unconditionally.
//! * `max_bytes` — after the age sweep, if the remaining files still
//!   exceed `max_bytes`, the oldest files (by mtime) are deleted until
//!   the total drops below the cap.
//!
//! Both bounds default to `0`, which disables them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::archive::CotArchiver;

/// Configuration for the archive rotation task.
#[derive(Clone)]
pub struct RotationConfig {
    /// Archive directory to scan.
    pub dir: PathBuf,
    /// Maximum total bytes across all archive files. `0` = unlimited.
    pub max_bytes: u64,
    /// Maximum file age. `Duration::ZERO` = unlimited.
    pub max_age: Duration,
    /// Interval between rotation passes.
    pub interval: Duration,
    /// Optional reference to the live archiver. When set, the rotation
    /// pass will exclude the archiver's currently active segment from
    /// both size accounting and deletion sweeps so it never races the
    /// writer.
    pub archiver: Option<Arc<CotArchiver>>,
}

/// Outcome of a single rotation pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct RotationStats {
    /// Total bytes remaining in the directory after the pass.
    pub bytes_after: u64,
    /// Number of files deleted during the pass.
    pub files_deleted: u64,
}

/// One archive file with its mtime and size, used for sorting by age.
struct Entry {
    path: PathBuf,
    mtime: SystemTime,
    size: u64,
}

/// Run a single rotation pass on `dir`.
///
/// Errors from individual file operations are logged via `tracing` and
/// do not abort the pass — a transient I/O failure on one file should
/// not block retention for the rest of the directory.
pub fn run_pass(
    dir: &Path,
    max_bytes: u64,
    max_age: Duration,
    active_path: Option<&Path>,
) -> std::io::Result<RotationStats> {
    if !dir.exists() {
        return Ok(RotationStats::default());
    }

    let mut entries = collect_entries(dir)?;

    // Exclude the writer's currently active segment from both size
    // accounting and deletion. We never want to delete (or even count
    // the size of) a file the archiver is actively appending to.
    if let Some(active) = active_path {
        entries.retain(|e| e.path != active);
    }

    let mut stats = RotationStats::default();
    let now = SystemTime::now();

    // Age-based sweep.
    if max_age > Duration::ZERO {
        entries.retain(|e| {
            let age = now.duration_since(e.mtime).unwrap_or_default();
            if age > max_age {
                if let Err(err) = std::fs::remove_file(&e.path) {
                    tracing::warn!(
                        path = %e.path.display(),
                        error = %err,
                        "archive rotation: failed to delete aged file",
                    );
                    true
                } else {
                    stats.files_deleted += 1;
                    false
                }
            } else {
                true
            }
        });
    }

    // Sort oldest first so we evict the right files for the size sweep.
    entries.sort_by_key(|e| e.mtime);

    let mut total: u64 = entries.iter().map(|e| e.size).sum();

    // Size-based sweep.
    if max_bytes > 0 && total > max_bytes {
        let mut idx = 0;
        while idx < entries.len() && total > max_bytes {
            let e = &entries[idx];
            match std::fs::remove_file(&e.path) {
                Ok(()) => {
                    total = total.saturating_sub(e.size);
                    stats.files_deleted += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        path = %e.path.display(),
                        error = %err,
                        "archive rotation: failed to delete oversize file",
                    );
                }
            }
            idx += 1;
        }
    }

    stats.bytes_after = total;
    Ok(stats)
}

fn collect_entries(dir: &Path) -> std::io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(error = %err, "archive rotation: read_dir entry failed");
                continue;
            }
        };
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "archive rotation: metadata failed");
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        out.push(Entry {
            path,
            mtime,
            size: meta.len(),
        });
    }
    Ok(out)
}

/// Spawn the background rotation task. Returns the task handle so the
/// caller can abort it during shutdown.
pub fn spawn(cfg: RotationConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if cfg.interval == Duration::ZERO {
            return;
        }
        let mut ticker = tokio::time::interval(cfg.interval);
        // Skip the immediate first tick so startup doesn't immediately
        // pay the rotation cost before any data has been written.
        let _ = ticker.tick().await;
        loop {
            let _ = ticker.tick().await;
            let dir = cfg.dir.clone();
            let max_bytes = cfg.max_bytes;
            let max_age = cfg.max_age;
            let active = cfg.archiver.as_ref().map(|a| a.active_path());
            let join = tokio::task::spawn_blocking(move || {
                run_pass(&dir, max_bytes, max_age, active.as_deref())
            })
            .await;
            match join {
                Ok(Ok(stats)) => {
                    #[cfg(feature = "metrics")]
                    crate::metrics::archive_bytes().set(stats.bytes_after as i64);
                    if stats.files_deleted > 0 {
                        tracing::info!(
                            files_deleted = stats.files_deleted,
                            bytes_after = stats.bytes_after,
                            "archive rotation pass completed",
                        );
                    } else {
                        tracing::debug!(
                            bytes_after = stats.bytes_after,
                            "archive rotation pass completed",
                        );
                    }
                }
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "archive rotation pass failed");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "archive rotation task join error");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::fs;
    use std::io::Write as _;

    use super::*;

    fn write_file(dir: &Path, name: &str, bytes: usize) -> PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&vec![0u8; bytes]).unwrap();
        f.flush().unwrap();
        path
    }

    fn set_mtime(path: &Path, ago: Duration) {
        let when = SystemTime::now() - ago;
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(when).unwrap();
    }

    #[test]
    fn rotation_drops_oldest_when_over_size_cap() {
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-size-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Five 1 KiB files, mtimes spaced one hour apart so the
        // sort order is deterministic.
        let f1 = write_file(&dir, "cot-1.jsonl", 1024);
        let f2 = write_file(&dir, "cot-2.jsonl", 1024);
        let f3 = write_file(&dir, "cot-3.jsonl", 1024);
        let f4 = write_file(&dir, "cot-4.jsonl", 1024);
        let f5 = write_file(&dir, "cot-5.jsonl", 1024);
        set_mtime(&f1, Duration::from_secs(3600 * 5));
        set_mtime(&f2, Duration::from_secs(3600 * 4));
        set_mtime(&f3, Duration::from_secs(3600 * 3));
        set_mtime(&f4, Duration::from_secs(3600 * 2));
        set_mtime(&f5, Duration::from_secs(3600));

        // Cap at ~2.5 KiB; expect the three oldest files (f1, f2, f3) to be deleted.
        let stats = run_pass(&dir, 2560, Duration::ZERO, None).unwrap();

        assert_eq!(stats.files_deleted, 3, "should drop three oldest files");
        assert!(!f1.exists(), "f1 should be deleted");
        assert!(!f2.exists(), "f2 should be deleted");
        assert!(!f3.exists(), "f3 should be deleted");
        assert!(f4.exists(), "f4 should be retained");
        assert!(f5.exists(), "f5 should be retained");
        assert!(stats.bytes_after <= 2560);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_drops_files_older_than_max_age() {
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-age-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let old = write_file(&dir, "cot-old.jsonl", 256);
        let fresh = write_file(&dir, "cot-fresh.jsonl", 256);
        set_mtime(&old, Duration::from_secs(7200));
        set_mtime(&fresh, Duration::from_secs(60));

        let stats = run_pass(&dir, 0, Duration::from_secs(3600), None).unwrap();

        assert_eq!(stats.files_deleted, 1);
        assert!(!old.exists());
        assert!(fresh.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_no_op_when_unbounded() {
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-noop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let f = write_file(&dir, "cot-1.jsonl", 4096);
        let stats = run_pass(&dir, 0, Duration::ZERO, None).unwrap();
        assert_eq!(stats.files_deleted, 0);
        assert_eq!(stats.bytes_after, 4096);
        assert!(f.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_never_deletes_active_file_even_when_over_caps() {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-rot-active-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // The "active" segment: large and ancient. Under both the size
        // and age caps it would normally be deleted first, but the
        // rotation pass must skip it because the writer owns it.
        let active = write_file(&dir, "cot-active.jsonl", 8192);
        set_mtime(&active, Duration::from_secs(86_400 * 30));

        // A rolled / closed segment that *should* be eligible for
        // deletion under both bounds.
        let rolled = write_file(&dir, "cot-rolled.jsonl", 4096);
        set_mtime(&rolled, Duration::from_secs(86_400 * 30));

        // Cap of 1 KiB and max age of 1 hour: without exclusion both
        // files would be deleted. With exclusion, only `rolled` goes.
        let stats = run_pass(&dir, 1024, Duration::from_secs(3600), Some(&active)).unwrap();

        assert!(active.exists(), "active segment must never be deleted");
        assert!(!rolled.exists(), "rolled segment should be deleted");
        assert_eq!(stats.files_deleted, 1);
        // The active file's bytes are also excluded from accounting.
        assert_eq!(stats.bytes_after, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_missing_dir_is_ok() {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-rot-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let stats = run_pass(&dir, 1024, Duration::from_secs(60), None).unwrap();
        assert_eq!(stats.files_deleted, 0);
        assert_eq!(stats.bytes_after, 0);
    }
}

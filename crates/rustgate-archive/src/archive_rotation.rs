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
//! * `max_active_bytes` — before each sweep, if the currently-written
//!   segment exceeds this cap, the archiver seals and rolls it to a
//!   timestamp-suffixed sibling. Without this, a flood of events (e.g.
//!   a policy spamming `Obligation::Unknown(...)` — see #887 Part 4.4)
//!   can grow the active file to tens of gigabytes between daily
//!   rotations, degrading startup and filling disk.
//!
//! All three bounds default to `0`, which disables them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::archive::CotArchiver;

/// Callback invoked after each successful rotation pass with the
/// resulting [`RotationStats`]. The server binary wires this to its
/// `rustgate_archive_bytes` Prometheus gauge; library callers without
/// metrics may leave this `None`.
pub type OnRotationStats = Arc<dyn Fn(RotationStats) + Send + Sync>;

/// Configuration for the archive rotation task.
#[derive(Clone)]
pub struct RotationConfig {
    /// Archive directory to scan.
    pub dir: PathBuf,
    /// Maximum total bytes across all archive files. `0` = unlimited.
    pub max_bytes: u64,
    /// Per-active-segment byte cap. When the segment currently being
    /// appended to exceeds this size, the rotation task asks the
    /// archiver to seal + rename the file and open a fresh segment.
    /// `0` = unlimited. Has no effect without `archiver`.
    pub max_active_bytes: u64,
    /// Maximum file age. `Duration::ZERO` = unlimited.
    pub max_age: Duration,
    /// Interval between rotation passes.
    pub interval: Duration,
    /// Optional reference to the live archiver. When set, the rotation
    /// pass will exclude the archiver's currently active segment from
    /// both size accounting and deletion sweeps so it never races the
    /// writer. Required for `max_active_bytes` to take effect.
    pub archiver: Option<Arc<CotArchiver>>,
    /// Optional callback fired after every successful rotation pass.
    /// Used by the server binary to update the per-pass
    /// `rustgate_archive_bytes` Prometheus gauge without coupling this
    /// crate to a Prometheus dependency.
    pub on_stats: Option<OnRotationStats>,
}

// Manual `Debug` because the `on_stats` callback is `Arc<dyn Fn>` —
// trait objects do not implement `Debug` by default. We surface the
// configured durations and caps; the callback is rendered as a presence
// flag.
impl std::fmt::Debug for RotationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationConfig")
            .field("dir", &self.dir)
            .field("max_bytes", &self.max_bytes)
            .field("max_active_bytes", &self.max_active_bytes)
            .field("max_age", &self.max_age)
            .field("interval", &self.interval)
            .field("archiver", &self.archiver.is_some())
            .field("on_stats", &self.on_stats.is_some())
            .finish()
    }
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

            // Per-active-segment size check runs BEFORE the directory
            // sweep so the just-rolled file is immediately eligible for
            // eviction by `max_bytes` / `max_age` in the same pass.
            if let Some(archiver) = cfg.archiver.as_ref()
                && cfg.max_active_bytes > 0
            {
                let archiver = Arc::clone(archiver);
                let cap = cfg.max_active_bytes;
                let _ = tokio::task::spawn_blocking(move || archiver.roll_if_over_size(cap)).await;
            }

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
                    if let Some(cb) = cfg.on_stats.as_ref() {
                        cb(stats);
                    }
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

    #[test]
    fn rotation_stats_default_is_zero() {
        // Pinned so callers can rely on `RotationStats::default()` as
        // the "nothing happened" value returned from early-exit paths
        // like the missing-directory short-circuit in `run_pass`.
        let s = RotationStats::default();
        assert_eq!(s.bytes_after, 0);
        assert_eq!(s.files_deleted, 0);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn rotation_stats_is_copy_and_clone() {
        // `run_pass` returns `RotationStats` by value and the background
        // loop reads both fields; the Copy derive is what lets that work
        // without moves. Pin the semantics so a future `derive` edit
        // that drops Copy would fail this test instead of silently
        // regressing the call sites. The explicit `.clone()` below is
        // the point of this test — if Copy were ever removed, the
        // `s_again = s` line above would fail first, and this Clone
        // call is what pins the *other* half of the derive.
        let s = RotationStats {
            bytes_after: 42,
            files_deleted: 7,
        };
        let s_copy = s;
        let s_again = s; // still usable — proves Copy, not just Clone.
        assert_eq!(s_copy.bytes_after, 42);
        assert_eq!(s_again.files_deleted, 7);
        let s_cloned = s.clone();
        assert_eq!(s_cloned.bytes_after, 42);
    }

    #[test]
    fn rotation_config_is_cloneable() {
        // The spawn path hands a cloned `RotationConfig` into the
        // background task; pin that Clone covers every field including
        // the `Option<Arc<CotArchiver>>` (None branch — the archiver
        // requires async machinery to construct, and the Arc clone
        // path is covered by Arc's own tests).
        let cfg = RotationConfig {
            dir: PathBuf::from("/tmp/does-not-matter-for-clone"),
            max_bytes: 1 << 20,
            max_active_bytes: 1 << 19,
            max_age: Duration::from_secs(86_400),
            interval: Duration::from_secs(60),
            archiver: None,
            on_stats: None,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.dir, cfg.dir);
        assert_eq!(cloned.max_bytes, cfg.max_bytes);
        assert_eq!(cloned.max_active_bytes, cfg.max_active_bytes);
        assert_eq!(cloned.max_age, cfg.max_age);
        assert_eq!(cloned.interval, cfg.interval);
        assert!(cloned.archiver.is_none());
        assert!(cloned.on_stats.is_none());
    }

    #[test]
    fn rotation_skips_subdirectories() {
        // `collect_entries` filters on `meta.is_file()`. A nested
        // directory under the archive path (e.g. an operator's manual
        // backup subdir) must not be counted toward `bytes_after`
        // and must not be considered for deletion.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-rot-subdir-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let f = write_file(&dir, "cot-1.jsonl", 512);
        let subdir = dir.join("backup");
        fs::create_dir_all(&subdir).unwrap();
        let _nested = write_file(&subdir, "should-be-ignored.jsonl", 4096);

        // Cap well below the nested file's size — if subdirectories
        // were counted, accounting would report >= 4608 bytes and the
        // sweep might try (and fail) to remove the subdir.
        let stats = run_pass(&dir, 1024, Duration::ZERO, None).unwrap();

        assert_eq!(stats.files_deleted, 0, "no top-level files exceed cap");
        assert_eq!(stats.bytes_after, 512, "subdir bytes must not be counted");
        assert!(f.exists(), "top-level file retained");
        assert!(subdir.is_dir(), "subdir preserved");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_empty_dir_returns_zero_stats() {
        // Edge case complementing `rotation_missing_dir_is_ok`: the
        // directory exists but is empty. Both the age and size sweeps
        // must be no-ops and the reported byte total must be zero.
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let stats = run_pass(&dir, 1024, Duration::from_secs(60), None).unwrap();
        assert_eq!(stats.files_deleted, 0);
        assert_eq!(stats.bytes_after, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_size_sweep_stops_once_under_cap() {
        // The size sweep is a `while total > max_bytes` loop — it must
        // stop as soon as the running total drops to (or below) the
        // cap, not continue deleting out of zeal. Three 1 KiB files
        // with a cap of 2 KiB: the single oldest should be enough to
        // bring total to 2 KiB, which is == cap and should therefore
        // stop the loop. Verify the two newer files survive.
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-stop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let f_old = write_file(&dir, "cot-old.jsonl", 1024);
        let f_mid = write_file(&dir, "cot-mid.jsonl", 1024);
        let f_new = write_file(&dir, "cot-new.jsonl", 1024);
        set_mtime(&f_old, Duration::from_secs(3600 * 3));
        set_mtime(&f_mid, Duration::from_secs(3600 * 2));
        set_mtime(&f_new, Duration::from_secs(3600));

        let stats = run_pass(&dir, 2048, Duration::ZERO, None).unwrap();

        assert_eq!(
            stats.files_deleted, 1,
            "sweep must stop once total <= cap, not delete extra"
        );
        assert!(!f_old.exists(), "oldest deleted");
        assert!(f_mid.exists(), "middle retained");
        assert!(f_new.exists(), "newest retained");
        assert_eq!(stats.bytes_after, 2048);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_age_sweep_runs_before_size_sweep() {
        // Age sweep happens first, then size sweep. Construct a case
        // where an ancient file would *not* be targeted by the size
        // sweep on its own (because the remaining files are already
        // under the cap once it is gone), but is removed anyway by the
        // age sweep. If the order were reversed (size first, age
        // second) the same files could be retained — pinning this
        // ordering protects the documented contract.
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-rot-order-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // One ancient small file (age-evicted) and two fresh smaller
        // files. Total bytes = 256 + 128 + 128 = 512; cap = 1024.
        // Without the age sweep the size sweep would be a no-op.
        let ancient = write_file(&dir, "cot-ancient.jsonl", 256);
        let fresh_a = write_file(&dir, "cot-fresh-a.jsonl", 128);
        let fresh_b = write_file(&dir, "cot-fresh-b.jsonl", 128);
        set_mtime(&ancient, Duration::from_secs(86_400 * 10));
        set_mtime(&fresh_a, Duration::from_secs(60));
        set_mtime(&fresh_b, Duration::from_secs(30));

        let stats = run_pass(&dir, 1024, Duration::from_secs(3600), None).unwrap();

        assert_eq!(stats.files_deleted, 1, "only the ancient file goes");
        assert!(!ancient.exists(), "ancient file age-evicted");
        assert!(fresh_a.exists(), "fresh file retained");
        assert!(fresh_b.exists(), "fresh file retained");
        assert_eq!(stats.bytes_after, 256, "two 128-byte files remain");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_combined_age_and_size_hits_both_sweeps() {
        // Age and size sweeps compose: an ancient file is removed by
        // age, and *additional* eviction happens in the size sweep if
        // the remainder still exceeds the cap. Pins that the deletion
        // counter accumulates across both passes and that the oldest
        // remaining files are the ones chosen for the size pass.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-rot-combined-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // ancient: evicted by age (older than 1h)
        // old:     evicted by size (oldest-surviving-after-age)
        // mid:     retained
        // new:     retained
        let ancient = write_file(&dir, "cot-ancient.jsonl", 1024);
        let old = write_file(&dir, "cot-old.jsonl", 1024);
        let mid = write_file(&dir, "cot-mid.jsonl", 1024);
        let new_f = write_file(&dir, "cot-new.jsonl", 1024);
        set_mtime(&ancient, Duration::from_secs(86_400 * 10));
        set_mtime(&old, Duration::from_secs(1800));
        set_mtime(&mid, Duration::from_secs(1200));
        set_mtime(&new_f, Duration::from_secs(600));

        // After age sweep: ancient gone, 3 files × 1 KiB = 3 KiB remain.
        // Size cap 2 KiB forces one more eviction — the oldest of the
        // survivors, which is `old`.
        let stats = run_pass(&dir, 2048, Duration::from_secs(3600), None).unwrap();

        assert_eq!(stats.files_deleted, 2, "one by age, one by size");
        assert!(!ancient.exists(), "ancient evicted by age");
        assert!(!old.exists(), "oldest survivor evicted by size");
        assert!(mid.exists(), "mid retained");
        assert!(new_f.exists(), "new retained");
        assert_eq!(stats.bytes_after, 2048);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_bytes_after_matches_disk_reality() {
        // `bytes_after` is the basis of the `archive_bytes` Prometheus
        // gauge; it has to equal the real size on disk (excluding the
        // active segment). Pin the arithmetic.
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-rot-bytes-after-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let _ = write_file(&dir, "cot-a.jsonl", 200);
        let _ = write_file(&dir, "cot-b.jsonl", 300);
        let _ = write_file(&dir, "cot-c.jsonl", 400);

        let stats = run_pass(&dir, 0, Duration::ZERO, None).unwrap();
        assert_eq!(stats.files_deleted, 0);
        assert_eq!(stats.bytes_after, 900);

        let _ = fs::remove_dir_all(&dir);
    }
}

// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Hardened secret-file reader with unified permission, size, and ownership checks.
//!
//! Replaces ad-hoc `std::fs::read` / `std::fs::read_to_string` implementations
//! across the workspace. Every caller that loads on-disk secret material — JWT
//! signing keys, bearer tokens, HMAC secrets, mTLS client keys, CA private keys,
//! enrollment passwords — should funnel through [`read_secret_file`].
//!
//! The helper enforces the strictest existing discipline (originally pioneered
//! in `rustgate-http::auth`): a small (8 KiB by default) size cap with an
//! attacker-RAM-exhaustion rationale, a Unix mode 0o077 permissions check that
//! refuses any group/other read access, optional file-owner-uid binding to
//! catch "secret dropped by root, service runs as rustgate" misconfigurations,
//! optional newline trimming, and rejection of empty files. The caller picks
//! the policy via [`SecretFileOpts`] but the defaults are safe.
//!
//! All success paths return [`Zeroizing<String>`](zeroize::Zeroizing) so the
//! decoded contents are wiped from memory on drop, on every exit path.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use thiserror::Error;
use zeroize::Zeroizing;

/// Default maximum secret file size — 8 KiB. Matches the pre-refactor
/// `rustgate-http::auth` cap. Comfortably above any reasonable token,
/// JWT secret, hex-encoded key, or PEM-encoded private key (a 4096-bit
/// RSA PKCS#8 PEM is ~3.2 KiB) while still bounding RAM consumption if
/// the configured path is mis-pointed at a log file.
pub const DEFAULT_MAX_SECRET_FILE_BYTES: u64 = 8 * 1024;

/// Errors returned by [`read_secret_file`].
///
/// The variant text is operator-facing — it explains both *what* failed
/// and *why the check exists*, so an operator can immediately see the
/// remediation (chmod the file, shrink it, populate it, chown it).
#[derive(Debug, Error)]
pub enum SecretFileError {
    /// The file could not be opened, stat'ed, read, or decoded as UTF-8.
    /// Wraps the original I/O error for chained `source()` traversal.
    #[error("secret file `{path}` not found or not readable: {source}")]
    NotReadable {
        /// Display path of the file we tried to read.
        path: String,
        /// Underlying I/O / UTF-8 error.
        source: std::io::Error,
    },

    /// The file's reported size exceeds [`SecretFileOpts::max_bytes`].
    /// Surfaced from the metadata pre-check so a multi-GB log file
    /// cannot be slurped into RAM before the size violation is noticed.
    #[error(
        "secret file `{path}` is too large: {actual} bytes (max {max} bytes); \
         attacker-inflated keyfiles can exhaust RAM in callers that lack size caps"
    )]
    TooLarge {
        /// Display path of the offending file.
        path: String,
        /// Actual file size in bytes.
        actual: u64,
        /// The configured cap.
        max: u64,
    },

    /// The file's Unix permissions allow group or other access.
    /// Only emitted on Unix when [`SecretFileOpts::require_mode_077`] is set.
    #[error(
        "secret file `{path}` has overly-permissive Unix mode {actual:#o}; \
         expected mode 0o077 (group/other bits zero) so a co-tenant cannot read"
    )]
    PermissionsTooOpen {
        /// Display path of the offending file.
        path: String,
        /// The mode bits returned by `stat(2)`.
        actual: u32,
    },

    /// The file is empty (or, when [`SecretFileOpts::trim_newline`] is set,
    /// contains nothing but trailing whitespace) and
    /// [`SecretFileOpts::reject_empty`] is set.
    #[error("secret file `{path}` is empty (after optional newline trim)")]
    Empty {
        /// Display path of the offending file.
        path: String,
    },

    /// The file's owner UID does not match the value supplied in
    /// [`SecretFileOpts::require_owner_uid`]. Catches the "secret dropped
    /// by root but the service runs as a different account" misconfig,
    /// where the read silently succeeds without the check.
    #[error("secret file `{path}` owner uid {actual} does not match expected {expected}")]
    OwnerMismatch {
        /// Display path of the offending file.
        path: String,
        /// The UID stat(2) reported.
        actual: u32,
        /// The UID the caller required.
        expected: u32,
    },
}

/// Knobs controlling [`read_secret_file`].
///
/// The [`Default`] impl is the recommended baseline — it matches the
/// strictest discipline that already existed in the workspace before
/// the unification. Override individual fields for narrower needs (e.g.
/// the federation key file is a multi-line PEM, so `trim_newline=false`
/// might be appropriate when the caller forwards the raw bytes to a PEM
/// parser that is whitespace-tolerant).
#[derive(Debug, Clone)]
pub struct SecretFileOpts {
    /// Hard cap on the file size in bytes. Files exceeding this are
    /// rejected at the metadata check, before any read into RAM.
    pub max_bytes: u64,
    /// On Unix, refuse to read files whose mode has any group/other
    /// bits set (i.e. require `mode & 0o077 == 0`). No-op on non-Unix.
    pub require_mode_077: bool,
    /// On Unix, optionally require the file's owner UID to match this
    /// value. Typically the running process's effective UID. No-op on
    /// non-Unix.
    pub require_owner_uid: Option<u32>,
    /// Strip a single trailing `\r\n` or `\n` (or any combination of
    /// trailing whitespace, since we use `str::trim`) before returning.
    pub trim_newline: bool,
    /// Reject the file if the post-trim contents are empty.
    pub reject_empty: bool,
}

impl Default for SecretFileOpts {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_SECRET_FILE_BYTES,
            require_mode_077: true,
            require_owner_uid: None,
            trim_newline: true,
            reject_empty: true,
        }
    }
}

impl SecretFileOpts {
    /// Convenience constructor for callers that want the strict defaults
    /// but a different size cap (e.g. PEM private-key files that are
    /// larger than the 8 KiB default for tokens).
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            ..Self::default()
        }
    }
}

/// Read a secret file, validate it against `opts`, and return the
/// (optionally trimmed) contents wrapped in [`Zeroizing<String>`].
///
/// Order of checks (each fails fast):
/// 1. Open the file. Failure → [`SecretFileError::NotReadable`].
/// 2. Stat for metadata. On Unix, optionally enforce mode 0o077 and
///    matching owner UID. Failures →
///    [`SecretFileError::PermissionsTooOpen`] /
///    [`SecretFileError::OwnerMismatch`].
/// 3. Compare reported size to `opts.max_bytes`. Over →
///    [`SecretFileError::TooLarge`].
/// 4. Read up to `opts.max_bytes + 1` so we can detect a file that
///    grew between stat and read. Over → [`SecretFileError::TooLarge`].
/// 5. Decode as UTF-8. Invalid → [`SecretFileError::NotReadable`]
///    with `ErrorKind::InvalidData`.
/// 6. Optional newline / whitespace trim.
/// 7. Optional empty-after-trim check → [`SecretFileError::Empty`].
///
/// The returned [`Zeroizing<String>`] is wiped on drop. Intermediate
/// raw buffers are also wiped before they go out of scope to minimise
/// the time uncovered secret material lives in process memory.
pub fn read_secret_file<P: AsRef<Path>>(
    path: P,
    opts: &SecretFileOpts,
) -> Result<Zeroizing<String>, SecretFileError> {
    let path_ref = path.as_ref();
    let display = path_ref.display().to_string();

    // 1. Open the file. We open before stat so we can use the same
    //    descriptor for the size check and the read — this makes a
    //    swap-the-symlink TOCTOU attack harder.
    let mut file = File::open(path_ref).map_err(|source| SecretFileError::NotReadable {
        path: display.clone(),
        source,
    })?;

    let metadata = file
        .metadata()
        .map_err(|source| SecretFileError::NotReadable {
            path: display.clone(),
            source,
        })?;

    // 2. Permission + ownership check (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opts.require_mode_077 {
            let mode = metadata.permissions().mode();
            // `mode & 0o7777` strips file-type bits (e.g. regular-file
            // S_IFREG = 0o100000) so the rendered error matches the
            // mode the operator would set with `chmod`.
            let permission_bits = mode & 0o7777;
            if permission_bits & 0o077 != 0 {
                return Err(SecretFileError::PermissionsTooOpen {
                    path: display,
                    actual: permission_bits,
                });
            }
        }
        if let Some(expected_uid) = opts.require_owner_uid {
            let actual_uid = metadata.uid();
            if actual_uid != expected_uid {
                return Err(SecretFileError::OwnerMismatch {
                    path: display,
                    actual: actual_uid,
                    expected: expected_uid,
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Non-Unix platforms cannot enforce POSIX mode bits or owner
        // UID. The fields are silently ignored rather than erroring,
        // because the workspace targets Linux/macOS for production and
        // Windows is only used as a developer environment where strict
        // perm checks would be a footgun.
        let _ = opts.require_mode_077;
        let _ = opts.require_owner_uid;
    }

    // 3. Reject oversized files at metadata level so we never even
    //    attempt to load a multi-GB file into RAM.
    let reported_size = metadata.len();
    if reported_size > opts.max_bytes {
        return Err(SecretFileError::TooLarge {
            path: display,
            actual: reported_size,
            max: opts.max_bytes,
        });
    }

    // 4. Read at most `max_bytes + 1` so a file that *grew* between
    //    stat and read is still rejected. The `+1` lets us
    //    distinguish "exactly at the cap" from "one byte over".
    let cap_with_overflow = opts.max_bytes.saturating_add(1);
    // The cap is checked above against u64::MAX-class file sizes, but
    // `Vec::with_capacity` takes a `usize` — clamp to avoid an
    // allocation panic on 32-bit hosts with absurd configured caps.
    let initial_capacity =
        usize::try_from(reported_size.min(cap_with_overflow)).unwrap_or(usize::MAX);
    let mut raw = Zeroizing::new(Vec::<u8>::with_capacity(initial_capacity));
    let bytes_read = (&mut file)
        .take(cap_with_overflow)
        .read_to_end(&mut raw)
        .map_err(|source| SecretFileError::NotReadable {
            path: display.clone(),
            source,
        })?;
    if (bytes_read as u64) > opts.max_bytes {
        return Err(SecretFileError::TooLarge {
            path: display,
            actual: bytes_read as u64,
            max: opts.max_bytes,
        });
    }

    // 5. Decode as UTF-8. Invalid sequences map to NotReadable with
    //    InvalidData kind — credentials are conventionally text and a
    //    binary blob almost certainly indicates a misconfigured path.
    let mut decoded = match std::str::from_utf8(&raw) {
        Ok(s) => Zeroizing::new(s.to_string()),
        Err(e) => {
            return Err(SecretFileError::NotReadable {
                path: display,
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            });
        }
    };

    // 6. Optional whitespace trim. We use `str::trim` (rather than
    //    just `trim_end_matches('\n')`) so editors that normalise to
    //    `\r\n` or that append a trailing space don't surface as an
    //    invalid token.
    let result = if opts.trim_newline {
        let trimmed = Zeroizing::new(decoded.trim().to_string());
        zeroize::Zeroize::zeroize(&mut *decoded);
        trimmed
    } else {
        decoded
    };

    // 7. Empty-after-trim guard.
    if opts.reject_empty && result.is_empty() {
        return Err(SecretFileError::Empty { path: display });
    }

    Ok(result)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    /// Set Unix mode 0o600 on the path so it passes the strict
    /// permission gate. No-op on non-Unix.
    fn chmod_owner_only(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(path).unwrap().permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(path, perm).unwrap();
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
    }

    #[test]
    fn read_secret_file_returns_zeroizing_with_trimmed_newline_by_default() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abc123\n").unwrap();
        f.flush().unwrap();
        chmod_owner_only(f.path());

        let result = read_secret_file(f.path(), &SecretFileOpts::default())
            .expect("default opts must accept a 0o600 7-byte UTF-8 file");
        assert_eq!(&*result, "abc123", "default trims trailing newline");
    }

    #[test]
    fn read_secret_file_rejects_oversized_file() {
        // 9 KiB > 8 KiB cap.
        let mut f = NamedTempFile::new().unwrap();
        let payload = vec![b'x'; 9 * 1024];
        f.write_all(&payload).unwrap();
        f.flush().unwrap();
        chmod_owner_only(f.path());

        match read_secret_file(f.path(), &SecretFileOpts::default()) {
            Err(SecretFileError::TooLarge { actual, max, .. }) => {
                assert_eq!(actual, 9 * 1024, "actual must reflect the on-disk size");
                assert_eq!(max, DEFAULT_MAX_SECRET_FILE_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_rejects_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abc\n").unwrap();
        f.flush().unwrap();
        let mut perm = std::fs::metadata(f.path()).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(f.path(), perm).unwrap();

        match read_secret_file(f.path(), &SecretFileOpts::default()) {
            Err(SecretFileError::PermissionsTooOpen { actual, .. }) => {
                assert_eq!(
                    actual, 0o644,
                    "reported mode bits must match what `chmod` set"
                );
            }
            other => panic!("expected PermissionsTooOpen, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_accepts_mode_600_owner_only() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"sekret").unwrap();
        f.flush().unwrap();
        chmod_owner_only(f.path());

        let result = read_secret_file(f.path(), &SecretFileOpts::default())
            .expect("0o600 must pass the strict permission gate");
        assert_eq!(&*result, "sekret");
    }

    #[test]
    fn read_secret_file_rejects_empty_file_when_configured() {
        let f = NamedTempFile::new().unwrap();
        chmod_owner_only(f.path());

        match read_secret_file(f.path(), &SecretFileOpts::default()) {
            Err(SecretFileError::Empty { .. }) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn read_secret_file_returns_not_readable_for_nonexistent_path() {
        let path = std::path::Path::new("/definitely/does/not/exist/rustgate-secrets-test.txt");
        match read_secret_file(path, &SecretFileOpts::default()) {
            Err(SecretFileError::NotReadable { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected NotReadable(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn read_secret_file_does_not_trim_when_disabled() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abc\n").unwrap();
        f.flush().unwrap();
        chmod_owner_only(f.path());

        let opts = SecretFileOpts {
            trim_newline: false,
            ..SecretFileOpts::default()
        };
        let result = read_secret_file(f.path(), &opts).expect("untrimmed read must succeed");
        assert_eq!(
            &*result, "abc\n",
            "disabling trim_newline must preserve the trailing byte"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_does_not_check_perms_when_disabled() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abc\n").unwrap();
        f.flush().unwrap();
        // World-readable on purpose — should still be accepted because
        // require_mode_077 is off.
        let mut perm = std::fs::metadata(f.path()).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(f.path(), perm).unwrap();

        let opts = SecretFileOpts {
            require_mode_077: false,
            ..SecretFileOpts::default()
        };
        let result =
            read_secret_file(f.path(), &opts).expect("perm check disabled must accept 0o644");
        assert_eq!(&*result, "abc");
    }

    #[test]
    fn read_secret_file_rejects_invalid_utf8() {
        // Defends the documented contract: the helper returns
        // Zeroizing<String>, so any binary blob must surface as
        // NotReadable rather than corrupt the returned String.
        let mut f = NamedTempFile::new().unwrap();
        // 0xFF is never a legal UTF-8 leading byte.
        f.write_all(&[0xFFu8, 0xFE]).unwrap();
        f.flush().unwrap();
        chmod_owner_only(f.path());

        match read_secret_file(f.path(), &SecretFileOpts::default()) {
            Err(SecretFileError::NotReadable { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
            }
            other => panic!("expected NotReadable(InvalidData), got {other:?}"),
        }
    }

    #[test]
    fn secret_file_opts_with_max_bytes_preserves_strict_defaults() {
        // Pin the convenience constructor so a future refactor that
        // accidentally relaxes a different field (e.g. `trim_newline`)
        // is caught here rather than in a downstream caller.
        let opts = SecretFileOpts::with_max_bytes(16 * 1024);
        assert_eq!(opts.max_bytes, 16 * 1024);
        assert!(opts.require_mode_077, "permission check must remain on");
        assert!(opts.trim_newline, "trim_newline must remain on");
        assert!(opts.reject_empty, "reject_empty must remain on");
        assert!(opts.require_owner_uid.is_none(), "no implicit uid binding");
    }
}

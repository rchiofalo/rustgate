//! Structured CoT event archiver.
//!
//! When enabled, logs all received CoT events as JSONL to a rotatable
//! archive file. Each line is a self-contained JSON object with source
//! identity, timestamp, and the raw payload.
//!
//! Files rotate daily (one file per UTC date). The archive directory is
//! created on first write if it does not exist.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rustgate_core::message::RoutableMessage;

/// Writes CoT events as JSONL to date-stamped archive files.
pub struct CotArchiver {
    dir: PathBuf,
    inner: Arc<Mutex<ArchiverState>>,
}

struct ArchiverState {
    current_date: String,
    writer: Option<std::io::BufWriter<std::fs::File>>,
}

impl CotArchiver {
    /// Create a new archiver that writes to the given directory.
    ///
    /// The directory is created lazily on the first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            inner: Arc::new(Mutex::new(ArchiverState {
                current_date: String::new(),
                writer: None,
            })),
        }
    }

    /// Archive a single message.
    ///
    /// Serialises the JSONL line on the calling task, then moves the
    /// blocking file I/O into `spawn_blocking` so the async read loop
    /// is never stalled by disk writes or file rotation.
    pub async fn record(&self, msg: &RoutableMessage) {
        let now = SystemTime::now();
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute UTC date string (YYYY-MM-DD) without chrono
        let today = utc_date_string(secs);

        // Build JSONL line on the async task (cheap CPU work).
        let payload_b64 = base64_encode(&msg.payload);
        let msg_type = escape_json(&msg.metadata.message_type.to_string());
        let dest = match &msg.destination {
            rustgate_core::message::Destination::Broadcast => "broadcast".to_string(),
            rustgate_core::message::Destination::Group(g) => {
                format!("group:{}", escape_json(g))
            }
            rustgate_core::message::Destination::Direct(d) => {
                format!("direct:{}", escape_json(&d.cn))
            }
        };

        let line = format!(
            "{{\"ts\":{secs},\"cn\":\"{}\",\"fp\":\"{}\",\"type\":\"{msg_type}\",\"dest\":\"{dest}\",\"proto\":\"{}\",\"payload\":\"{payload_b64}\"}}\n",
            escape_json(&msg.source.cn),
            escape_json(&msg.source.fingerprint),
            escape_json(&msg.metadata.source_protocol),
        );

        // Move all blocking file I/O onto the blocking thread pool.
        let inner = Arc::clone(&self.inner);
        let dir = self.dir.clone();
        let _result = tokio::task::spawn_blocking(move || {
            write_line(&inner, &dir, &today, &line);
        })
        .await;
    }

    /// Flush any buffered data to disk.
    pub fn flush(&self) {
        let mut state = match self.inner.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(ref mut w) = state.writer {
            let _ = w.flush();
        }
    }
}

impl Drop for CotArchiver {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Perform the blocking file rotation and write on the current thread.
///
/// Extracted as a free function so it can be called inside
/// `spawn_blocking` without borrowing `self`.
fn write_line(inner: &Mutex<ArchiverState>, dir: &std::path::Path, today: &str, line: &str) {
    let mut state = match inner.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Rotate file if date changed
    if state.current_date != today {
        if let Some(ref mut w) = state.writer {
            let _ = w.flush();
        }
        state.writer = None;
        state.current_date = today.to_owned();

        match open_file(dir, today) {
            Ok(file) => {
                state.writer = Some(std::io::BufWriter::new(file));
            }
            Err(e) => {
                tracing::error!(error = %e, dir = %dir.display(), "failed to open archive file");
                return;
            }
        }
    }

    let Some(ref mut writer) = state.writer else {
        return;
    };

    if let Err(e) = writer.write_all(line.as_bytes()) {
        tracing::error!(error = %e, "failed to write archive line");
    }
}

fn open_file(dir: &std::path::Path, date: &str) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("cot-{date}.jsonl"));
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Compute UTC date string (YYYY-MM-DD) from Unix epoch seconds.
fn utc_date_string(epoch_secs: u64) -> String {
    // Days since epoch
    let days = epoch_secs / 86400;
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Minimal JSON string escaping (backslash and double-quote).
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Minimal base64 encoder (standard alphabet, with padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_known_epoch() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(utc_date_string(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn utc_date_unix_epoch() {
        assert_eq!(utc_date_string(0), "1970-01-01");
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_padding() {
        assert_eq!(base64_encode(b"Hi"), "SGk=");
        assert_eq!(base64_encode(b"Hey"), "SGV5");
    }

    #[test]
    fn escape_json_special_chars() {
        assert_eq!(escape_json(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escape_json_clean() {
        assert_eq!(escape_json("hello"), "hello");
    }

    #[tokio::test]
    async fn archiver_escapes_special_cn_in_dest() {
        let dir = std::env::temp_dir().join(format!(
            "rustgate-archive-escape-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);

        let target_identity = rustgate_core::identity::Identity::new(
            "evil\"user\\name".to_string(),
            "fp-target".to_string(),
            std::collections::BTreeSet::new(),
        )
        .expect("valid identity");

        let msg = rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "sender".to_string(),
                "fp-sender".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Direct(target_identity),
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: rustgate_core::message::MessageType::Position,
                ttl: None,
            },
        };

        archiver.record(&msg).await;
        archiver.flush();

        let entries: Vec<_> = std::fs::read_dir(&dir).expect("dir should exist").collect();
        assert_eq!(entries.len(), 1);

        let file_path = entries[0].as_ref().expect("entry").path();
        let content = std::fs::read_to_string(&file_path).expect("read file");

        // Verify the special chars are escaped — no raw quotes or backslashes
        assert!(
            content.contains(r#"direct:evil\"user\\name"#),
            "CN with special chars should be escaped: {content}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn archiver_creates_file() {
        let dir =
            std::env::temp_dir().join(format!("rustgate-archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let archiver = CotArchiver::new(&dir);

        let msg = rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity::new(
                "alice".to_string(),
                "fp-123".to_string(),
                std::collections::BTreeSet::new(),
            )
            .expect("valid identity"),
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"<event/>"),
            metadata: rustgate_core::message::Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: rustgate_core::message::MessageType::Position,
                ttl: None,
            },
        };

        archiver.record(&msg).await;
        archiver.flush();

        // Verify file exists and has content
        let entries: Vec<_> = std::fs::read_dir(&dir).expect("dir should exist").collect();
        assert_eq!(entries.len(), 1, "should have one archive file");

        let file_path = entries[0].as_ref().expect("entry").path();
        let content = std::fs::read_to_string(&file_path).expect("read file");
        assert!(content.contains("\"cn\":\"alice\""));
        assert!(content.contains("\"fp\":\"fp-123\""));
        assert!(content.ends_with('\n'));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}

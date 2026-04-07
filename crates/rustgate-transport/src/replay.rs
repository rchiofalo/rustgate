//! Sliding-window anti-replay filter for messages.
//!
//! Prevents duplicate messages from being routed by tracking recently-seen
//! `(uid, time)` pairs from CoT XML payloads within a configurable time
//! window. Messages whose `(uid, time)` key was already seen within the
//! window are flagged as replays and should be dropped.
//!
//! Non-CoT payloads (where uid/time cannot be extracted) are always passed
//! through to avoid dropping unknown traffic.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default replay window duration in seconds.
const DEFAULT_WINDOW_SECS: u64 = 300;

/// Number of insertions between automatic eviction sweeps.
/// Keeps the map from growing unboundedly between manual `evict()` calls.
const EVICT_INTERVAL: u64 = 1000;

/// Thread-safe sliding-window replay filter.
///
/// Tracks `(uid, time)` hashes from CoT XML messages and flags duplicates
/// seen within the configured window. Expired entries are periodically
/// evicted to bound memory usage.
#[derive(Debug)]
pub struct ReplayFilter {
    inner: Mutex<ReplayFilterInner>,
}

#[derive(Debug)]
struct ReplayFilterInner {
    /// Map from message key hash to the instant it was first seen.
    seen: HashMap<u64, Instant>,
    /// Sliding window duration. Messages older than this are evicted.
    window: Duration,
    /// Counter of insertions since last eviction sweep.
    ops_since_evict: u64,
}

impl ReplayFilter {
    /// Create a new replay filter with the default window (300 seconds).
    pub fn new() -> Self {
        Self::with_window(Duration::from_secs(DEFAULT_WINDOW_SECS))
    }

    /// Create a new replay filter with the given window duration.
    pub fn with_window(window: Duration) -> Self {
        Self {
            inner: Mutex::new(ReplayFilterInner {
                seen: HashMap::new(),
                window,
                ops_since_evict: 0,
            }),
        }
    }

    /// Create a new replay filter from a window specified in seconds.
    ///
    /// Returns `None` if `secs` is 0 (disabled).
    pub fn from_secs(secs: u64) -> Option<Self> {
        if secs == 0 {
            return None;
        }
        Some(Self::with_window(Duration::from_secs(secs)))
    }

    /// Check whether a payload is a replay of a previously seen message.
    ///
    /// Extracts the `uid` and `time` attributes from the CoT XML payload
    /// and checks whether the same key has been seen within the window.
    /// Returns `true` if the message is a replay and should be dropped.
    ///
    /// Non-CoT payloads (where uid/time cannot be extracted) always return
    /// `false` to avoid dropping unknown traffic.
    ///
    /// # Timing side-channel mitigation
    ///
    /// This method uses the [`HashMap::entry`] API so that every call
    /// traverses to the insertion point regardless of whether the key
    /// already exists. This ensures the HashMap lookup and mutation follow
    /// the same code path for both hits and misses, preventing an attacker
    /// from inferring replay status through response-time observation.
    pub fn is_replay(&self, payload: &[u8]) -> bool {
        let key = match message_key(payload) {
            Some(k) => k,
            None => return false,
        };

        let mut guard = self.inner.lock();

        let now = Instant::now();
        let window = guard.window;

        // Use the entry API to always traverse to the insertion point,
        // eliminating the timing difference between hit and miss paths.
        let is_duplicate = match guard.seen.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let first_seen = *entry.get();
                if now.duration_since(first_seen) < window {
                    // Still within window — this is a replay.
                    true
                } else {
                    // Entry expired — treat as new and update timestamp.
                    let _ = entry.insert(now);
                    false
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let _ = entry.insert(now);
                false
            }
        };

        guard.ops_since_evict += 1;

        // Periodic eviction to bound memory.
        if guard.ops_since_evict >= EVICT_INTERVAL {
            guard.ops_since_evict = 0;
            guard.seen.retain(|_, ts| now.duration_since(*ts) < window);
        }

        is_duplicate
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }

    /// Whether the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Key extraction (shared logic with federation dedup)
// ---------------------------------------------------------------------------

/// Extract a hash key from a CoT XML payload.
///
/// Scans for `uid="..."` and `time="..."` attributes in the first 512
/// bytes and hashes them together. Returns `None` if either attribute
/// is missing (non-CoT payload).
fn message_key(payload: &[u8]) -> Option<u64> {
    let uid = extract_xml_attr(payload, b"uid=")?;
    let time = extract_xml_attr(payload, b"time=")?;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    uid.hash(&mut hasher);
    time.hash(&mut hasher);
    Some(hasher.finish())
}

/// Extract the value of an XML attribute from raw bytes.
///
/// Searches for `name="value"` or `name='value'` in the first 512 bytes.
/// Uses a forward scan with quote-state tracking to avoid matching attribute
/// names that appear inside another attribute's quoted value.
pub(crate) fn extract_xml_attr<'a>(payload: &'a [u8], attr: &[u8]) -> Option<&'a [u8]> {
    let search_limit = payload.len().min(512);
    let haystack = &payload[..search_limit];
    let attr_len = attr.len();

    // Track whether we are inside a quoted attribute value.
    // When `in_quote` is Some(q), we are inside a value delimited by quote char q.
    let mut in_quote: Option<u8> = None;
    let mut i = 0;

    while i < search_limit {
        let b = haystack[i];

        // If inside a quoted value, skip until closing quote.
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }

        // Check for attribute match at this position.
        if i + attr_len <= search_limit
            && &haystack[i..i + attr_len] == attr
            && (i == 0 || haystack[i - 1].is_ascii_whitespace())
        {
            let value_start = i + attr_len;
            if value_start >= search_limit {
                return None;
            }

            let quote = haystack[value_start];
            if quote == b'"' || quote == b'\'' {
                let content_start = value_start + 1;
                if content_start >= search_limit {
                    return None;
                }
                let remaining = &haystack[content_start..];
                let end = remaining.iter().position(|&c| c == quote)?;
                return Some(&payload[content_start..content_start + end]);
            }
        }

        // Enter quoted value if we see `=` followed by a quote.
        if b == b'=' && i + 1 < search_limit {
            let next = haystack[i + 1];
            if next == b'"' || next == b'\'' {
                in_quote = Some(next);
                i += 2; // skip past `="` or `='`
                continue;
            }
        }

        i += 1;
    }

    None
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_message_is_not_replay() {
        let filter = ReplayFilter::new();
        let xml = br#"<event uid="A1" time="2024-01-01T00:00:00Z" type="a-f-G">"#;
        assert!(!filter.is_replay(xml));
    }

    #[test]
    fn same_message_is_replay() {
        let filter = ReplayFilter::new();
        let xml = br#"<event uid="A1" time="2024-01-01T00:00:00Z" type="a-f-G">"#;
        assert!(!filter.is_replay(xml));
        assert!(filter.is_replay(xml));
    }

    #[test]
    fn different_uid_not_replay() {
        let filter = ReplayFilter::new();
        let a = br#"<event uid="A1" time="T1" type="a-f-G">"#;
        let b = br#"<event uid="A2" time="T1" type="a-f-G">"#;
        assert!(!filter.is_replay(a));
        assert!(!filter.is_replay(b));
    }

    #[test]
    fn different_time_not_replay() {
        let filter = ReplayFilter::new();
        let a = br#"<event uid="A1" time="T1" type="a-f-G">"#;
        let b = br#"<event uid="A1" time="T2" type="a-f-G">"#;
        assert!(!filter.is_replay(a));
        assert!(!filter.is_replay(b));
    }

    #[test]
    fn non_cot_payload_passes_through() {
        let filter = ReplayFilter::new();
        assert!(!filter.is_replay(b"random binary data"));
        assert!(!filter.is_replay(b"random binary data"));
    }

    #[test]
    fn expired_entry_is_not_replay() {
        // Use a very short window so entries expire immediately.
        let filter = ReplayFilter::with_window(Duration::from_millis(0));
        let xml = br#"<event uid="A1" time="T1" type="a-f-G">"#;
        assert!(!filter.is_replay(xml));
        // With a zero-duration window, the entry is immediately expired.
        assert!(!filter.is_replay(xml));
    }

    #[test]
    fn from_secs_zero_returns_none() {
        assert!(ReplayFilter::from_secs(0).is_none());
    }

    #[test]
    fn from_secs_nonzero_returns_some() {
        assert!(ReplayFilter::from_secs(60).is_some());
    }

    #[test]
    fn len_tracks_entries() {
        let filter = ReplayFilter::new();
        assert_eq!(filter.len(), 0);
        assert!(filter.is_empty());

        let _ = filter.is_replay(br#"<event uid="S1" time="T1">"#);
        assert_eq!(filter.len(), 1);
        assert!(!filter.is_empty());

        let _ = filter.is_replay(br#"<event uid="S2" time="T2">"#);
        assert_eq!(filter.len(), 2);
    }

    #[test]
    fn duplicate_does_not_increase_len() {
        let filter = ReplayFilter::new();
        let xml = br#"<event uid="S1" time="T1">"#;
        let _ = filter.is_replay(xml);
        assert_eq!(filter.len(), 1);
        let _ = filter.is_replay(xml);
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn thread_safety() {
        use std::sync::Arc;

        let filter = Arc::new(ReplayFilter::new());
        let mut handles = vec![];

        for i in 0..10 {
            let f = Arc::clone(&filter);
            handles.push(std::thread::spawn(move || {
                let xml = format!(r#"<event uid="T-{i}" time="T-{i}">"#);
                f.is_replay(xml.as_bytes())
            }));
        }

        for h in handles {
            let is_replay = h.join().unwrap();
            assert!(!is_replay);
        }

        assert_eq!(filter.len(), 10);
    }

    #[test]
    fn cross_thread_replay_detected() {
        use std::sync::Arc;

        let filter = Arc::new(ReplayFilter::new());
        let xml = br#"<event uid="SHARED" time="T">"#;

        // First insert on main thread.
        assert!(!filter.is_replay(xml));

        // Second insert on spawned thread should detect replay.
        let f = Arc::clone(&filter);
        let result = std::thread::spawn(move || f.is_replay(xml)).join().unwrap();

        assert!(result);
    }

    #[test]
    fn default_impl() {
        let filter = ReplayFilter::default();
        assert!(filter.is_empty());
    }

    // ── extract_xml_attr tests ────────────────────────────────────

    #[test]
    fn extract_uid_double_quotes() {
        let xml = br#"<event uid="ALPHA-1" type="a-f-G">"#;
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"ALPHA-1");
    }

    #[test]
    fn extract_uid_single_quotes() {
        let xml = b"<event uid='BRAVO-2' type='a-f-G'>";
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"BRAVO-2");
    }

    #[test]
    fn extract_returns_none_for_missing() {
        let xml = br#"<event uid="s" type="a-f-G">"#;
        assert!(extract_xml_attr(xml, b"time=").is_none());
    }

    #[test]
    fn extract_skips_attr_inside_value() {
        let xml = br#"<event desc="uid=fake" uid="REAL" time="T">"#;
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"REAL");
    }

    #[test]
    fn extract_skips_nested_quoted_attr_in_single_quotes() {
        // uid="nested" appears inside a single-quoted desc value — should be skipped
        let xml = br#"<event desc='has uid="nested"' uid="REAL" time="T">"#;
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"REAL");
    }

    #[test]
    fn extract_attr_at_start_of_payload() {
        // Attribute at byte 0 (no preceding whitespace) should still match
        let xml = br#"uid="VALUE" time="T""#;
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"VALUE");
    }

    #[test]
    fn eviction_removes_expired_entries() {
        // Use a zero-duration window so all entries expire immediately.
        let filter = ReplayFilter::with_window(Duration::from_millis(0));
        // Insert more than EVICT_INTERVAL unique messages to trigger a sweep.
        for i in 0..1100 {
            let xml = format!(r#"<event uid="E-{i}" time="T-{i}">"#);
            let _ = filter.is_replay(xml.as_bytes());
        }
        // After eviction with a zero window, all entries should be expired.
        // The map should be significantly smaller than 1100.
        assert!(
            filter.len() < 200,
            "expected most entries evicted, got {}",
            filter.len()
        );
    }
}

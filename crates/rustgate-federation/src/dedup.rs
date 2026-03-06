//! Message deduplication for V1 federation loop detection.
//!
//! V1 federation uses length-prefixed XML over mTLS without provenance
//! metadata.  When two V1 servers are interconnected, messages can bounce
//! back and forth indefinitely.  This module detects duplicates by
//! extracting the stable CoT `uid` and `time` attributes from the raw
//! XML bytes and tracking recently-seen combinations in a bounded cache.
//!
//! The extraction uses fast byte-level scanning (no XML parsing) and
//! the cache uses FIFO eviction to stay within a fixed capacity.

use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};

/// Default maximum number of entries in the dedup cache.
const DEFAULT_CAPACITY: usize = 10_000;

/// Bounded message dedup cache.
///
/// Tracks recently-seen `(uid, time)` pairs from CoT XML messages.
/// When the cache reaches capacity, the oldest entry is evicted (FIFO).
pub struct MessageDedup {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl MessageDedup {
    /// Create a new dedup cache with the default capacity (10,000).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new dedup cache with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Check whether a payload has been seen before.
    ///
    /// Extracts the `uid` and `time` attributes from the CoT XML and
    /// checks the cache.  Returns `true` if the message is a duplicate.
    /// If the key cannot be extracted (non-CoT payload), returns `false`
    /// to avoid dropping unknown traffic.
    pub fn is_duplicate(&mut self, payload: &[u8]) -> bool {
        let key = match message_key(payload) {
            Some(k) => k,
            None => return false,
        };

        if self.seen.contains(&key) {
            return true;
        }

        // Evict oldest entry if at capacity
        if self.seen.len() >= self.capacity
            && let Some(old) = self.order.pop_front()
        {
            let _ = self.seen.remove(&old);
        }

        let _ = self.seen.insert(key);
        self.order.push_back(key);

        false
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for MessageDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MessageDedup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageDedup")
            .field("len", &self.seen.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Key extraction
// ---------------------------------------------------------------------------

/// Extract a hash key from a CoT XML payload.
///
/// Scans for `uid="..."` and `time="..."` attributes in the first 512
/// bytes of the payload and hashes them together.  Returns `None` if
/// either attribute is missing (non-CoT payload).
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
/// Returns the inner value (without quotes) as a byte slice.
fn extract_xml_attr<'a>(payload: &'a [u8], attr: &[u8]) -> Option<&'a [u8]> {
    let search_limit = payload.len().min(512);
    let haystack = &payload[..search_limit];

    // Find the attribute name (e.g., `uid=`)
    let attr_pos = haystack.windows(attr.len()).position(|w| w == attr)?;
    let value_start = attr_pos + attr.len();

    if value_start >= search_limit {
        return None;
    }

    // Determine the quote character (" or ')
    let quote = haystack[value_start];
    if quote != b'"' && quote != b'\'' {
        return None;
    }

    let content_start = value_start + 1;
    if content_start >= search_limit {
        return None;
    }

    // Find the closing quote
    let remaining = &haystack[content_start..];
    let end = remaining.iter().position(|&b| b == quote)?;

    Some(&payload[content_start..content_start + end])
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── extract_xml_attr ──────────────────────────────────────────

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
    fn extract_time_attribute() {
        let xml = br#"<event uid="s" time="2024-01-15T10:30:00Z" start="t">"#;
        let val = extract_xml_attr(xml, b"time=").unwrap();
        assert_eq!(val, b"2024-01-15T10:30:00Z");
    }

    #[test]
    fn extract_returns_none_for_missing_attr() {
        let xml = br#"<event uid="s" type="a-f-G">"#;
        assert!(extract_xml_attr(xml, b"time=").is_none());
    }

    #[test]
    fn extract_returns_none_for_empty() {
        assert!(extract_xml_attr(b"", b"uid=").is_none());
    }

    #[test]
    fn extract_returns_none_for_no_quote() {
        let xml = b"<event uid=noquote type=a-f-G>";
        assert!(extract_xml_attr(xml, b"uid=").is_none());
    }

    #[test]
    fn extract_respects_512_byte_limit() {
        let mut payload = vec![b' '; 510];
        payload.extend_from_slice(br#"uid="too-late""#);
        assert!(extract_xml_attr(&payload, b"uid=").is_none());
    }

    #[test]
    fn extract_at_boundary() {
        // uid= starts at position that puts value within 512 bytes
        let mut payload = vec![b'<'; 490];
        payload.extend_from_slice(br#"uid="ok""#);
        let val = extract_xml_attr(&payload, b"uid=").unwrap();
        assert_eq!(val, b"ok");
    }

    #[test]
    fn extract_empty_value() {
        let xml = br#"<event uid="" time="t">"#;
        let val = extract_xml_attr(xml, b"uid=").unwrap();
        assert_eq!(val, b"");
    }

    // ── message_key ───────────────────────────────────────────────

    #[test]
    fn message_key_stable() {
        let xml = br#"<event uid="S1" time="2024-01-01T00:00:00Z" type="a-f-G">"#;
        let a = message_key(xml);
        let b = message_key(xml);
        assert_eq!(a, b);
    }

    #[test]
    fn message_key_different_uid() {
        let a = message_key(br#"<event uid="A" time="T" type="a-f-G">"#);
        let b = message_key(br#"<event uid="B" time="T" type="a-f-G">"#);
        assert_ne!(a, b);
    }

    #[test]
    fn message_key_different_time() {
        let a = message_key(br#"<event uid="S" time="T1" type="a-f-G">"#);
        let b = message_key(br#"<event uid="S" time="T2" type="a-f-G">"#);
        assert_ne!(a, b);
    }

    #[test]
    fn message_key_none_without_uid() {
        let xml = br#"<event time="T" type="a-f-G">"#;
        assert!(message_key(xml).is_none());
    }

    #[test]
    fn message_key_none_without_time() {
        let xml = br#"<event uid="S" type="a-f-G">"#;
        assert!(message_key(xml).is_none());
    }

    #[test]
    fn message_key_ignores_flow_tags() {
        // Same uid+time but different flow tags → same key
        let a = br#"<event uid="S" time="T"><detail><_flow-tags_><source name="server-a"/></_flow-tags_></detail></event>"#;
        let b = br#"<event uid="S" time="T"><detail><_flow-tags_><source name="server-b"/></_flow-tags_></detail></event>"#;
        assert_eq!(message_key(a), message_key(b));
    }

    // ── MessageDedup ──────────────────────────────────────────────

    #[test]
    fn dedup_new_message_not_duplicate() {
        let mut dedup = MessageDedup::new();
        let xml = br#"<event uid="S1" time="T1" type="a-f-G">"#;
        assert!(!dedup.is_duplicate(xml));
    }

    #[test]
    fn dedup_same_message_is_duplicate() {
        let mut dedup = MessageDedup::new();
        let xml = br#"<event uid="S1" time="T1" type="a-f-G">"#;
        assert!(!dedup.is_duplicate(xml));
        assert!(dedup.is_duplicate(xml));
    }

    #[test]
    fn dedup_different_messages_not_duplicate() {
        let mut dedup = MessageDedup::new();
        let a = br#"<event uid="S1" time="T1" type="a-f-G">"#;
        let b = br#"<event uid="S2" time="T2" type="a-f-G">"#;
        assert!(!dedup.is_duplicate(a));
        assert!(!dedup.is_duplicate(b));
    }

    #[test]
    fn dedup_non_cot_not_duplicate() {
        let mut dedup = MessageDedup::new();
        // Non-CoT payload (no uid/time) should never be flagged as duplicate
        assert!(!dedup.is_duplicate(b"random binary data"));
        assert!(!dedup.is_duplicate(b"random binary data"));
    }

    #[test]
    fn dedup_evicts_oldest_at_capacity() {
        let mut dedup = MessageDedup::with_capacity(3);

        let m1 = br#"<event uid="S1" time="T1">"#;
        let m2 = br#"<event uid="S2" time="T2">"#;
        let m3 = br#"<event uid="S3" time="T3">"#;
        let m4 = br#"<event uid="S4" time="T4">"#;

        assert!(!dedup.is_duplicate(m1));
        assert!(!dedup.is_duplicate(m2));
        assert!(!dedup.is_duplicate(m3));
        assert_eq!(dedup.len(), 3);

        // Adding m4 should evict m1
        assert!(!dedup.is_duplicate(m4));
        assert_eq!(dedup.len(), 3);

        // m1 should no longer be detected as duplicate
        assert!(!dedup.is_duplicate(m1));
        // m2 should have been evicted now
        assert!(!dedup.is_duplicate(m2));
    }

    #[test]
    fn dedup_capacity_minimum_is_one() {
        let dedup = MessageDedup::with_capacity(0);
        assert_eq!(dedup.capacity, 1);
    }

    #[test]
    fn dedup_default() {
        let dedup = MessageDedup::default();
        assert_eq!(dedup.capacity, DEFAULT_CAPACITY);
        assert!(dedup.is_empty());
    }

    #[test]
    fn dedup_debug() {
        let dedup = MessageDedup::new();
        let debug = format!("{dedup:?}");
        assert!(debug.contains("MessageDedup"));
        assert!(debug.contains("len"));
        assert!(debug.contains("capacity"));
    }

    #[test]
    fn dedup_len_tracks_entries() {
        let mut dedup = MessageDedup::new();
        assert_eq!(dedup.len(), 0);
        assert!(dedup.is_empty());

        let _ = dedup.is_duplicate(br#"<event uid="S1" time="T1">"#);
        assert_eq!(dedup.len(), 1);
        assert!(!dedup.is_empty());

        let _ = dedup.is_duplicate(br#"<event uid="S2" time="T2">"#);
        assert_eq!(dedup.len(), 2);
    }

    #[test]
    fn dedup_duplicate_does_not_increase_len() {
        let mut dedup = MessageDedup::new();
        let xml = br#"<event uid="S1" time="T1">"#;
        let _ = dedup.is_duplicate(xml);
        assert_eq!(dedup.len(), 1);
        let _ = dedup.is_duplicate(xml);
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn dedup_same_uid_time_with_different_flow_tags() {
        let mut dedup = MessageDedup::new();
        let a = br#"<event uid="S" time="T"><detail><_flow-tags_><source name="a"/></_flow-tags_></detail></event>"#;
        let b = br#"<event uid="S" time="T"><detail><_flow-tags_><source name="b"/></_flow-tags_></detail></event>"#;
        assert!(!dedup.is_duplicate(a));
        assert!(dedup.is_duplicate(b)); // same uid+time = duplicate
    }

    #[test]
    fn dedup_large_capacity() {
        let mut dedup = MessageDedup::with_capacity(100_000);
        for i in 0..1000 {
            let xml = format!(r#"<event uid="S-{i}" time="T-{i}">"#);
            assert!(!dedup.is_duplicate(xml.as_bytes()));
        }
        assert_eq!(dedup.len(), 1000);
    }
}

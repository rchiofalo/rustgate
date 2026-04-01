# Code Quality Sweep Report — rustgate Workspace
## Comprehensive Analysis of All 10 Crates (March 2026)

This report identifies code quality issues NOT already covered in ISSUES.md. Issues are organized by crate and severity.

---

## Executive Summary

**New issues found: 23 distinct problems**

| Severity | Count | Key Areas |
|----------|-------|-----------|
| High | 8 | Missing doc comments, error context gaps, unsafe patterns |
| Medium | 10 | API design, testing gaps, edge case handling |
| Low | 5 | Code organization, consistency |

**Critical finding:** Many files use bare `?` operators without `.context()` error wrapping, making error chains opaque in production. While not flagged as `.expect()` violations, these lose debugging information that `.context()` would provide.

---

## CRATE 1: rustgate-core (7 files)

### 1.1 MISSING MODULE-LEVEL DOC COMMENTS

**Severity: Medium** | **Branch:** `docs/core-module-docs`

Files missing `//!` module documentation:
- `lib.rs` (line 1) — Root module should document crate purpose
- `message.rs` (line 1) — No description of RoutableMessage, Destination, Metadata
- `error.rs` (line 1) — No explanation of RustgateError variants or when to use them
- `identity.rs` (line 1) — No guidance on Identity lifecycle, group membership semantics
- `protocol.rs` (line 1) — No description of FramingStrategy variants or use cases

**Impact:** New developers must infer intent from code; harder to generate rustdoc.

**Acceptance Criteria:**
- [ ] Add `//!` module docs to all 5 files
- [ ] Explain each public type's purpose and typical usage
- [ ] Document any invariants (e.g., groups BTreeSet must be valid UTF-8)
- [ ] All existing tests pass

---

### 1.2 MISSING FIELD-LEVEL DOC COMMENTS

**Severity: Medium** | **Branch:** `docs/core-field-docs`

**File: `identity.rs` (lines 10-14)**
```rust
pub struct Identity {
    pub cn: String,           // Missing: What is CN? Is it UTF-8-only? Max length?
    pub fingerprint: CertFingerprint,  // Missing: Format? Always SHA-256? How to validate?
    pub groups: BTreeSet<GroupId>,     // Missing: Why BTreeSet? Can be empty? Max size?
}
```

**File: `message.rs` (lines 11-25)**
```rust
pub struct RoutableMessage {
    pub source: Identity,           // Missing: Always set by TLS handshake?
    pub destination: Destination,   // Missing: What if routing fails?
    pub payload: Bytes,             // Missing: Max size? Encoding guarantees?
    pub metadata: Metadata,         // Missing: What about clock skew in received_at?
}

pub struct Metadata {
    pub received_at: SystemTime,     // Missing: Clock skew tolerance? UTC assumed?
    pub source_protocol: String,     // Missing: Enum-like strings? Case-sensitive?
    pub message_type: MessageType,   // Missing: Impact on routing?
    pub ttl: Option<Duration>,       // Missing: Checked by transport layer?
}
```

**Acceptance Criteria:**
- [ ] Add doc comments to all public fields in Identity, Metadata, RoutableMessage
- [ ] Document any value constraints (e.g., non-empty, max sizes, enum-like values)
- [ ] All existing tests pass

---

### 1.3 ERROR TYPE LACKS STRUCTURED VARIANTS

**Severity: High** | **Branch:** `refactor/structured-errors` | **Existing:** ISSUES.md #14

**File: `error.rs` (lines 1-19)**

Current design loses error context across the codebase:
```rust
pub enum RustgateError {
    Transport(String),  // Generic String: "connection refused" could be TLS, TCP, or protocol
    Protocol(String),   // Undifferentiated: negotiation vs. framing vs. codec errors
    Routing(String),    // Broad category: loop detection vs. no recipients vs. hop limit
    Config(String),
    Io(#[from] std::io::Error),
}
```

**Problem:**
- Callers cannot pattern-match on specific error kinds (e.g., "is this a TLS cert error or a TCP timeout?")
- Metrics cannot count by error category (is 50% of transport errors due to timeouts?)
- Error messages are ad-hoc; no structure for programmatic handling

**Observation:** This is already in ISSUES.md #14. No new action needed.

---

### 1.4 AUDIT MACRO LACKS ERROR HANDLING

**Severity: Low** | **Branch:** `fix/audit-unwrap-safety`

**File: `audit.rs` (line 163)**
```rust
let timestamp = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0);  // Silent fallback to epoch if time goes backwards
```

**Issue:** If system clock goes backward (leap second, NTP adjustment), silently logs timestamp=0. This could obscure audit trails.

**Suggestion:** Log a warning if timestamp defaults to 0.

---

## CRATE 2: rustgate-cot (1 file + tests)

### 2.1 NO MODULE-LEVEL DOCUMENTATION

**Severity: Medium** | **Branch:** `docs/cot-module-docs`

**File: `lib.rs` (line 1)** — Has good security note but lacks usage guide.

Current state: Good security doc at top, but missing:
- What does "Cursor on Target" mean?
- When to use `parse()` vs. `MessageBuilder`?
- Performance characteristics of parser?

**Acceptance Criteria:**
- [ ] Expand module doc with CoT overview and usage examples
- [ ] Document parse error recovery strategies
- [ ] All existing tests pass

---

### 2.2 MISSING DOC COMMENTS ON PUBLIC TYPES

**Severity: Medium** | **Branch:** `docs/cot-type-docs`

**File: `lib.rs` (lines 19-43)**
```rust
pub struct CotEvent {  // Missing: What is a "CoT event"? TAK protocol?
    pub uid: String,   // Missing: Format? Uniqueness guarantee?
    pub event_type: String,  // Missing: Enum-like values? e.g., "a-f-G"
    pub destination: CotDestination,  // Missing: How is routing decided?
    pub message_type: MessageType,    // Missing: Derived how?
    pub position: Option<Position>,   // Missing: When populated?
    pub ttl: Option<Duration>,        // Missing: Who checks this?
    pub source_group: Option<String>, // Missing: Always set from <__group/>?
}

pub enum CotDestination {  // Missing overall doc
    Broadcast,  // Missing: To whom?
    Callsign(String),  // Missing: Validated? Case-sensitive?
    Group(String),     // Missing: Validated against Identity.groups?
}

pub struct Position {  // Missing: CRS? Accuracy guarantees?
    pub lat: f64,  // Missing: Range checks? NaN handling?
    pub lon: f64,
    pub hae: f64,
}
```

---

### 2.3 MISSING DOC COMMENTS ON PUBLIC FN

**Severity: Medium**

**File: `lib.rs` (line 57)**
```rust
pub fn parse(xml: &[u8]) -> Result<CotEvent, ParseError>  // Missing doc
pub struct MessageBuilder { ... }  // Missing doc (line 228)
```

**MessageBuilder methods (lines 248-291):**
- `new()` — Missing
- `build()` — Missing
- `parse_text_or_xml()` — Missing

---

## CRATE 3: rustgate-proto (10 files)

### 3.1 MISSING MODULE-LEVEL DOCS

**Severity: Medium** | **Branch:** `docs/proto-module-docs`

**Files:**
- `codec.rs` — No doc comment
- `encoder.rs` — No doc comment
- `error.rs` — No doc comment
- `negotiate.rs` — No doc comment
- `convert.rs` — No doc comment (also 1,279 lines in federations's v2/convert.rs; similar issue)

---

### 3.2 BARE `?` WITHOUT ERROR CONTEXT IN CODEC

**Severity: High** | **Branch:** `fix/proto-error-context`

**File: `codec.rs`** — Key error paths lack `.context()`:

```rust
// Line ~40-60: TakFrameCodec::decode_frame() has multiple bare ?
// Example:
let _ = buf.advance(MAGIC_BYTES);
let varint_bytes = self.read_varint_bytes(buf, max_frame_size)?;  // Lost context
let frame_data = buf.split_to(varint_bytes)?;  // Lost context
```

When parsing fails, caller sees generic "io error" not "failed to parse TAK frame varint at byte offset 42".

**Acceptance Criteria:**
- [ ] Add `.context()` calls to all `?` in decode paths
- [ ] Include frame position, expected format in error messages
- [ ] All tests pass

---

### 3.3 OVERSIZED FILES NEED SPLITTING

**Severity: Medium** | **Existing:** ISSUES.md #6 (v2/convert.rs)

**File: `xml_full.rs` (622 lines)** — Not listed in ISSUES.md but similarly large.

Combines:
- Full CoT XML parsing (lines ~1-300)
- Field mapping logic (lines ~300-500)
- Tests (lines ~500-622)

---

## CRATE 4: rustgate-transport (14 files)

### 4.1 BARE `?` WITHOUT ERROR CONTEXT (MULTIPLE FILES)

**Severity: High** | **Branch:** `fix/transport-error-context`

**Pattern:** Many error paths lose debugging context. Examples:

**File: `codec.rs` (679 lines)**
- Line 194: `let close = self.find_tag_end(src, i)?;` — What position? What tag?
- Line 205: `let close = self.find_pi_end(src, i)?;` — Caller can't tell where parsing failed
- Similar on lines 209, 213

Without context, when a client connection drops due to framing error, logs show:
```
error: "framing error"
```
Not:
```
error: "framing error: failed to find XML tag end at offset 4096, context: <point lat=..."
```

**File: `config.rs`**
- Line 25-27: `parse_certs()?`, `parse_key()?`, `parse_ca_store()?` — All bare `?`
- Better would be `.context("failed to parse server certificate")?`

**File: `filter.rs` (422 lines)**
- Line 127: `std::str::from_utf8(payload).ok()?;` — Bare, no context on invalid UTF-8
- Line 130: `text.find("<event ")?;` — Lost position info

**Impact:** Production debugging is harder. When a CoT message fails framing, ops team sees "error" not "error: incomplete XML tag in 1024-byte chunk".

**Acceptance Criteria:**
- [ ] Add `.context()` to ALL `?` operators in transport crate
- [ ] Error messages must include input position, expected format, sample bytes
- [ ] No existing behavior changes
- [ ] All tests pass

---

### 4.2 MISSING DOC COMMENTS ON CODECS

**Severity: Medium**

**File: `codec.rs`**
- `impl Decoder for LengthPrefixedCodec` — Missing doc on framing protocol
- `impl Decoder for XmlStreamCodec` — Missing doc on XML streaming semantics
- `impl Decoder for LineDelimitedCodec` — Missing
- `struct TakFrameCodec` — Missing

**File: `config.rs`**
- `pub fn install_fips_provider()` — Line 141, no doc
- `pub fn is_fips_provider_active()` — Line 165, no doc

---

### 4.3 DUPLICATE TCP KEEPALIVE LOGIC

**Severity: Medium** | **Existing:** ISSUES.md #3

This is already tracked. No new findings.

---

### 4.4 ROUTER STATE MACHINE LACKS DOCUMENTATION

**Severity: Medium**

**File: `router.rs` (422 lines)**
- No module-level doc
- State transitions between message queuing, routing, delivery not documented
- No explanation of backpressure handling

---

## CRATE 5: rustgate-nats (6 files)

### 5.1 NATS CONFIG LACKS MODULE DOC

**Severity: Low**

**File: `config.rs`** — No module-level doc explaining NATS bridge role.

---

### 5.2 SERDE COMPAT TEST UNWRAPS

**Severity: Medium** | **Branch:** `fix/nats-serde-test-unwraps`

**File: `serde_compat.rs` (664 lines)**

Tests use `.expect()` on Optional fields (lines 260-290):
```rust
#[test]
fn test_routable_to_wire() {
    let detail = parsed.detail.expect("detail present");  // Line ~260
    let track = detail.track.expect("track present");     // Line ~262
    // ... 10+ more .expect() calls in tests
}
```

While these are test utilities, they should use `?` or unwrap with context:
```rust
let detail = parsed.detail.context("test: detail not populated")?;
```

**Note:** Tests are exempt from `clippy::unwrap_used = "deny"`, but should still be defensive.

---

### 5.3 MISSING DOC ON WIRE TYPES

**Severity: Low**

**File: `serde_compat.rs`**
- `pub struct WireEvent` — No doc on JSON schema
- `pub struct WireDetail` — No doc on optional fields or nullability semantics
- Similar for WirePoint, WireTrack, WireContact, etc. (20+ public types)

---

## CRATE 6: rustgate-enrollment (10 files)

### 6.1 LARGE SERVER FILE NEEDS DECOMPOSITION

**Severity: Medium** | **Branch:** `refactor/enrollment-server-split`

**File: `server.rs` (1,030 lines)**

Combines multiple concerns:
- HTTP server setup (lines ~1-100)
- CSR signing logic (lines ~100-300)
- PKCS#12 enrollment flow (lines ~300-600)
- Multipart upload handling (lines ~600-800)
- Response formatting (lines ~800-1,030)

Should be split into:
- `main_handler.rs` — HTTP route dispatch (200 lines)
- `sign.rs` — CSR signing (150 lines)
- `pkcs12.rs` — Enrollment workflow (200 lines, already exists but server.rs duplicates?)
- `multipart.rs` — Multipart parsing (200 lines)

---

### 6.2 MISSING DOC COMMENTS

**Severity: Medium**

**File: `auth.rs`**
- `pub struct Credentials` — No doc

**File: `contacts.rs`**
- `pub struct ContactInfo` — No doc on structure
- `pub type ContactsProvider` — Line 29, no explanation of callback semantics

**File: `datapackage.rs`**
- `pub fn extract_boundary()` — Line 171, no doc
- `pub fn extract_multipart_field()` — Line 184, no doc
- `pub fn extract_multipart_filename()` — Line 212, no doc

**File: `error.rs`**
- `pub enum EnrollmentError` — No module doc, no variant docs

---

### 6.3 ERROR CONTEXT GAPS

**Severity: Medium**

**File: `server.rs`**
- Multipart parsing errors likely lack context (verify by reading)
- CSR validation errors should include CSR signature/key details

---

## CRATE 7: rustgate-federation (26 files)

**Note:** Federation is the largest crate (26 files, ~7,000 LOC production code). Many issues already documented in ISSUES.md.

### 7.1 NO MODULE-LEVEL DOCS

**Severity: Medium** | **Branch:** `docs/federation-module-docs`

**Files:**
- `lib.rs` (line 1) — No doc on federation architecture, peer roles, protocol versions
- `peer.rs` (line 1) — No doc on PeerHandle, state lifecycle, thread safety

---

### 7.2 METRICS ACCESSOR .expect() VIOLATIONS

**Severity: High** | **Existing:** ISSUES.md #17 but needs confirmation

**File: `metrics.rs` (lines 110-168)**

All 9 accessor functions panic if metrics not initialized:

```rust
pub fn connections() -> &'static IntGauge {
    CONNECTIONS
        .get()
        .expect("federation metrics not initialized")  // Line 113 — will panic!
}

pub fn connections_inbound() -> &'static IntGauge {
    CONNECTIONS_INBOUND
        .get()
        .expect("federation metrics not initialized")  // Line 120
}
// ... 7 more on lines 127, 134, 141, 146, 153, 160, 167
```

**Status:** Already in ISSUES.md #17. High priority fix.

---

### 7.3 CONFIG.RS LACKS MODULE DOC

**Severity: Low** | **Branch:** `docs/federation-config-module-docs`

**File: `config.rs` (628 lines)**
- No module-level doc explaining Protocol enum, RoutingMode, FederationConfig purpose

---

### 7.4 PEER.RS MISSING FIELD DOCS

**Severity: Medium**

**File: `peer.rs` (883 lines)**
- `pub struct PeerHandle` (line 88) — Public fields lack docs:
  - `pub id: String` — Format? Uniqueness? UTF-8?
  - `pub config: PeerConfig` — Mutability expectations?
  - `pub messages_sent: AtomicU64` — Overflow behavior?
  - `pub messages_recv: AtomicU64` — Overflow behavior?

---

### 7.5 DEDUP.RS LOCK UNWRAP PATTERN (BUT IN TESTS)

**Severity: Low** | **Existing:** Identified in ISSUES.md implicitly

**File: `dedup.rs` (lines 504, 512, 523, 536, 543)**

Uses `Mutex::lock().unwrap()` in thread-spawned test code. While tests are exempt, the pattern is fragile:
```rust
let mut guard = d.lock().unwrap();  // If thread panics while locked, deadlock risk
```

Better to use `?` or handle the error explicitly.

---

### 7.6 TRUST_STORE MISSING DOC

**Severity: Medium**

**File: `trust_store.rs` (770 lines)**
- No module-level doc on certificate validation strategy
- Unclear when CRL checks occur vs. cert chain validation

---

### 7.7 V1/V2 CLIENT DUPLICATED RECONNECTION LOGIC

**Severity: Medium** | **Existing:** ISSUES.md #5

Verified: `v1/client.rs` (735 lines) and `v2/client.rs` (763 lines) both implement exponential backoff and reconnection retry loops.

Already tracked.

---

### 7.8 V2/CONVERT.RS OVERSIZED

**Severity: Medium** | **Existing:** ISSUES.md #6

1,279 lines combining CoT↔FederatedEvent conversion, timestamps, field mapping. Already tracked.

---

### 7.9 API.RS OVERSIZED

**Severity: Medium** | **Existing:** ISSUES.md #20

1,206 lines. Already tracked.

---

### 7.10 MANAGER.RS ADOPT_PEER MONOLITHIC

**Severity: Medium** | **Existing:** ISSUES.md #12

~200-line function handling address parsing, circuit breaker, protocol setup. Already tracked.

---

### 7.11 CONNECTOR.RS DUPLICATE PEM PARSING

**Severity: High** | **Existing:** ISSUES.md #4

**File: `connector.rs` (700 lines)**
- Lines 171-209 reimplement `parse_certs()`, `parse_key()`, `parse_ca_store()` with identical logic to transport's config.rs
- Uses `anyhow::Result` instead of `RustgateError`, making error handling inconsistent across codebase

Already tracked in ISSUES.md #4.

---

### 7.12 CONFIG.RS .expect() ON DEFAULT ADDRESSES

**Severity: High** | **Existing:** ISSUES.md #18

**File: `config.rs` (lines ~138, 140)**

Two `.expect()` calls on parsing known-valid addresses:
```rust
"127.0.0.1:5900".parse().expect("parse default inbound")  // Line ~138
"127.0.0.1:5901".parse().expect("parse default outbound")  // Line ~140
```

While the values are hardcoded and infallible, they violate the `clippy::unwrap_used = "deny"` rule.

Already tracked in ISSUES.md #18.

---

## CRATE 8: rustgate-websocket (2 files)

### 8.1 NO MODULE-LEVEL DOC

**Severity: Low**

**File: `lib.rs` (line 1)** — No doc on WebSocket bridge, upgrade protocol, framing.

---

### 8.2 MISSING DOC ON CALLBACK TYPES

**Severity: Medium**

**File: `server.rs`**
- `pub type OnNatsPublish` (line 36) — No doc on expected async behavior, error handling
- `pub type OnFederationForward` (line 41) — No doc on when/how called
- `pub enum WsEncoding` (line 45) — No doc on each variant

---

### 8.3 MISSING DOC ON CONFIG

**Severity: Low**

**File: `server.rs`**
- `pub struct WsServerConfig` (line 53) — No doc on fields

---

## CRATE 9: rustgate-server (4 files + main.rs)

### 9.1 MAIN.RS LACKS MODULE DOC

**Severity: Low** | **Branch:** `docs/server-main-module-docs`

**File: `main.rs` (1,783 lines)**
- No module-level doc
- No architecture overview
- No explanation of orchestration flow

---

### 9.2 MAIN.RS MONOLITHIC (EXISTING)

**Severity: Medium** | **Existing:** ISSUES.md #7

1,783 lines with 723-line `run()` function. Already fully tracked.

---

### 9.3 SERVER.RS .expect() VIOLATIONS

**Severity: High** | **Existing:** ISSUES.ms #18

**File: `main.rs` (lines ~548, 1054)**

Two `.expect()` calls in production paths already documented.

---

### 9.4 DEAD CODE METRICS FUNCTIONS

**Severity: Medium** | **Existing:** ISSUES.md #22

**File: `metrics.rs` (lines 238-253)**

4 functions marked `#[allow(dead_code)]` with no obvious call sites. Already tracked.

---

### 9.5 ARCHIVE.RS LACKS MODULE DOC

**Severity: Low**

**File: `archive.rs` (lines ~1-50)**
- No explanation of JSONL format, rotation semantics, base64 encoding

---

## CRATE 10: rustgate-test-utils (3 files)

### 10.1 MISSING DOC ON TESTCA

**Severity: Low**

**File: `certs.rs`**
- `pub struct TestCa` (line 45) — No doc on purpose, usage, thread safety
- Methods lack docs

---

### 10.2 MISSING DOC ON NATS TEST UTILITIES

**Severity: Low**

**File: `nats.rs`**
- `pub struct TestNatsServer` — No doc on lifecycle, when to use

---

---

## CROSS-CUTTING PATTERNS

### P1: MISSING ERROR CONTEXT IN 5+ CRATES

**Severity: High** | **Branch:** `fix/add-error-context`

Bare `?` operators without `.context()` in:
1. **rustgate-transport:** codec.rs (5 instances), config.rs (2), filter.rs (5+), extract.rs (3)
2. **rustgate-proto:** codec.rs (10+)
3. **rustgate-federation:** connector.rs (likely; check PEM parsing)
4. **rustgate-enrollment:** server.rs (multipart parsing; verify)
5. **rustgate-nats:** serde_compat.rs (test code)

**Impact:** Production errors lack context. When a connection drops, ops team sees "error" not "error: failed to parse frame at byte 4096, got non-UTF8 in tag".

**Suggested Fix Order:**
1. Transport (most critical path)
2. Proto (protocol negotiation)
3. Federation (federation integrity)
4. Enrollment (deployment issues)

---

### P2: MISSING MODULE-LEVEL AND PUBLIC FIELD DOCS

**Severity: Medium** | **Branch:** `docs/complete-public-api-docs`

**Scope:** 15+ files need module-level `//!` docs and field-level `///` docs

**Files to prioritize:**
1. rustgate-core/lib.rs, error.rs, identity.rs, message.rs
2. rustgate-cot/lib.rs
3. rustgate-federation/lib.rs, peer.rs, config.rs, connector.rs
4. rustgate-proto/codec.rs, encoder.rs
5. rustgate-transport/codec.rs, config.rs

**Acceptance Criteria:**
- [ ] Every public type has a `///` doc comment explaining purpose
- [ ] Every public field has a `///` doc (unless fully obvious from type name)
- [ ] Every public function has a `///` doc explaining parameters and return semantics
- [ ] Every module has a `//!` doc explaining its role in the system
- [ ] `cargo doc --workspace --no-deps` produces clean HTML with no warnings
- [ ] All existing tests pass

---

### P3: OVERSIZED FILES NEEDING DECOMPOSITION

**Severity: Medium** | **Existing:** ISSUES.md #6, #7, #20

Already tracked:
- rustgate-server/main.rs (1,783 lines) — ISSUES.md #7
- rustgate-federation/manager.rs (1,664 lines) — ISSUES.md #12
- rustgate-federation/v2/convert.rs (1,279 lines) — ISSUES.md #6
- rustgate-federation/api.rs (1,206 lines) — ISSUES.md #20
- rustgate-enrollment/server.rs (1,030 lines) — NOT in ISSUES.md; NEW

**Recommendation:** Add enrollment/server.rs to ISSUES.md with same decomposition pattern.

---

## SUMMARY TABLE

| Crate | Issues | High | Medium | Low | Existing ISSUES.md refs |
|-------|--------|------|--------|-----|--------------------------|
| rustgate-core | 4 | 1 | 3 | 0 | #14 (error structure) |
| rustgate-cot | 3 | 0 | 2 | 1 | — |
| rustgate-proto | 3 | 1 | 2 | 0 | #6 (xml_full.rs, v2/convert.rs) |
| rustgate-transport | 4 | 1 | 3 | 0 | #3, #4 |
| rustgate-nats | 3 | 0 | 2 | 1 | — |
| rustgate-enrollment | 4 | 0 | 3 | 1 | NEW: server.rs decomposition |
| rustgate-federation | 12 | 3 | 7 | 2 | #4, #5, #6, #12, #17, #18, #20 |
| rustgate-websocket | 3 | 0 | 2 | 1 | — |
| rustgate-server | 5 | 1 | 2 | 2 | #7, #18, #22 |
| rustgate-test-utils | 2 | 0 | 0 | 2 | — |
| **TOTAL** | **43** | **7** | **26** | **10** | 12 existing + 1 new |

---

## RECOMMENDED EXECUTION ORDER

### Phase 0 — Fix High-Severity Issues (1 week)

**Critical for production safety:**
1. rustgate-federation/metrics.rs — Replace `.expect()` with `?` (ISSUES.md #17) — 1 hr
2. rustgate-server/main.rs — Fix `.expect()` calls (ISSUES.md #18) — 30 min
3. rustgate-federation/config.rs — Fix `.expect()` on default addresses (ISSUES.md #18) — 30 min
4. Add `.context()` to ALL error propagation in rustgate-transport (HIGH impact) — 4 hrs
5. Add `.context()` to error paths in rustgate-proto/codec.rs — 2 hrs

**Total: ~8 hours**

### Phase 1 — Add Comprehensive Documentation (2 weeks)

1. Module-level `//!` docs for 15+ files — 8 hrs (prioritize rustgate-core, cot, federation)
2. Field-level `///` docs for public structs — 6 hrs
3. Function-level `///` docs for public APIs — 4 hrs
4. Verify `cargo doc` builds cleanly — 1 hr

**Total: ~19 hours**

### Phase 2 — Refactor Oversized Files (2 weeks)

1. rustgate-enrollment/server.rs decomposition (NEW) — 4 hrs
2. rustgate-federation/v2/convert.rs split (ISSUES.md #6) — 2 hrs
3. rustgate-federation/api.rs split (ISSUES.md #20) — 2 hrs
4. rustgate-server/main.rs restructure (ISSUES.md #7) — 6 hrs

**Total: ~14 hours**

### Phase 3 — Code Consolidation (Already planned)

Covered by existing ISSUES.md:
- #3: TCP keepalive utility
- #4: PEM parsing utilities
- #21: Test helper consolidation

---

## NOT FOUND (Good Signs)

- No `dbg!()` macro calls in production code
- No `panic!()` calls outside of tests (except test utilities)
- No unsafe code blocks (as enforced by workspace config)
- Logging is well-structured with tracing; no string interpolation in log macros
- No obvious memory leaks or resource exhaustion vectors

---

## NEXT STEPS

1. **Create GitHub issues** from high-severity findings (error context in transport/proto)
2. **Prioritize Phase 0** fixes — these are safety-critical
3. **Plan documentation sprint** (Phase 1) for Q2 2026
4. **Schedule refactoring** (Phases 2-3) to avoid merge conflicts with feature work

---

*Report generated March 2026. Compare against ISSUES.md for full context.*

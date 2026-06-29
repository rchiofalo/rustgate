# Ultracode Red-Team & Deep-Analysis Checklist (rustgate)

> A one-hour, maximum-intensity security pass over rustgate. Codifies the
> taint-to-sink + exploit-trace + adversarial-refutation methodology used in
> the 2026-06 audit rounds. Work it top-to-bottom or jump to a surface.
>
> **Golden rule for every box below:** a finding is not real until you have
> **(a)** the exact `file:line`, **(b)** the offending line *quoted*, and
> **(c)** a concrete attack trace `untrusted input → entry fn → vulnerable
> line → impact` with nothing in between that stops it. No trace ⇒ not a
> finding (yet).

---

## 0. Posture & method (read first)

- [ ] **Assume-vulnerable-until-proven-safe.** Pick a path, prove it *safe* by
      reading it — don't assume a guard exists.
- [ ] **Source → sink.** Start at an attacker-controlled SOURCE, follow the
      data to a dangerous SINK, ask what (if anything) on the path stops it.
- [ ] **Exploit-trace to CONFIRM, quoted-guard to REFUTE.** To kill a candidate
      you must quote the cap/guard/type/early-return that makes it impossible,
      that it is already handled, that the input is not attacker-reachable, or
      that it is a *documented* intentional opt-in.
- [ ] **Recall over precision while hunting; precision while verifying.** When
      unsure, keep it as PLAUSIBLE and verify second — don't drop silently.
- [ ] **Dedup against known issues** (§9) so you report only NEW bugs.
- [ ] **Severity honestly.** Downgrade if impact is smaller than it first looks;
      note feature-flag / non-default gating that lowers reachability.

### Threat actors (ask "which of these reaches this code?")
- [ ] Malicious/compromised **mTLS client** (valid cert, hostile payloads/framing)
- [ ] Malicious/compromised **federated peer** (gRPC, JWT, replay, hop count, group claims)
- [ ] Malicious **enrolling client** (CSR / EST / PKCS#12, auth, rate-limit)
- [ ] **Unauthenticated** attacker spraying crafted **tactical packets** at the
      live UDP/TCP codec ingress (DIS/ASTERIX/VMF/Link16/STANAG/MAVLink/CoT/
      SAPIENT/meshtastic) — **highest-value DoS/memory surface, no auth**
- [ ] Hostile **HTTP upstream** the webhook egress talks to (responses, redirects, timing)
- [ ] Hostile **NATS / MQTT / WebSocket** client (subject/topic injection, compression bombs)
- [ ] **Local** attacker on a multi-tenant host (symlinks, file perms, /proc)
- [ ] **Network** attacker (downgrade, replay, MITM within mTLS limits)

---

## 1. Setup (≈5 min)

- [ ] `git log origin/main --oneline -30` — what changed recently (fresh code = fresh bugs)
- [ ] `gh issue list --state open --label security` — load the exclusion set (§9)
- [ ] Build the **source map**: `rg -n "into_body\(\)|recv_from|read_buf|peer_certificates|from_der|deserialize|from_slice|parse"` across `crates/*/src`
- [ ] Build the **sink map**: `rg -n "with_capacity\(|reserve\(|vec!\[|\.\.\]|\[[a-z_]+\]|as usize|as u32| - |unwrap\(|expect\(|format!\(|tokio::spawn|\.await"` (scope per crate)
- [ ] Decide scope/time-box (use the §10 hour plan).

---

## 2. Untrusted ingress — codec parsers (the unauthenticated surface) ⚠️ highest value

Crates: `rustgate-dis`, `rustgate-asterix`, `rustgate-vmf`, `rustgate-link16`,
`rustgate-stanag4586`, `rustgate-mavlink`, `rustgate-nffi`, `rustgate-sapient`,
`rustgate-meshtastic`, `rustgate-cot`, `rustgate-codec-schema` (runtime),
`rustgate-transport` (`codec.rs`, `codec_tcp_ingress.rs`, `udp_multicast.rs`).

### Panic hunt (panic = remote DoS on an unauth datagram)
- [ ] Every `unwrap()` / `expect()` on a path reachable from a decode entry fn
- [ ] Every slice index `buf[i]` and range `buf[a..b]` — is `i`/`a`/`b` bounded vs `buf.len()`?
- [ ] Every `array[const]` after a length check that could be `<` the const
- [ ] Integer division / modulo where the divisor comes from the wire (`/ 0` panics)
- [ ] `.try_into().unwrap()`, `[u8; N]::try_from(slice).unwrap()` on attacker length
- [ ] `char::from_u32(...).unwrap()`, `from_utf8(...).unwrap()` on attacker bytes
- [ ] Recursive descent with no depth cap (stack overflow = abort)

### Integer overflow / underflow / truncation
- [ ] `len as usize` / `count as usize` where the wire value is larger than expected
- [ ] `a - b` where `b` can exceed `a` (underflow → huge usize → OOB/alloc)
- [ ] `n * elem_size` for a buffer size (multiply overflow → small alloc, big write)
- [ ] Sign-extension on `as i32 → as usize`; truncation on `as u16`/`as u8`
- [ ] Offset/length fields trusted without `offset + len <= buf.len()` check

### Unbounded allocation from a wire length
- [ ] `Vec::with_capacity(n)` / `reserve(n)` / `vec![0; n]` where `n` is an
      attacker length field read **before** the bytes arrive (claim "1 GiB", send 10 B)
- [ ] `read_to_end` / `collect` / `repeat(n)` driven by a count field
- [ ] Frame size honored against `rustgate_core::constants::MAX_FRAME_SIZE` (16 MiB)?
- [ ] Per-element loop bounded by a count field with no ceiling

### CoT / XML specifics (`rustgate-cot`, `XmlStreamCodec`)
- [ ] XML entity expansion / billion-laughs; nesting depth cap on `<detail>`
- [ ] `delta.rs` reconstruction: text re-escaped on output? unmatched close tags? (see #1609/#1610)
- [ ] `mask.rs` reconstruction well-formedness invariant
- [ ] CDATA / comments / namespaced / attribute-positioned markings handled

> Trace template: *attacker UDP datagram → `<codec>::decode`/`Codec::decode`
> → the slice/alloc/arith line → panic-abort or N-byte heap.*

---

## 3. TLS / mTLS & certificate identity

Crate: `rustgate-tls` (`verifier.rs`, `extract.rs`, `config.rs`, `client_ocsp.rs`,
`session.rs`, `listener.rs`, `crl_store.rs`, `pem.rs`).

- [ ] **EKU enforcement parity across transports.** webpki `client_auth()` is
      `RequiredIfPresent` (accepts a cert with no EKU). Confirm **every** identity
      extraction calls `validate_key_usage(cert, ExpectedKeyUsage::ClientAuth)` —
      TLS listener, WebSocket, MQTT, federation, plaintext. (gap class: #1620)
- [ ] CN / SAN / attribute extraction caps enforced (`MAX_SAN_ENTRIES_PER_CATEGORY=32`,
      `MAX_ATTR_BAG_BYTES=4KiB`, `MAX_CN_LENGTH=256`)
- [ ] Identity spoof via duplicate/ordered cert fields (first-match vs all-match)
- [ ] CN normalized to ASCII-lowercase at **both** insert and lookup (defense in depth)
- [ ] Verifier / CRL **rebuild race** during a concurrent handshake (generation logic in `verifier.rs`)
- [ ] Cert reload (`CertReloader`) mid-handshake atomicity
- [ ] OCSP / CRL staleness: fail-open default? stale CRL still trusted? (CRL lifecycle: #1496)
- [ ] Downgrade: `tls_min_version` actually enforced; no plaintext fallback
- [ ] Client identity comes from the **cert**, never the IP address

---

## 4. Authorization, ACL & PEP

Crates: `rustgate-authz` (`engine.rs`, `cache.rs`, `compile.rs`, `cedar`),
`rustgate-router` (`router.rs` ACL/PEP, `dedup`, `cache`).

- [ ] **Deny-first**, **default-deny** when a policy is loaded (unconfigured group denied)
- [ ] CN normalization / Unicode-equivalence bypass before ACL match (`nfc()` + lowercase)
- [ ] **Fail-open logic**: `is_none_or(...)`, `unwrap_or(true)`, `?`-into-allow — are these only the *documented* `--authz-fail-open`?
- [ ] An authz/ACL check **skipped on one delivery path** (direct vs group vs broadcast vs replay vs store-forward drain)
- [ ] Authz cache: key collision / poisoning; the dual-hash `SubjectHash` actually 128-bit; normalization matches between compile and lookup
- [ ] ABAC attribute spoofing via cert attributes
- [ ] Off-by-one / inverted comparison / negation error in the decision

---

## 5. Authorization on state *restore* / replay (a recurring bug class)

- [ ] **Store-and-forward drain** re-evaluates ACL **and** authz against the
      client's **current** cert groups (policy may have changed offline)
- [ ] **Position-cache replay** (`replay_positions`) re-checks Receive PEP per entry
- [ ] **MQTT session restore** re-validates each re-joined subscription against
      current cert membership (don't trust the persisted session) — gap class: #1605
- [ ] Federation store-forward replays with consistent hop-limit envelope (#1519)
- [ ] Any "restore without re-check" — grep `join_group`, `restore`, `replay`, `drain` for a missing `is_member_of` / PEP call

---

## 6. Federation trust, replay & state machine

Crate: `rustgate-federation` (`manager.rs`, `v2/server.rs`, `jwt.rs`, `jwks.rs`,
`connector.rs`, `mesh*`, `discovery/`).

- [ ] Peer identity from `peer_certs()` CN, never IP
- [ ] **Group claim enforced on ALL RPC paths** (not just the obvious one) — #1508 was one path
- [ ] Hop-count / loop-prevention boundary (off-by-one, reset-on-forward)
- [ ] Replay window correctness (boundary, monotonicity, clock-backwards)
- [ ] JWT: alg-confusion (`none`/HS-vs-RS), `exp`/`nbf`/`aud`/`iss`/`kid` **all** checked
- [ ] JWKS refresh trust / key rollover / fetch-error fail-open
- [ ] Re-key / rotation races; peer session takeover
- [ ] **Discovery backend is untrusted input**: TLS + ACL-token to Consul/etcd?
      response tampering → poisoned `PeerConfig` (addresses, auth material, CN pin
      from discovery id) — #1612, #1619
- [ ] HA `ClaimManager` / `ConnectionRegistry` snapshot freshness / split-brain (#1494)

---

## 7. Enrollment / EST / CSR signing

Crate: `rustgate-enrollment` (`auth.rs`, `signing.rs`, `est.rs`, `pkcs12.rs`,
`ratelimit.rs`, `datapackage.rs`, `server.rs`).

- [ ] CSR field validation — **SAN/CN smuggling** into the signed cert
- [ ] EST auth completeness; constant-time credential compare (`subtle::ConstantTimeEq`)
- [ ] Rate-limit **ordering**: slot consumed only by meaningful attempts, *after*
      cheap validation (Content-Type/shape) — #1611
- [ ] Rate-limit bypass (IP spoof behind proxy, window reset)
- [ ] Body size capped with `http_body_util::Limited` **before** collect (template: `est.rs read_body`, `MAX_CSR_BODY`)
- [ ] CA key material in `Zeroizing`; PKCS#12 handling; datapackage path traversal

---

## 8. HTTP egress / webhooks

Crate: `rustgate-http` (`publisher.rs`, `dlq.rs`, `auth.rs`, `circuit`, `dlq_reader.rs`).

- [ ] **SSRF**: target URL validation, redirect-following to internal, DNS-rebind, scheme/IP allowlist
- [ ] Response handling: size cap (`max_response_body_bytes`), header trust, timing
- [ ] Auth secret leak in error/log/Debug (custom `Debug` redacts? `mask_credential`?)
- [ ] Retry amplification / thundering herd (jittered backoff)
- [ ] Drop-on-full bypasses backpressure silently (#1513)
- [ ] DLQ decrypt integrity (terminator, AAD) — `dlq_reader.rs`

---

## 9. NATS / MQTT / WebSocket adapters

Crates: `rustgate-nats`, `rustgate-mqtt`, `rustgate-websocket`.

- [ ] NATS subject injection / NFC-normalization bypass (`sanitize_nats_token`)
- [ ] MQTT topic ACL: wildcard, `$SYS`, empty prefix (#1532); per-session subscription cap (v5 sub-id growth #1615)
- [ ] WebSocket `permessage-deflate` **decompression bomb** (ratio/output cap)
- [ ] Frame size caps; will-message abuse; auth-before-upgrade ordering
- [ ] EKU enforced here too (see §3)

---

## 10. Crypto & secret hygiene

- [ ] **Nonce / IV**: derivation unique per message, no reuse at scale (base-nonce width — #1506); counter overflow
- [ ] **MAC/HMAC verify-before-use** (never decrypt-then-trust); store-forward HMAC ordering
- [ ] **Signature verification completeness**: full chain? alg-confusion? all fields? (MAVLink signing, package ML-DSA)
- [ ] Key **reuse across contexts**; RNG is a CSPRNG for security values (`OsRng`, not `fastrand` — #1520)
- [ ] **Constant-time** compare for ALL secrets (`subtle::ConstantTimeEq`, never `==`) — auth.rs, acl_api.rs
- [ ] Secrets wrapped in `Zeroizing<T>`; early `zeroize()` of intermediate key buffers
- [ ] Custom `Debug` prints `[REDACTED]` for secret-bearing types
- [ ] Audit chain (`audit_chain.rs`): tamper detection, genesis-reset abuse (#1495), torn-write recovery
- [ ] Encrypted archive (`encrypted.rs`): per-chunk AAD, sealed terminator

---

## 11. Cross-domain guard / classification

Crate: `rustgate-guard`, `rustgate-core::classification`, transport obligations.

- [ ] **The guard is a binary Allow/Deny GATE** — `server/guard.rs` discards the
      evaluated payload (`Ok(_) => Allow`). Fixes must make the **check** fail-closed,
      not rewrite bytes. (See memory: *guard is gate not transform*.)
- [ ] Multiple `<marking>` elements: are **all** checked, or only the first? (#1604)
- [ ] Present-but-**unparseable** marking treated as failure (not conflated with "no marking"); independent of `mandatory_marking` (#1495)
- [ ] Classification dominance comparison correctness; marking downgrade/strip
- [ ] Obligation bypass (`MaskPayload`/`MaskPoint`/`MaskCommand`) on a protocol it doesn't cover (#1545)

---

## 12. Admin / management API

Crate: `rustgate-admin` (`server.rs`, `marti_compat.rs`, `acl_api.rs`,
`management_api.rs`, missions/video/correlation handlers).

- [ ] **Auth is gated per match-arm** — enumerate **every** dispatch arm in
      `server.rs` and confirm which are intentionally unauthenticated; a new
      `/api/*` handler silently inherits no-auth (#1616)
- [ ] **Body-size cap before collect** at every `BodyExt::collect(req.into_body())`
      site (`Limited` + 413); collect happens **before** per-route auth (#1618)
- [ ] Pre-auth side effects beyond #1504/#1551 (handler runs work before auth)
- [ ] Path traversal / **zip-slip** in package & datapackage stores (#1556)
- [ ] ACL-API mutation auth + constant-time bearer compare
- [ ] SSRF via video / contacts providers; info disclosure in errors

---

## 13. Resource exhaustion / unbounded growth (sweep)

- [ ] **Every collection keyed by an attacker-controlled value** — grep
      `entry(...).or_insert` / `.push(` / `.insert(` with **no** companion
      `remove` or capacity cap. Known siblings: session map (#1606), MQTT v5
      sub-id (#1615), tenant `O` quota map (#1617), correlation sources (#1613).
      Check also: per-CN group maps, store-forward queues, position cache,
      dedup cache, retained-message store, federation peer/replay maps.
- [ ] **Task fan-out**: unbounded `spawn_background` / `tokio::spawn` per message
      (inference reinject #1614); is there a semaphore / bounded channel?
- [ ] **Algorithmic complexity on a synchronous hot path** (router `OnRouted`
      slot): un-indexed nested scans (#1613), `str::find` on periodic bytes (#1618),
      regex backtracking, recursion
- [ ] Pipeline length / model count capped (#1528); decompression caps (§9, §15)
- [ ] redb / on-disk store growth bounds

---

## 14. Concurrency, races & lifecycle

- [ ] **Lock held across `.await`** (`std`/`parking_lot` guard, or `tokio` write
      lock around an unbounded await) → stall/deadlock (federation shutdown #1607)
- [ ] **TOCTOU**: file path check→open, quota CAS, session register/unregister,
      drain→register (#1509)
- [ ] **ArcSwap reload** racing a mid-request reader at the swap point (ACL/authz/dedup/CRL)
- [ ] Atomic CAS / double-checked-lock correctness
- [ ] Graceful shutdown drops in-flight unsafely; signal-handling race; subsystem drain timeout
- [ ] Background tasks go through `spawn_background` (panic logging) — not bare `tokio::spawn` (#1527)

---

## 15. Injection / path / log / deserialization

- [ ] **Log injection**: attacker string into `tracing` without
      `rustgate_core::sanitize::sanitize_for_log` (CR/LF forging)
- [ ] **PII in logs**: raw CN/IP/serial without `mask_cn`/`mask_ip`/`mask_cert_serial` (#1558)
- [ ] **Header injection**: attacker value into a response header (CRLF) — multipart filename #1608
- [ ] **Path traversal / symlink TOCTOU** on any attacker-influenced file open/create/read
- [ ] **Deserialization**: untrusted serde/bincode/json/protobuf — size hint,
      `deny_unknown_fields` where it matters, recursive/depth bomb, enum-tag confusion
- [ ] **Decompression**: zip/gzip/inflate ratio + output cap before buffering (#1556)
- [ ] Env / CLI value injection; format-string

---

## 16. Config, CLI & server setup

Crate: `rustgate-server` (`setup.rs`, `main.rs`, `cli.rs`), config loaders.

- [ ] Config / parse **error → fail-open default** (the dangerous direction)
- [ ] `deny_unknown_fields` on config structs (typo-silent-ignore)
- [ ] Secret / topology leaked in a config error message or log (`--redact-paths` #1526)
- [ ] Dormant subsystem fails **loud** (warn), not silent (#1456)
- [ ] No-op / overstated flags (PQ wiring #1512); a flag with no effect without its companion
- [ ] TCP sockets hardened via `configure_tactical_socket` / keepalive helper (CI: `check-playbook-drift.sh`)

---

## 17. rustgate convention gaps (verify the playbook is actually followed)

The codebase *claims* these patterns (`.claude/rules/shared-infrastructure.md`).
A **gap** is a real bug — verify, don't assume:

- [ ] Secrets NOT in `Zeroizing` anywhere they should be
- [ ] `==` instead of `subtle::ConstantTimeEq` on any token/password/HMAC
- [ ] `once_cell::sync::Lazy` used (banned — must be `OnceLock`)
- [ ] `std::sync::Mutex` held across `.await` (footgun)
- [ ] Connection-reject / event-drop paths missing an `audit::*` event (#1500)
- [ ] New `#[allow(...)]` in production without a `// justification:` (CI: `check-allow-justified.py`)
- [ ] New `.rs` missing the `// Copyright © 2026 Roberto Chiofalo.` header
- [ ] Banned deps (`openssl`, `openssl-sys`, `native-tls`) — `cargo deny check`

---

## 18. The hour, phased

| Time | Phase | Focus |
|------|-------|-------|
| 0:00–0:05 | **Setup** | threat model, source/sink map, load exclusions (§0–1) |
| 0:05–0:22 | **Unauth ingress** | codec parsers + transport framing: panic / overflow / alloc (§2) — *biggest blast radius* |
| 0:22–0:37 | **Trust boundaries** | TLS/EKU, authz/PEP, restore-reauth, federation, enrollment, admin auth-per-arm (§3–7, §12) |
| 0:37–0:47 | **Crypto & guard** | nonce/MAC ordering, signature completeness, constant-time, secrets, classification (§10–11) |
| 0:47–0:55 | **Resource & race & inject** | unbounded collections, task fan-out, lock-across-await, TOCTOU, injection, deser (§13–15) |
| 0:55–1:00 | **Synthesize** | dedup vs §9 exclusions, rank, write traces, completeness critic (§19) |

If multi-agent (Workflow): fan one finder per surface above, then an
**exploit-trace verifier per candidate** (refute-by-guard or confirm-by-trace),
then dedup + rank + completeness critic. Recall-bias the verifier.

---

## 19. Output, triage & completeness

- [ ] Each finding: `title · severity · crate · file:line · vuln_class · source · sink · exploit_scenario · attack_trace · fix`
- [ ] **Severity rubric**: critical = unauth RCE / auth-bypass / classification cross;
      high = authed bypass / unauth DoS-to-OOM / cross-transport confusion;
      medium = authed resource amplification / algorithmic DoS / info-leak;
      low = hardening / non-default-gated / local-only
- [ ] **Dedup** vs open trackers and the round-1/round-2 set before filing
- [ ] **Completeness critic** — ask: *what surface did I not run? what claim is
      unverified? what modality (panic vs overflow vs alloc) did I skip on this
      parser?* Those become the next round.
- [ ] File issues with `-l security -l severity/<high|medium>`; attach the attack trace.

### Known exclusion set (don't re-report — verify these are still the same bug before dedup'ing)
- Round-1 audit: `#1604`–`#1612`, `#1495`
- Round-2 audit: `#1613`–`#1619`
- EKU parity: `#1620`
- Round-3 audit: `#1621`–`#1627` (+ `#1607` extended with federation-RwLock V2-shutdown trigger sites)
- Other open: `#1494 #1497 #1498 #1500 #1502 #1506 #1509 #1512 #1513 #1514 #1516 #1519 #1526 #1527 #1529 #1533 #1545 #1551 #1554 #1555 #1556 #1558 #1560 #1561`

### Round-3 coverage gaps flagged by prior critics (start here)
- [ ] Guard marking-parser **fuzzing** (nested/CDATA/namespaced/mixed-case CAPCO)
- [ ] Guard **payload-integrity** contract (audited bytes ≠ forwarded bytes)
- [ ] Workspace-wide **unbounded-collection** sweep (`or_insert` / `.push` w/o cap)
- [ ] Workspace-wide **lock-across-`.await`** sweep + ArcSwap swap points
- [ ] **Admin dispatch-arm auth** enumeration + uniform `Limited` body caps
- [ ] **Semi-trusted infra** (Consul/etcd/DNS-SD) as an untrusted-input boundary
- [ ] **Algorithmic-complexity** profiling of the synchronous `OnRouted` hot path

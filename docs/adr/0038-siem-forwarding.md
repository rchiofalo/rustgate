<!-- SPDX-FileCopyrightText: 2026 Roberto Chiofalo -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ADR 0038: Forward the audit trail to a SIEM over syslog-over-TLS

- **Status:** Accepted
- **Date:** 2026-10-18
- **Deciders:** rchiofalo
- **Related:** #1780, #1460 (SIEM forwarding + IdP auth epic), draft #1701
  (superseded), ADR 0014 (hash-chained audit log)

## Context

Audit events (`target="audit"`) reach only the local `--audit-log` file, so
an operator who wants them in an enterprise SIEM has to scrape that file
out of band. Draft #1701 added a CEF formatter but no transport, and
derived severity from the `result` field, which ranked tamper evidence
(`audit.chain_discontinuity`, `result="detected"`) as routine.

## Decision

Add an opt-in forwarder in `rustgate-server` (`src/siem/`), enabled by
`--siem-endpoint host:port`. No new crates and no build feature.

- **A second consumer, not a replacement.** A `tracing` layer filtered to
  `target="audit"` copies each event into a bounded queue. The hash-chained
  `--audit-log` file stays authoritative; the SIEM copy is best-effort.
- **Never slows the router.** The layer only calls `try_send`. A full queue
  drops the event and counts it (`rustgate_siem_events_dropped_total`).
  Formatting and I/O run on a background task.
- **Transport: syslog over TLS only** (RFC 5425 framing, RFC 5424 header,
  facility 13). Plaintext UDP/TCP syslog is not offered: audit records
  should not cross the network in the clear. The collector must chain to
  `--siem-ca` (no system roots); a client certificate is optional.
  The frame whose write failed is retried once on the next connection.
- **Payload: CEF or JSON.** CEF is the broadest ingest format; JSON is what
  Splunk and Elastic parse best.
- **Severity per event type**, from a table that covers every audit event
  in the workspace (the `rustgate_core::audit` functions and the direct
  `target: "audit"` calls); a test fails when a new event is left out.
- **Reconnects back off after every failure**, not only failed connects, and
  the backoff resets only after a connection stays up for 30 s, so a
  collector that accepts and hangs up cannot cause a reconnect storm (each
  attempt is itself audited). The forwarder watches the read side so a
  closed connection is noticed before more records are written into it.
- **Classification-linked events are protected by default** (#1782), since
  the SIEM may be cleared below the traffic. `authz.classified_delivery`
  (plaintext CNs of classified-artefact recipients) is withheld.
  `classification.denied` and `guard.rejected` for
  `unauthorized_classification` are the attempted-spill signal a SOC most
  needs, so they are forwarded, but pseudonymized: CNs become HMAC-SHA256
  tokens under a random per-process key, the message uid is dropped, and
  the marking is cut to its classification level, since compartment and
  control names can be sensitive. The unkeyed `hash_cn` is not used: anyone
  with a roster can reverse it. `--siem-include-classified` sends all three
  unchanged.
- The setup is split because the subscriber is installed before the async
  runtime and crypto provider exist: the layer is built during subscriber
  setup and the sender is started at the top of `run`, and stopped last at
  shutdown so final audit records are flushed.

## Alternatives considered

- **Formatter-only first (#1701).** Ships code nothing calls, and its
  result-based severity mis-ranked security events. Rejected.
- **Derive severity from `result`.** Results do not track risk
  (`federation.group_claim_rejected` reports `success`). Rejected for an
  explicit table.
- **Plaintext syslog for legacy collectors.** Rejected; a TLS-terminating
  relay can bridge a legacy collector if needed.
- **Block or buffer to disk when the collector is down.** Blocking would let
  a SIEM outage stall the router; a disk buffer duplicates the audit log,
  which already holds every event.

## Consequences

- Operators get SIEM ingestion with one flag set and no rebuild.
- Events can be lost from the SIEM (never from the audit log) during long
  outages; the drop counter is the alert signal.
- New audit events need a severity entry; the coverage test enforces it.
- External IdP authentication (the rest of #1460) is still open.

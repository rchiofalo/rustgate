# Getting Started

Run a local rustgate server with one client connected, end to end, in about ten minutes. No Docker, no Kubernetes, no certificates pulled from the air — every command is reproducible on a laptop.

If you want the production-style deployment instead, jump to [`deployment.md`](deployment.md). If you want to understand *why* the pieces fit together the way they do, read [`mental-model.md`](mental-model.md) after this.

---

## What rustgate is

rustgate is a tactical mTLS message router. It accepts authenticated client connections, maps client certificates to identities, and routes messages between groups, peers, and sinks (NATS, federation, HTTP, multicast). It speaks CoT, MAVLink, MQTT, NATS, WebSocket, and a dozen tactical wire formats. One binary, no JVM.

The 10-minute walkthrough below uses the `rustgate-client` echo example — a real Rust client that connects over mTLS, subscribes to inbound traffic, and prints what it receives — so you can watch a message complete a round trip.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust toolchain | **1.94+** (edition 2024) | `rustup install 1.94` if you don't have it |
| `openssl` | any modern | one-shot CA generation |
| ~10 GB free disk | | the workspace builds 30+ crates |

That's it. No Docker, no Kubernetes, no external services for this walkthrough.

## 1. Build the server

```bash
git clone https://github.com/rchiofalo/rustgate.git
cd rustgate
cargo build --release --bin rustgate
```

First build takes ~5 minutes on a modern laptop; subsequent rebuilds are seconds. The binary lands at `./target/release/rustgate`.

## 2. Generate test certificates

We need a CA, a server cert, and a client cert. The CA signs the other two; the server presents its cert during the TLS handshake; the client presents its own and the server uses the client cert's CN to derive an identity.

```bash
mkdir -p certs && cd certs

# CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=rustgate-test-ca"

# Server cert (CN must match the address you bind to; localhost works)
openssl req -newkey rsa:4096 -keyout server.key -out server.csr \
  -nodes -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Client cert (CN becomes the client's identity inside rustgate)
openssl req -newkey rsa:4096 -keyout client.key -out client.csr \
  -nodes -subj "/CN=alpha-1/O=blue-team"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

cd ..
```

The client's `CN=alpha-1` becomes its identity; `O=blue-team` becomes its tenant. We'll see those flow through the router in step 4.

## 3. Run the server

```bash
./target/release/rustgate \
  --bind 127.0.0.1:8089 \
  --cert certs/server.crt \
  --key certs/server.key \
  --ca certs/ca.crt
```

You should see structured logs ending with:

```
INFO TLS listener bound on 127.0.0.1:8089
INFO server ready
```

Leave that running. Open a second terminal for step 4.

## 4. Run the echo client

`rustgate-client` ships an `echo` example that connects, subscribes, prints everything it receives, and echoes every frame back:

```bash
cargo run -p rustgate-client --example echo -- \
  --addr 127.0.0.1:8089 \
  --cert certs/client.crt --key certs/client.key --ca certs/ca.crt
```

You should see:

```
INFO connected as alpha-1 (tenant: blue-team)
INFO subscribed to group: blue-team
```

The client is now sitting on the wire. The server has accepted its mTLS handshake, parsed `CN=alpha-1` into an identity, and put it in the `blue-team` group based on the cert's `O` field.

## 5. Send a message and watch it route

Open a **third terminal** and `curl` the rustgate management API to inspect the live router state:

```bash
curl -k --cert certs/client.crt --key certs/client.key \
  --cacert certs/ca.crt \
  https://127.0.0.1:9000/api/clients
```

You should see one connected client:

```json
[{"cn": "alpha-1", "tenant": "blue-team", "source_protocol": "tls", ...}]
```

To inject a message, send a CoT event over the established connection. The simplest way is to start a second `echo` client with a different cert (re-run step 2 with `CN=bravo-1`) — when it connects, both clients are in `blue-team` and any frame from one routes to the other. The first client prints what arrived.

If you'd rather see a single end-to-end test programmatically, the integration tests in `crates/rustgate-server/tests/` exercise the full path; `cargo nextest run -p rustgate-server e2e` runs one in 10 seconds.

## 6. Inspect the live state

While the server is running:

```bash
# Liveness probe
curl http://127.0.0.1:9090/healthz

# Prometheus metrics (every counter we ship)
curl http://127.0.0.1:9090/metrics | grep rustgate_router

# Audit chain verification (tamper-evident log)
curl --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
  https://127.0.0.1:9000/api/audit/verify
```

`rustgate_router_fanout_total`, `rustgate_router_dropped_total`, and the per-identity histograms are the canonical signals for a SOC operator.

---

## What you just did

You connected an mTLS client to a rustgate server, the server derived an identity from the client cert, evaluated it against an (empty default) ACL, allowed the connection, registered the client as a member of the group derived from the cert's Organization, and stood ready to fan out any frame the client sends to every peer in the same group. That's the end-to-end critical path.

## Where to go next

| You want to... | Read this |
|---|---|
| Understand the message lifecycle and where to extend | [`mental-model.md`](mental-model.md) |
| Connect ATAK / WinTAK / iTAK clients | [`tls-certificates.md`](tls-certificates.md) and the Marti compat shim docs |
| Federate two rustgate servers | [`federation.md`](federation.md) |
| Add an authorization policy | [`authorization.md`](authorization.md) |
| Run rustgate in Kubernetes | [`deployment.md`](deployment.md) |
| Tune for a specific deployment | [`performance-tuning.md`](performance-tuning.md) |
| Wire up FIPS / post-quantum / SPIFFE | [`fips.md`](fips.md), [`post-quantum.md`](post-quantum.md), `crates/rustgate-tls/README.md` |
| See the full configuration surface | [`configuration.md`](configuration.md) |

## Common first-time issues

| Symptom | Cause | Fix |
|---|---|---|
| `tls handshake failed: bad cert` | Server cert CN doesn't match `--bind` host | Regenerate server cert with the right CN/SAN (step 2) |
| `forbidden: identity not in any group` | Client cert has no `O=` field | Add `/O=blue-team` (or any group) to the client cert subject |
| Echo client connects but receives nothing | You only have one client; nothing to route to | Connect a second client with a different cert |
| `EADDRINUSE: 8089` | Another rustgate is running | `pkill rustgate` and retry |
| Build fails with `forbid(unsafe_code)` | You're on an old toolchain | `rustup default 1.94` |

If something else fails, the structured logs on the server terminal almost always say what went wrong — every TLS rejection, every ACL deny, every rate-limit trip emits a typed `tracing` event with enough context to diagnose without reading source.

# Performance Tuning Guide

This guide covers configuration parameters and system-level settings that affect rustgate throughput, latency, and resource consumption. All flags have corresponding environment variables (see the [Configuration Reference](configuration.md) for the full list).

## Connection Limits

### Maximum Connections

| Flag | Env Var | Default |
|------|---------|---------|
| `--max-connections` | `RUSTGATE_MAX_CONNECTIONS` | `1024` |

Controls the maximum number of concurrent client connections. When the limit is reached, new connections are rejected at the application level with a warning log. Existing connections are unaffected.

**Tuning guidance:**
- Each connection holds read/write buffers (typically 8-16 KB each). At 1024 connections, baseline buffer memory is approximately 16-32 MB.
- For high-density deployments (thousands of connections), increase to `2048` or `4096` and ensure memory limits are raised accordingly.
- Prefer horizontal scaling (multiple instances with NATS bridge) over raising this limit beyond 4096.

### TLS Handshake Concurrency

| Flag | Env Var | Default |
|------|---------|---------|
| `--max-concurrent-handshakes` | `RUSTGATE_MAX_HANDSHAKES` | `100` |

Limits the number of TLS handshakes that can proceed simultaneously. Incoming connections that exceed this limit wait until a handshake slot becomes available. This bounds the CPU cost of concurrent cryptographic operations during connection storms.

**Tuning guidance:**
- Lower values (e.g., `25`-`50`) protect against CPU exhaustion during mass reconnection events at the cost of slower connection ramp-up.
- Higher values (e.g., `200`) allow faster bulk connections but increase peak CPU usage.
- Monitor the `tls_handshake` span duration (via OpenTelemetry) to detect handshake bottlenecks.

## Rate Limiting

### Per-Client Message Rate

| Flag | Env Var | Default |
|------|---------|---------|
| `--client-message-rate` | `RUSTGATE_CLIENT_MSG_RATE` | `0` (disabled) |
| `--client-burst` | `RUSTGATE_CLIENT_BURST` | `200` |

Uses a token bucket algorithm. `client-message-rate` is the sustained rate (tokens per second), and `client-burst` is the bucket capacity (maximum burst size). When a client exceeds their rate, excess messages are dropped silently.

**Tuning guidance:**
- For position-reporting workloads (1-2 updates/second per client), a rate of `10` with a burst of `50` is generous.
- For chat-heavy workloads, a rate of `5` with a burst of `20` prevents spam floods.
- Start with rate limiting disabled, monitor per-client message rates via metrics, and set limits based on observed P99 traffic patterns.

### WebSocket Rate Limiting

| Flag | Env Var | Default |
|------|---------|---------|
| `--ws-max-frames-per-sec` | `RUSTGATE_WS_MAX_FRAMES_PER_SEC` | `0` (disabled) |
| `--ws-max-bytes-per-sec` | `RUSTGATE_WS_MAX_BYTES_PER_SEC` | `0` (disabled) |
| `--ws-max-violations` | `RUSTGATE_WS_MAX_VIOLATIONS` | `10` |

Per-connection frame-rate and byte-rate limits for WebSocket clients. Clients exceeding limits have frames dropped. After `ws-max-violations` consecutive violations in a single measurement window, the connection is terminated.

**Tuning guidance:**
- Frame rate limits protect against clients sending many small messages. A value of `100` frames/sec is generous for most workloads.
- Byte rate limits protect against clients sending large payloads. A value of `1048576` (1 MB/sec) is reasonable for position data.
- Both limits can be used together. Set `ws-max-violations` higher (e.g., `20`) if transient bursts are expected.

### Session Circuit Breaker

| Flag | Env Var | Default |
|------|---------|---------|
| `--circuit-breaker-threshold` | `RUSTGATE_CIRCUIT_BREAKER_THRESHOLD` | `10` |

Disconnects slow sessions after this many consecutive send failures (outbound channel full). Prevents a single backpressured client from degrading group routing for other sessions.

**Tuning guidance:**
- Lower values (e.g., `5`) aggressively disconnect slow clients, keeping routing fast for others.
- Higher values (e.g., `25`) tolerate longer transient slowdowns but risk cascading backpressure.
- Set to `0` to disable (not recommended in production).

## Federation Tuning

### Circuit Breaker

| Flag | Env Var | Default |
|------|---------|---------|
| `--federation-circuit-breaker-threshold` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD` | `5` |
| `--federation-circuit-breaker-timeout` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT` | `60` |

Controls how quickly the system stops attempting to send to an unhealthy peer and how long it waits before probing recovery.

**Tuning guidance:**
- For unreliable networks, increase the threshold to `10` to avoid tripping on transient failures.
- For latency-sensitive deployments, decrease the timeout to `30` seconds for faster recovery detection.
- Monitor `rustgate_federation_circuit_breaker_trips_total` to understand trip frequency.

### Replay Buffer

| Flag | Env Var | Default |
|------|---------|---------|
| `--federation-replay-buffer-size` | `RUSTGATE_FEDERATION_REPLAY_BUFFER_SIZE` | `1000` |

Bounded per-peer ring buffer that stores recent forwarded messages. On reconnection, missed messages are replayed from the buffer before resuming the live stream.

**Tuning guidance:**
- Each buffered message stores the raw payload and group metadata. For a typical 1 KB message, 1000 entries consume approximately 1 MB per peer.
- For deployments with many federation peers (e.g., 50), total replay buffer memory is approximately `peers * buffer_size * avg_message_size`.
- Set to `0` to disable replay buffering entirely (saves memory, but peers miss messages during reconnection gaps).
- Increase to `5000`-`10000` for deployments where reconnection gaps are long (minutes) and message rates are moderate.

### Hop Limit

| Flag | Env Var | Default |
|------|---------|---------|
| `--federation-max-hops` | `RUSTGATE_FEDERATION_MAX_HOPS` | `10` |

Maximum number of federation hops before a message is dropped. Prevents infinite loops in mesh topologies.

**Tuning guidance:**
- For simple hub-and-spoke topologies, set to `2` or `3`.
- For deep mesh topologies, keep the default of `10`.
- Each hop adds the server ID to the provenance chain, increasing message size slightly.

## NATS Bridge Tuning

### JetStream Checkpoint

| Flag | Env Var | Default |
|------|---------|---------|
| `--nats-checkpoint-path` | `RUSTGATE_NATS_CHECKPOINT_PATH` | *(none)* |

When set, the server persists the last replayed JetStream sequence number to a file. On restart, replay resumes from the checkpoint instead of replaying the entire history stream.

**Tuning guidance:**
- Always set this in production to avoid replaying the full JetStream history on every restart.
- Use a path on a persistent volume (e.g., `/data/nats-checkpoint.json`) in Kubernetes.
- The checkpoint file is small (a few bytes) and updated periodically.

### NATS mTLS

For production deployments, enable mTLS between rustgate and the NATS server:

```bash
rustgate \
  --nats-url nats://nats:4222 \
  --nats-tls-cert /certs/nats-client.pem \
  --nats-tls-key /certs/nats-client-key.pem \
  --nats-tls-ca /certs/nats-ca.pem \
  --nats-tls-required
```

This adds TLS overhead per NATS connection but protects against credential interception on the network.

## Memory Allocator

### jemalloc

The `jemalloc` feature replaces the system allocator with jemalloc, which provides better performance characteristics for long-running server workloads:

- Reduced memory fragmentation under sustained allocation/deallocation patterns
- More predictable memory usage over time
- Better multi-threaded allocation performance

**Enable at build time:**

```bash
cargo build --release --features jemalloc
```

**Tuning guidance:**
- Recommended for all production deployments.
- The feature is excluded from CI because it requires platform-specific build tooling.
- Monitor RSS (Resident Set Size) with and without jemalloc to measure the improvement for your workload.

## Anti-Replay Filter

| Flag | Env Var | Default |
|------|---------|---------|
| `--replay-window` | `RUSTGATE_REPLAY_WINDOW` | `300` |

The replay detection window in seconds. Messages with identical `(uid, time)` pairs within this window are dropped.

**Tuning guidance:**
- The filter stores one hash entry per unique message within the window. Under typical loads, memory usage is negligible.
- For very high-throughput deployments (tens of thousands of messages per second), the filter scales linearly with `message_rate * window_duration`.
- Reduce the window to `60` seconds if memory is constrained and replay attacks are not a primary concern.
- Set to `0` to disable entirely (zero overhead).

## Kernel Parameters

These OS-level settings affect rustgate performance and should be tuned on production hosts.

### File Descriptors

Each connection requires one file descriptor. The default system limit (often 1024) is insufficient for production.

```bash
# Check current limits
ulimit -n

# Set for the current session
ulimit -n 65536

# Persistent (Linux /etc/security/limits.conf)
rustgate soft nofile 65536
rustgate hard nofile 65536

# Persistent (systemd)
# In the [Service] section of the unit file:
LimitNOFILE=65536
```

In Kubernetes, the default container file descriptor limit is typically sufficient (1048576), but verify with `kubectl exec deploy/rustgate -- ulimit -n`.

### TCP Keepalive

TCP keepalive prevents idle connections from being reaped by intermediate firewalls and NAT devices. This is especially important for federation connections across WAN links.

```bash
# Linux: detect dead peers faster
sysctl -w net.ipv4.tcp_keepalive_time=60      # seconds before first probe (default 7200)
sysctl -w net.ipv4.tcp_keepalive_intvl=10      # seconds between probes (default 75)
sysctl -w net.ipv4.tcp_keepalive_probes=6      # probes before connection is dropped (default 9)
```

### Socket Buffer Sizes

For high-throughput deployments, increase the default socket buffer sizes:

```bash
# Linux: increase send/receive buffer sizes
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=1048576
sysctl -w net.core.wmem_default=1048576
```

### Connection Backlog

Increase the connection backlog for servers expecting many simultaneous connections:

```bash
# Linux: increase the listen backlog
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

## Monitoring Key Metrics

Set up Prometheus alerting on these metrics for proactive performance management:

| Metric | Alert Condition | Meaning |
|--------|----------------|---------|
| `rustgate_sessions_active` | > 80% of `--max-connections` | Approaching connection limit |
| `rustgate_connections_rejected_total` | rate > 0 | Clients being turned away |
| `federation_errors_total` | rate > 1/min | Federation health degrading |
| `rustgate_federation_circuit_breaker_trips_total` | any increase | Peer circuit breaker tripping |
| Container memory usage | > 80% of limit | Risk of OOMKill |
| Container CPU usage | > 70% sustained | May need horizontal scaling |

### Prometheus ServiceMonitor

In Kubernetes with the Prometheus Operator:

```yaml
metrics:
  enabled: true
  port: 9090
  serviceMonitor:
    enabled: true
    interval: 30s
    scrapeTimeout: 10s
```

## Load Testing

When load testing rustgate, consider the following approach:

1. **Generate test certificates** in bulk using the enrollment endpoint or the `rustgate-test-utils` crate (`TestCa`).
2. **Simulate connections** using `openssl s_client` or a custom TLS client that presents client certificates.
3. **Ramp gradually** to identify the inflection point where latency increases or connections are rejected.
4. **Monitor during the test**: watch `rustgate_sessions_active`, CPU usage, memory usage, and message routing latency.
5. **Test federation separately** by setting up two or more instances with peer connections and measuring cross-instance message delivery latency.

### Key metrics to track during load tests

- Connection establishment rate (connections/second)
- Message routing latency (P50, P95, P99)
- Memory usage trend over time (watch for leaks/fragmentation)
- Federation message delivery latency (if applicable)
- TLS handshake duration under load

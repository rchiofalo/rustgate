# Runbook: Anti-Replay Message Filtering

## Overview

rustgate includes a sliding-window replay filter that detects and drops
duplicate messages based on their `uid` and `time` XML attributes. This
prevents replayed or retransmitted messages from being routed to clients
multiple times.

## Configuration

| Flag / Env | Default | Description |
|---|---|---|
| `--replay-window` / `RUSTGATE_REPLAY_WINDOW` | `300` | Window duration in seconds. Messages with the same UID+time seen within this window are dropped. Set to `0` to disable. |

## How It Works

1. When a message arrives, the filter extracts `uid` and `time` attributes
   from the first 512 bytes of the CoT XML payload.
2. These values are hashed together to form a message key.
3. If the key was already seen within the configured window, the message
   is dropped and a structured warning is logged.
4. Non-CoT payloads (where uid/time cannot be extracted) always pass
   through to avoid dropping unknown traffic.
5. Expired entries are periodically evicted to bound memory usage.

## Symptoms of Replay Attacks

- Clients receive the same position report or chat message multiple times
- `rustgate_messages_replayed_total` counter increasing
- Logs contain `message dropped: replay detected`

## Diagnosis

1. Check the replay metric:
   ```bash
   curl -s http://localhost:9090/metrics | grep replayed
   ```

2. Check logs for replay warnings:
   ```bash
   kubectl logs deploy/rustgate | grep "replay detected"
   ```

3. Verify the replay window is configured:
   ```bash
   kubectl get deploy rustgate -o yaml | grep REPLAY_WINDOW
   ```

## Tuning

- **High-frequency position updates**: If clients send rapid position
  updates with the same UID but different timestamps, the filter will not
  interfere (different `time` values produce different keys).

- **Intentional retransmission**: If your deployment relies on message
  retransmission (e.g., unreliable transport), consider increasing the
  window or disabling the filter (`--replay-window 0`).

- **Memory usage**: The filter stores one hash entry per unique message
  within the window. Under typical loads (thousands of messages per
  minute), memory usage is negligible. Entries are automatically evicted
  after the window expires.

- **Large deployments**: The filter is shared across all TLS and plaintext
  TCP sessions on the same server instance. For multi-instance deployments
  behind a load balancer, each instance maintains its own filter.

## Disabling

Set `--replay-window 0` or `RUSTGATE_REPLAY_WINDOW=0` to disable replay
filtering entirely. The filter will not be created and no overhead is added
to message processing.

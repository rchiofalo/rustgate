# systemd unit for bare-metal / edge installs

`rustgate.service` is a hardened systemd unit for running the rustgate
binary directly on a bare-metal or edge host — the tactical-node case where
Kubernetes and the Helm chart (`helm/`) are not available.

It is a **starting point**, not a turnkey drop-in: you must supply the
binary, the TLS material, and an environment file. It is complementary to
the container/Helm path in [`docs/deployment.md`](../../docs/deployment.md);
use whichever matches your target.

## What the unit assumes

- The binary is installed at `/usr/bin/rustgate`. Adjust `ExecStart=` /
  `ExecStartPre=` if you install it elsewhere.
- All rustgate flags are supplied as `RUSTGATE_*` environment variables in
  `/etc/rustgate/rustgate.env` (every CLI flag has an env fallback — see
  `rustgate --help` and [`docs/configuration.md`](../../docs/configuration.md)).
  Keeping flags in the `EnvironmentFile` means secrets and paths never appear
  in `systemctl show` output or the process command line.

## `Type=simple`, not `Type=notify`

The unit uses `Type=simple`. rustgate does **not** emit an `sd_notify`
readiness signal today, so `Type=notify` would leave systemd waiting for a
notification that never arrives and mark the unit `failed` after
`TimeoutStartSec`. Readiness is instead observable via:

- the `ExecStartPre=` pre-flight (`rustgate test-connection`), which aborts
  the start if the bind endpoint is unreachable, and
- the HTTP `/health/ready` probe (requires `--features metrics`), which an
  external monitor can poll.

If `sd_notify` is wired into the server in a later change, switch this unit
to `Type=notify` and drop the pre-flight caveat. This is a deliberate
forward reference recorded in
[ADR 0031](../../docs/adr/0031-production-hardening-ha-and-edge.md).

## Setup

1. Install the binary:
   ```bash
   sudo install -m 0755 target/release/rustgate /usr/bin/rustgate
   ```
2. Create the config directory and a 0600 environment file:
   ```bash
   sudo mkdir -p /etc/rustgate
   sudo tee /etc/rustgate/rustgate.env >/dev/null <<'EOF'
   RUSTGATE_BIND=0.0.0.0:4433
   RUSTGATE_CERT=/etc/rustgate/server.pem
   RUSTGATE_KEY=/etc/rustgate/server-key.pem
   RUSTGATE_CA=/etc/rustgate/ca.pem
   RUSTGATE_METRICS_BIND=127.0.0.1:9090
   # Add any other RUSTGATE_* overrides here.
   EOF
   sudo chmod 0600 /etc/rustgate/rustgate.env
   sudo chown root:root /etc/rustgate/rustgate.env
   ```
   Place the TLS material in `/etc/rustgate/` with restrictive permissions.
   The unit mounts `/etc/rustgate` read-only into the service.
3. Install and start the unit:
   ```bash
   sudo install -m 0644 deploy/systemd/rustgate.service /etc/systemd/system/rustgate.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now rustgate.service
   ```
4. Verify:
   ```bash
   systemctl status rustgate.service
   curl -s http://127.0.0.1:9090/health/ready   # requires --features metrics
   ```
5. Reload config (SIGHUP hot-reload of ACL/authz/CRL) without a restart:
   ```bash
   sudo systemctl reload rustgate.service
   ```

## Hardening notes

The unit ships a defense-in-depth sandbox: `NoNewPrivileges`,
`ProtectSystem=strict`, `DynamicUser`, an empty `CapabilityBoundingSet`, a
`@system-service` syscall filter, and `RestrictAddressFamilies` limited to
`AF_INET AF_INET6 AF_UNIX`.

- **`DynamicUser=yes`** gives a transient unprivileged UID per start. If you
  enable durable state (store-and-forward redb dir, `--nats-checkpoint-path`)
  you may want a **stable** UID so file ownership survives restarts — replace
  `DynamicUser=yes` with fixed `User=`/`Group=` and pre-create that account.
  The unit already provisions `StateDirectory=rustgate`
  (`/var/lib/rustgate`, mode 0700) for writable state.
- **`MemoryDenyWriteExecute=yes`** is safe for rustgate (no JIT). Remove it
  only if a future dependency needs W+X pages.
- **`LimitNOFILE=65536`** — raise for large fleets; rustgate uses at least
  one fd per client. See [`docs/capacity-planning.md`](../../docs/capacity-planning.md).
- Uncomment **`MemoryMax=`** to enforce the memory ceiling from the capacity
  plan (align it with `--max-queued-bytes` plus per-client overhead).

## Validate before deploying

```bash
systemd-analyze verify /etc/systemd/system/rustgate.service
systemd-analyze security rustgate.service    # sandbox exposure score
```

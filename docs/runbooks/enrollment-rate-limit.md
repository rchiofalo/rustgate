# Runbook: Enrollment Rate Limit Triggered

> **Important:** CSR signing is an RSA private-key operation — orders of
> magnitude more expensive than a TLS handshake. The per-IP rate limit
> exists to prevent trivial DoS against the enrollment endpoint. Treat
> sustained limit hits as either misconfiguration (clients retrying too
> aggressively) or active probing.

## Symptoms

- Enrollment endpoint returns `429 Too Many Requests` with body
  `rate limit exceeded` to a subset of clients.
- New clients cannot complete the EST `/simpleenroll` (or legacy
  `/Marti/api/tls/signClient/*`) flow on first attempt.
- Audit log carries `security.rate_limited` records with
  `endpoint = "request"`.
- `rustgate_enrollment_rate_limited_total` counter climbing.
- Clients report intermittent enrollment success on retry but no
  consistent pattern.

## Detection

1. Check the rate-limited counter:
   ```bash
   curl -s http://localhost:9090/metrics | grep rustgate_enrollment_rate_limited_total
   ```
   A non-zero rate sustained over 5 minutes is the canonical signal.

2. Pull recent `security.rate_limited` audit records for the
   enrollment endpoint:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=2000 \
     | grep '"event_type":"security.rate_limited"' \
     | grep -E '"endpoint":"(request|enroll)"'
   ```

3. Identify the source IPs being limited (IPs are masked in logs; the
   last octet / group is redacted, but enough remains to correlate
   with the load balancer's per-source view):
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=2000 \
     | grep "CSR signing rate limited" \
     | awk -F'peer=' '{print $2}' \
     | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
   ```

## Diagnosis

1. **Confirm the configured limit.** Default is 10 requests per IP per
   minute. The flag is `--enrollment-rate-limit` /
   `RUSTGATE_ENROLLMENT_RATE_LIMIT`:
   ```bash
   kubectl get deploy rustgate -o yaml \
     | grep -E "enrollment-rate-limit|ENROLLMENT_RATE_LIMIT"
   ```

2. **Identify what kind of caller is hitting the limit.** Three usual
   suspects:
   - **Legitimate fleet rollout.** A large fleet provisioning at the
     same time (e.g., a new client image rolled out to thousands of
     devices). Look for `enrollment.signed` audit records arriving
     just before the limit kicks in:
     ```bash
     kubectl logs -l app.kubernetes.io/name=rustgate --tail=5000 \
       | grep '"event_type":"enrollment.signed"' | tail -50
     ```
   - **Misconfigured retry loop.** A single client retrying every
     few seconds because it can't parse the response, or because the
     CA cert it received doesn't chain to its trust store. The
     `rustgate_enrollment_rate_limited_total` rate will exceed the
     `enrollment.signed` rate by orders of magnitude. Identify the
     CN in the failed CSR by correlating timestamps with
     `enrollment.sign_failed` audit records.
   - **Active probing.** Many distinct source IPs each hitting the
     limit at once. Each individual peer is at-limit but the
     aggregate rate is much higher than a single client's pattern.
     This is the security signal — treat as an incident.

3. **Verify the EST endpoints are reachable for the affected
   clients.** A misconfigured load balancer that strips the
   `X-Forwarded-For` header can make every request appear to come
   from the load balancer's own IP, so the global pool of clients
   collides into a single per-IP bucket:
   ```bash
   # Check whether the server sees real client IPs or a single LB IP
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=200 \
     | grep "new connection" | awk '{print $NF}' \
     | sort | uniq -c | sort -rn | head
   ```
   If almost every connection appears to come from one address, the
   load balancer is hiding the client identity and the per-IP limit
   is collapsing the whole fleet into one bucket.

## Resolution

### Immediate: Raise the per-IP limit (legitimate burst)

For a coordinated fleet rollout you know is going to be brief:

1. Bump the limit temporarily:
   ```bash
   kubectl set env deploy/rustgate \
     RUSTGATE_ENROLLMENT_RATE_LIMIT=100
   kubectl rollout restart deploy/rustgate
   ```
   The rate limiter reads its bound at startup; a restart is
   required to apply the new value.

2. Monitor `rustgate_enrollment_signed_total` (if exposed) and the
   `enrollment.signed` audit event rate. When the rollout subsides,
   revert to the conservative default to maintain the DoS floor:
   ```bash
   kubectl set env deploy/rustgate \
     RUSTGATE_ENROLLMENT_RATE_LIMIT=10
   kubectl rollout restart deploy/rustgate
   ```

### Immediate: Diagnose a client retry loop

If a single client is generating most of the limit hits:

1. Find the CN in recent `enrollment.sign_failed` audit records:
   ```bash
   kubectl logs -l app.kubernetes.io/name=rustgate --tail=5000 \
     | grep '"event_type":"enrollment.sign_failed"' \
     | tail -20
   ```

2. Inspect the `error` field — it identifies which signing stage
   failed (`csr_parse`, `csr_verify`, `cert_build`, `cms_wrap`, ...)
   so you can fix the client-side malformed CSR instead of the
   server.

3. Coordinate with the operator of the offending client to pause its
   retry loop while you fix the underlying problem (wrong CA cert in
   the request, wrong subject template, missing SAN, etc.). Use the
   management API to remove its in-flight cert if one was issued in
   error.

### Immediate: Restore real client IPs at the load balancer

If the load balancer is collapsing the fleet into one bucket:

1. Verify the proxy chain preserves `X-Forwarded-For` / PROXY
   protocol. For NGINX:
   ```nginx
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   ```
   For Kubernetes services in front of the pod, set
   `externalTrafficPolicy: Local` so client source IPs reach the pod.

2. **rustgate does not currently honour `X-Forwarded-For` for the
   per-IP rate-limit key.** Until that lands as a feature, the only
   options are:
   - Bypass the load balancer with a direct service mesh route for
     enrollment.
   - Run the enrollment server behind a layer-4 (not layer-7) load
     balancer that preserves the client IP at the TCP level.
   - Temporarily raise `RUSTGATE_ENROLLMENT_RATE_LIMIT` to a value
     that accepts the aggregate rate (and accept the increased DoS
     surface area until the LB topology is fixed).

### Active probing — incident response

A coordinated probe across many source IPs is the security case:

1. Capture the source-IP distribution at the load balancer or
   network firewall before the evidence rotates out.
2. Apply network-level blocks (NetworkPolicy, ALB rule, WAF) on the
   most prolific sources.
3. Tighten the limit (e.g. `RUSTGATE_ENROLLMENT_RATE_LIMIT=5`) so
   subsequent probes shed faster.
4. File an incident; do not raise the limit to clear the alert —
   that is what the attacker wants.

## Prevention

- Alert on `rate(rustgate_enrollment_rate_limited_total[5m]) > 0`
  with a 5-minute hold-down. A handful of hits is normal during a
  rollout; sustained non-zero is the operational signal.
- Provision client images with **jittered** exponential backoff on
  enrollment retry (initial 5 s, cap at 5 min, ±25 % jitter). The
  default rustgate-client backoff already does this; verify
  third-party clients in your fleet do too.
- Document the rate-limit value (`RUSTGATE_ENROLLMENT_RATE_LIMIT`)
  in your runbook for the planned-rollout case so on-call operators
  know what knob to turn without re-deriving it.
- Co-locate the EST listener with a load balancer that preserves
  client IPs end-to-end. Layer-4 passthrough or PROXY protocol is
  the right shape; layer-7 reverse proxies without trusted
  `X-Forwarded-For` collapse the rate-limit key space.
- Treat sustained limit hits without a corresponding rise in
  successful `enrollment.signed` events as suspicious — the audit
  trail is the discriminator between "legitimate burst" and
  "probe".

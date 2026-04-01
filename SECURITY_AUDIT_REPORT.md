# Comprehensive Security Audit: rustgate Helm Chart & Container Deployment

**Audit Date:** March 30, 2026
**Scope:** Helm Chart, Dockerfile, docker-compose.yml, Kubernetes deployment manifests
**Baseline Standards:** Pod Security Standards (Restricted), CIS Kubernetes Benchmark v1.8, NSA/CISA Kubernetes Hardening Guide v1.2, Helm security best practices

---

## Executive Summary

The rustgate deployment demonstrates **strong foundational security practices** with several production-ready controls already in place. However, there are **critical gaps** in network isolation, image pinning, Ingress TLS handling, and operational security that require remediation before production deployment at scale.

### Risk Rating by Category

| Category | Rating | Status |
|----------|--------|--------|
| Container Image Security | MEDIUM | Actionable improvements |
| SecurityContext | GOOD | Meets restricted profile mostly |
| Network Security | CRITICAL | Requires immediate attention |
| Secrets Management | MEDIUM | Needs encryption-at-rest strategy |
| RBAC & Service Accounts | GOOD | Well-scoped |
| Pod Disruption & HA | GOOD | Topology spread configured |
| Ingress Security | MEDIUM | TLS handling needs review |
| Runtime Security | NOT CONFIGURED | Opportunity for Falco integration |

---

## 1. CONTAINER IMAGE SECURITY

### 1.1 Image Tag Pinning (CRITICAL)

**Finding:** Images are referenced by **tag only**, not digest SHA.

**Current State (values.yaml:8):**
```yaml
image:
  repository: ghcr.io/rchiofalo/rustgate
  tag: "0.3.0"
  pullPolicy: IfNotPresent
```

**Risk:** Tags are mutable. The `0.3.0` tag can be reassigned by the image maintainer (or attacker with write access to the registry) to point to a completely different image without any code review or audit trail. This breaks reproducibility and enables **supply chain attacks**.

**CIS Benchmark:** 5.2.4 - Minimize cluster access to read-only for container image registries
**NSA/CISA Guide:** Recommends pinning by digest for immutability

**Remediation:**

1. **Pin by SHA digest in Helm chart:**
   ```yaml
   image:
     repository: ghcr.io/rchiofalo/rustgate
     tag: "0.3.0@sha256:abcdef1234567890..."  # Add digest
     pullPolicy: IfNotPresent
   ```

2. **Or use image pull policy with digest:**
   ```yaml
   image:
     repository: ghcr.io/rchiofalo/rustgate@sha256:abcdef1234567890
     pullPolicy: IfNotPresent
   ```

3. **In CI/CD, generate SHA on every build:**
   - Capture the digest from `docker build` output
   - Update Helm values with the full SHA256 digest
   - Enforce code review on chart changes

4. **Also pin builder and runtime base images in Dockerfile:**
   - ✓ Builder image IS pinned: `rust:1.94-alpine@sha256:ff0adc...` (GOOD)
   - ✓ Runtime image IS pinned: `alpine:3.23@sha256:25109...` (GOOD)
   - The Dockerfile is correct; the issue is only in Helm values

**Priority:** HIGH - Address immediately before production

---

### 1.2 Image Pull Policy (GOOD)

**Current State (values.yaml:9):**
```yaml
pullPolicy: IfNotPresent
```

**Assessment:** ✓ GOOD - Prevents unnecessary registry pulls and layer download attacks.

**Recommendation:** For production, consider `Always` with digest pinning for guaranteed freshness, or `IfNotPresent` with regular image rotation schedules.

---

### 1.3 ImagePullSecrets (GOOD)

**Current State (values.yaml:11, deployment.yaml:21-24):**
- Supports optional imagePullSecrets
- Properly templated with `with` block

**Assessment:** ✓ GOOD - Allows private registry authentication. Can be configured in values-production.yaml.

---

## 2. SECURITYCONTEXT & POD HARDENING

### 2.1 Pod-Level SecurityContext (EXCELLENT)

**Current State (deployment.yaml:25-31):**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
```

**Assessment:** ✓ EXCELLENT - Meets Restricted Pod Security Standard requirements.

**Validates Against:**
- Pod Security Standards (Restricted): ✓ Compliant
- CIS Benchmark 5.2.1 (run containers as non-root): ✓
- NSA/CISA (least privilege user context): ✓

**Strengths:**
- Non-root user (10001) not a reserved system UID
- fsGroup set for proper volume ownership
- RuntimeDefault seccomp profile (good default; can be tightened with custom policy)
- Dockerfile confirms user creation: `adduser -u 10001 -S rustgate -G rustgate`

---

### 2.2 Container-Level SecurityContext (EXCELLENT)

**Current State (deployment.yaml:36-41):**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

**Assessment:** ✓ EXCELLENT - Meets Restricted Pod Security Standard.

**Validates Against:**
- Pod Security Standards (Restricted): ✓ Fully compliant
- allowPrivilegeEscalation: false: ✓ Sets no_new_privs kernel bit
- Capabilities: ✓ ALL dropped (most restrictive)
- readOnlyRootFilesystem: ✓ Forces immutable filesystem

**Strengths:**
- Zero capabilities (does not need NET_BIND_SERVICE for non-standard ports)
- Read-only root filesystem eliminates entire class of attacks (file modification, persistence)
- Dockerfile confirms: `RUN apk add --no-cache ca-certificates && addgroup -g 10001 -S rustgate && adduser -u 10001 -S rustgate -G rustgate` (user runs as non-root by default)

**Note:** docker-compose.yml also correctly sets this:
```yaml
security_opt:
  - no-new-privileges:true
read_only: true
```

---

### 2.3 AppArmor & SELinux (NOT CONFIGURED)

**Finding:** No AppArmor or SELinux profiles specified.

**Current State:** Not configured in deployment.yaml

**Assessment:** These are optional but recommended for production at scale.

**Recommendation for Future:**
```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault  # Already have this
  appArmorProfile:       # Add if platform supports
    type: RuntimeDefault
  seLinuxOptions:        # Add if enforcing SELinux
    level: "s0:c123,c456"
```

**Note:** AppArmor and SELinux require cluster-level support and should be added if your platform (EKS, GKE, AKS) has them enabled.

---

## 3. NETWORK SECURITY

### 3.1 NetworkPolicy: CRITICAL GAPS

**Finding:** NetworkPolicy exists but has significant blind spots and missing controls.

**Current State (networkpolicy.yaml) - PARTIALLY ENABLED:**
```yaml
networkPolicy:
  enabled: false  # values.yaml:111 - DISABLED BY DEFAULT!
```

**CRITICAL ISSUE 1: NetworkPolicy Disabled by Default**

The NetworkPolicy is present in templates but **disabled by default** (`enabled: false`). Production deployments without NetworkPolicy are vulnerable to:
- Pod-to-pod lateral movement
- Compromised pods accessing kube-system, default, or other namespaces
- Uncontrolled egress to external networks
- DNS exfiltration attacks

**Remediation:**
```yaml
# helm/values-production.yaml
networkPolicy:
  enabled: true
```

**CRITICAL ISSUE 2: Incomplete Ingress Rules**

The NetworkPolicy ingress allows traffic to all specified ports **without fromSelector**:
```yaml
ingress:
  - ports:
      - port: {{ .Values.service.port }}
        protocol: TCP
      # ... more ports
```

**Problem:** This allows ANY pod (or any IP outside the cluster) to access these ports. Should restrict to specific namespaces/selectors.

**Remediation:**
```yaml
ingress:
  - from:
      - podSelector:
          matchLabels:
            # Define which pods can reach rustgate
            role: client
      - namespaceSelector:
          matchLabels:
            name: monitoring  # For Prometheus scraping metrics
      - namespaceSelector:
          matchLabels:
            name: ingress-controller
    ports:
      - port: {{ .Values.service.port }}
        protocol: TCP
```

**CRITICAL ISSUE 3: Incomplete Egress Rules**

**Missing DNS Selector:**
```yaml
egress:
  - ports:
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
    # Missing: to: selector for kube-dns
```

**Problem:** DNS will not work if kube-dns is in kube-system namespace. NetworkPolicy blocks cross-namespace traffic by default.

**Remediation:**
```yaml
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            name: kube-system
      - podSelector:
          matchLabels:
            k8s-app: kube-dns
    ports:
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
```

**CRITICAL ISSUE 4: NATS Egress Incomplete**

```yaml
{{- if .Values.nats.enabled }}
- ports:
    - port: 4222
      protocol: TCP
{{- end }}
```

**Problem:** No `to:` selector. Should restrict to NATS namespace or service.

**Remediation:**
```yaml
- to:
    - namespaceSelector:
        matchLabels:
          name: nats  # or whatever namespace NATS runs in
    - podSelector:
        matchLabels:
          app: nats-server
  ports:
    - port: 4222
      protocol: TCP
```

**CRITICAL ISSUE 5: Federation Egress Incomplete**

Federation peer communications (ports 9000, 9001) have no `to:` selector - they'll be blocked or require open egress.

**Remediation:**
```yaml
- to:
    - podSelector:
        matchLabels:
          app: rustgate
          federation: enabled
  ports:
    - port: {{ .Values.federation.v1Port }}
      protocol: TCP
    - port: {{ .Values.federation.v2Port }}
      protocol: TCP
```

**Summary of NetworkPolicy Recommendations:**

1. **Enable by default in production values**
2. **Fix ingress rules:** Add `from:` selectors for each port
3. **Fix egress DNS:** Specify namespace/pod selectors for kube-dns
4. **Fix egress NATS:** Restrict to NATS namespace
5. **Fix egress Federation:** Restrict to other rustgate pods
6. **Add egress for external APIs** if federation connects to remote peers (currently hardcoded to deny-all external)

---

### 3.2 Metrics Port Exposure (MEDIUM RISK)

**Finding:** Metrics port (9090 by default) is exposed in NetworkPolicy without authentication.

**Current State (networkpolicy.yaml:23-24):**
```yaml
- port: {{ .Values.metrics.port }}
  protocol: TCP
```

**Risk:** Prometheus metrics often leak sensitive information (connection counts, API call patterns, internal IPs, configuration details).

**Recommendation:**
1. Restrict metrics ingress to monitoring namespace only:
   ```yaml
   - from:
       - namespaceSelector:
           matchLabels:
             name: monitoring
     ports:
       - port: {{ .Values.metrics.port }}
         protocol: TCP
   ```

2. Authenticate metrics endpoint:
   - Add HTTP Basic Auth to metrics port
   - Or require mTLS for metrics scraping
   - Or use RBAC + bearer tokens

---

### 3.3 Plaintext Traffic Exposure (HIGH RISK)

**Finding:** Plaintext TCP/UDP (ports 8087) can be enabled but lacks network isolation.

**Current State (values.yaml:84-97):**
```yaml
plaintext:
  tcp:
    enabled: false  # Disabled by default - GOOD
    bind: "0.0.0.0:8087"
  udp:
    enabled: false
    bind: "0.0.0.0:8087"
  cn: "anonymous"
  group: "__plaintext__"
```

**Assessment:** Good that disabled by default. Recommendation if enabled:

```yaml
# In NetworkPolicy, restrict plaintext to specific CIDR or pod selector
- from:
    - ipBlock:
        cidr: 10.0.0.0/8
        except:
          - 10.255.0.0/16
    - podSelector:
        matchLabels:
          trust-level: internal
  ports:
    - port: 8087
      protocol: TCP
    - port: 8087
      protocol: UDP
```

---

## 4. SECRETS MANAGEMENT

### 4.1 TLS Certificate Secrets (GOOD)

**Current State (deployment.yaml:258-260, values.yaml:18-22):**
```yaml
tls:
  secretName: rustgate-tls
  cert: /certs/server.crt
  key: /certs/server.key
  ca: /certs/ca.crt
```

**Assessment:** ✓ GOOD - Certificates mounted as Kubernetes Secrets.

**Strengths:**
- Mounted read-only
- User cannot access (10001)
- Separate from application config

**Recommendations:**

1. **Enable encryption at rest for Secrets in etcd:**
   - This is a cluster-wide setting (not Helm responsibility)
   - Document in deployment guide: "Cluster must have `--encryption-provider-config` enabled for all.EncryptionConfiguration"

2. **Rotate certificates regularly:**
   - Implement cert-manager for automatic renewal
   - Add lifecycle.preStop hook that validates certificate TTL

3. **Use External Secrets Operator (ESO) for production:**
   ```yaml
   # Future enhancement: replace hardcoded secretName with ESO
   externalSecrets:
     enabled: false  # Set to true for prod
     backendType: vault  # or aws-secrets, azure-keyvault
     refreshInterval: 1h
   ```

---

### 4.2 NATS Credentials (GOOD)

**Current State (deployment.yaml:94-103):**
```yaml
{{- if .Values.nats.enabled }}
- name: NATS_CREDENTIALS
  valueFrom:
    secretKeyRef:
      name: {{ .Values.nats.existingSecret }}
      key: NATS_CREDENTIALS
{{- else if .Values.nats.credentials }}
- name: NATS_CREDENTIALS
  value: {{ .Values.nats.credentials | quote }}
{{- end }}
```

**Assessment:** ✓ GOOD - Supports both:
- Kubernetes Secret via RBAC-scoped reference (preferred)
- Plaintext env var (for dev only)

**Recommendation:** Plaintext credentials path should be documented as "dev only":
```yaml
nats:
  credentials: ""  # DANGER: Only for development. Use existingSecret in production.
  existingSecret: ""
```

---

### 4.3 Enrollment Credentials (MEDIUM RISK)

**Current State (deployment.yaml:109-140):**
```yaml
{{- if .Values.enrollment.existingSecret }}
- name: ENROLLMENT_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.enrollment.existingSecret }}
      key: ENROLLMENT_USER
- name: ENROLLMENT_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.enrollment.existingSecret }}
      key: ENROLLMENT_PASSWORD
{{- else }}
{{- if .Values.enrollment.user }}
- name: ENROLLMENT_USER
  value: {{ .Values.enrollment.user | quote }}
{{- end }}
{{- if .Values.enrollment.password }}
- name: ENROLLMENT_PASSWORD
  value: {{ .Values.enrollment.password | quote }}
{{- end }}
{{- end }}
```

**Assessment:** ✓ GOOD design (Secret-first) but **DANGER: plaintext fallback**

**Risk:** Enrollment credentials in values.yaml YAML will be committed to Git, visible in Helm history, visible in Pod description, visible in logs.

**Remediation:**

1. **Remove plaintext path entirely for production:**
   ```yaml
   {{- if .Values.enrollment.existingSecret }}
   # Use secret
   {{- else if .Values.enrollment.enabled }}
   # ERROR: enrollment.enabled but no existingSecret set!
   {{- end }}
   ```

2. **Make values-production.yaml require the secret:**
   ```yaml
   enrollment:
     enabled: true
     existingSecret: rustgate-enrollment-creds  # MUST be set
   ```

3. **Document secret creation:**
   ```bash
   kubectl create secret generic rustgate-enrollment-creds \
     --from-literal=ENROLLMENT_USER=admin \
     --from-literal=ENROLLMENT_PASSWORD=<secure-password> \
     -n rustgate
   ```

---

### 4.4 Federation Peers File (MEDIUM RISK)

**Current State (deployment.yaml:168-174):**
```yaml
{{- if .Values.federation.existingSecret }}
- name: FEDERATION_PEERS_FILE
  value: /etc/federation/peers.json
{{- else if .Values.federation.peersFile }}
- name: FEDERATION_PEERS_FILE
  value: {{ .Values.federation.peersFile | quote }}
{{- end }}
```

**Risk:** Peer configurations might contain sensitive TLS hostnames, IP addresses, or authentication tokens.

**Recommendation:** Use existingSecret exclusively; document path requirement:

```yaml
# In deployment.yaml
{{- if .Values.federation.enabled }}
{{- if not .Values.federation.existingSecret }}
  {{ fail "federation.enabled requires federation.existingSecret to be set" }}
{{- end }}
```

---

## 5. SERVICE ACCOUNTS & RBAC

### 5.1 automountServiceAccountToken (EXCELLENT)

**Current State (deployment.yaml:19):**
```yaml
automountServiceAccountToken: false
```

**Assessment:** ✓ EXCELLENT - Follows least-privilege principle.

**Validates Against:**
- Pod Security Standards (Restricted): ✓
- CIS Benchmark 5.1.6 (Ensure that Service Account tokens are only mounted where necessary): ✓
- NSA/CISA (minimize credential exposure): ✓

**Rationale:** rustgate does not need to call the Kubernetes API, so the service account token is not mounted. If it did (e.g., to list Secrets or update ConfigMaps), you would:
1. Mount the token only in containers that need it
2. Create a dedicated ServiceAccount with minimal Role
3. Use namespace-scoped RoleBinding (not ClusterRoleBinding)

---

### 5.2 Missing ServiceAccount Definition (MINOR)

**Finding:** Helm chart does not explicitly define a ServiceAccount resource.

**Current State:** No serviceaccount.yaml template

**Assessment:** MINOR ISSUE - Kubernetes auto-creates a default ServiceAccount, but best practice is explicit:

**Remediation - Create helm/templates/serviceaccount.yaml:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "rustgate.fullname" . }}
  labels:
    {{- include "rustgate.labels" . | nindent 4 }}
automountServiceAccountToken: false
```

Then reference in deployment.yaml:
```yaml
spec:
  serviceAccountName: {{ include "rustgate.fullname" . }}
  automountServiceAccountToken: false
```

---

### 5.3 RBAC Bindings (NOT APPLICABLE - INTENTIONAL)

**Finding:** No Roles or RoleBindings are defined.

**Assessment:** ✓ CORRECT - rustgate does not require any Kubernetes API access, so zero RBAC is the right choice.

---

## 6. RESOURCE MANAGEMENT

### 6.1 Resource Requests & Limits (GOOD)

**Current State (values.yaml:126-132):**
```yaml
resources:
  requests:
    cpu: 500m
    memory: 256Mi
  limits:
    cpu: "2"
    memory: 512Mi
```

**Assessment:** ✓ GOOD - Prevents resource starvation and runaway consumption.

**Validates Against:**
- Pod Security Standards: Not restricted profile requirement, but a best practice
- CIS Benchmark 1.4.12 (Ensure that all pods have resource requests and limits)

**Production Override (values-production.yaml:8-14):**
```yaml
resources:
  requests:
    cpu: "1"
    memory: 512Mi
  limits:
    cpu: "4"
    memory: 2Gi
```

**Assessment:** ✓ APPROPRIATE - Accounts for federation and NATS workloads.

**Recommendation:** Add memory margin for GC pauses:
```yaml
resources:
  requests:
    cpu: "1"
    memory: 512Mi
  limits:
    cpu: "4"
    memory: 2.5Gi  # +500Mi headroom
```

---

### 6.2 Quality of Service (QoS) Class (GOOD)

**Implicit QoS:** With requests == limits for some resources, the pod is **Burstable** class.

**Assessment:** ✓ ACCEPTABLE - Burstable pods get second-priority scheduling (after Guaranteed), which is reasonable for a message router.

**Future Optimization:** If mission-critical, consider making requests == limits everywhere (Guaranteed QoS):
```yaml
resources:
  requests:
    cpu: "1"
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 512Mi  # Equal = Guaranteed QoS
```

---

## 7. HIGH AVAILABILITY & DISRUPTION TOLERANCE

### 7.1 Pod Disruption Budget (EXCELLENT)

**Current State (pdb.yaml:1-13):**
```yaml
{{- if or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "rustgate.fullname" . }}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      {{- include "rustgate.selectorLabels" . | nindent 6 }}
{{- end }}
```

**Assessment:** ✓ EXCELLENT - PDB created for multi-replica or HPA deployments.

**Validates Against:**
- Kubernetes best practices for cluster maintenance
- NSA/CISA (ensure availability during disruptions)

**Ensures:** At least 1 pod remains available during node drains, upgrades, etc.

---

### 7.2 Topology Spread Constraints (EXCELLENT)

**Current State (values-production.yaml:23-29):**
```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: rustgate
```

**Assessment:** ✓ EXCELLENT - Spreads pods across nodes for resilience.

**Validates Against:**
- CIS Benchmark (distribute workloads across nodes)
- NSA/CISA (availability through geographic distribution)
- Kubernetes best practices (HA architectures)

**What it does:**
- Maximum 1 pod per node (maxSkew: 1)
- Spreads across kubernetes.io/hostname (different nodes)
- Fails to schedule if constraint cannot be met (safety-first)

**Recommendation:** Also add zone spread for multi-zone clusters:
```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: rustgate
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway  # More lenient for zone spread
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: rustgate
```

---

### 7.3 Horizontal Pod Autoscaling (EXCELLENT)

**Current State (hpa.yaml:1-28, values-production.yaml:16-21):**
```yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70
```

**Assessment:** ✓ EXCELLENT - HPA configured with dual metrics.

**Validates Against:**
- Kubernetes best practices (automatic scaling)
- Production reliability patterns

**Strengths:**
- Scales on both CPU and memory (most robust)
- Conservative thresholds (60% CPU, 70% memory) prevent thrashing
- Min 3 replicas ensures HA
- Max 20 prevents cost explosion

---

### 7.4 Termination Grace Period (GOOD)

**Current State (values.yaml:142, deployment.yaml:20):**
```yaml
terminationGracePeriodSeconds: 120
```

**Assessment:** ✓ GOOD - Allows time for graceful shutdown.

**Rationale:** 120s (2 minutes) accounts for:
- 110s drain timeout (application shutdown time)
- 5s preStop sleep (connection draining)
- 5s buffer

**Validates Against:** Kubernetes pod lifecycle best practices

---

## 8. INGRESS & EXTERNAL ACCESS

### 8.1 Ingress TLS Termination (NOT CONFIGURED - MEDIUM RISK)

**Current State (ingress.yaml:1, values.yaml:113-118):**
```yaml
ingress:
  enabled: false
  className: ""
  annotations: {}
  hosts: []
  tls: []
```

**Assessment:** ✓ GOOD it's disabled by default, but MEDIUM RISK if enabled without care.

**Issue 1: No TLS Configuration Template**

When Ingress is enabled, the template does not enforce TLS:
```yaml
{{- if .Values.ingress.tls }}
tls:
  {{- range .Values.ingress.tls }}
  - hosts:
      {{- range .hosts }}
      - {{ . | quote }}
      {{- end }}
    secretName: {{ .secretName }}
  {{- end }}
{{- end }}
```

**Problem:** If tls: [] is empty (default), ingress serves HTTP only!

**Remediation:**
1. Make TLS mandatory in production:
   ```yaml
   # helm/values-production.yaml
   ingress:
     enabled: true
     className: nginx
     tls:
       - secretName: rustgate-tls
         hosts:
           - rustgate.example.com
   ```

2. Add annotation for auto-redirect HTTP -> HTTPS:
   ```yaml
   ingress:
     annotations:
       nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
       nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
   ```

3. Use cert-manager for automatic certificate renewal:
   ```yaml
   ingress:
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
       cert-manager.io/issue-temporary-certificate: "true"
   tls:
     - secretName: rustgate-tls
       hosts:
         - rustgate.example.com
   ```

**Issue 2: Backend Port Mismatch**

The ingress routes to `$.Values.service.port` (4433 - mTLS), but doesn't support backend mTLS:

```yaml
backend:
  service:
    name: {{ include "rustgate.fullname" $ }}
    port:
      number: {{ $.Values.service.port }}  # 4433 - mTLS!
```

**Problem:** Ingress controller (typically NGINX) doesn't do mTLS to backend. It expects plain HTTP/TCP.

**Options:**
1. **If using mTLS backend:** Deploy rustgate behind a service mesh (Istio, Linkerd)
2. **If using HTTP:** Expose a separate HTTP service (not recommended for this security-focused app)
3. **If using plaintext:** Use the plaintext port if enabled (requires NetworkPolicy changes)

**Recommendation:** Document that if Ingress is enabled, you must:
- Use a service mesh for mTLS termination, OR
- Use Ingress only with plaintext backend (less secure), OR
- Implement SSL_PASSTHROUGH in NGINX and client certificates

---

### 8.2 Service Type Configuration (GOOD)

**Current State (service.yaml:8, values.yaml:13-16):**
```yaml
service:
  type: ClusterIP
  port: 4433
```

**Assessment:** ✓ GOOD - Default is ClusterIP (internal only).

**Recommendation:** Document in values.yaml:
```yaml
service:
  type: ClusterIP  # Use LoadBalancer for external access, ClusterIP for internal (recommended)
  port: 4433
```

---

## 9. OBSERVABILITY & PROBES

### 9.1 Health Checks (EXCELLENT)

**Current State (deployment.yaml:195-228):**

With metrics enabled:
```yaml
startupProbe:
  httpGet:
    path: /healthz
    port: metrics
  failureThreshold: 30
  periodSeconds: 2
livenessProbe:
  httpGet:
    path: /healthz
    port: metrics
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: metrics
  initialDelaySeconds: 3
  periodSeconds: 5
```

**Assessment:** ✓ EXCELLENT - All three probe types configured.

**Validates Against:**
- Kubernetes best practices (pod lifecycle management)
- CIS Benchmark 1.4.6 (Use health checks)

**Strengths:**
- startupProbe allows slow startup (30 * 2s = 60s grace period)
- livenessProbe detects deadlocks
- readinessProbe prevents traffic during recovery

---

### 9.2 Metrics & Prometheus (GOOD)

**Current State (values.yaml:99-108):**
```yaml
metrics:
  enabled: true
  port: 9090
  serviceMonitor:
    enabled: false
    interval: 30s
    scrapeTimeout: 10s
```

**Assessment:** ✓ GOOD - Metrics endpoint enabled; ServiceMonitor optional.

**Recommendation:**
1. Enable ServiceMonitor in production:
   ```yaml
   metrics:
     serviceMonitor:
       enabled: true
       interval: 30s
       scrapeTimeout: 10s
       additionalLabels:
         release: prometheus  # For Prometheus discovery
   ```

2. Secure metrics with authentication (see Section 3.2)

3. Create a ServiceMonitor template:
   ```yaml
   # helm/templates/servicemonitor.yaml
   {{- if and .Values.metrics.enabled .Values.metrics.serviceMonitor.enabled }}
   apiVersion: monitoring.coreos.com/v1
   kind: ServiceMonitor
   metadata:
     name: {{ include "rustgate.fullname" . }}
   spec:
     selector:
       matchLabels:
         {{- include "rustgate.selectorLabels" . | nindent 8 }}
     endpoints:
       - port: metrics
         interval: {{ .Values.metrics.serviceMonitor.interval }}
         scrapeTimeout: {{ .Values.metrics.serviceMonitor.scrapeTimeout }}
   {{- end }}
   ```

---

## 10. PERSISTENT STORAGE SECURITY

### 10.1 PersistentVolumeClaim Configuration (MEDIUM RISK)

**Current State (pvc.yaml:1-35):**
```yaml
{{- if and .Values.persistence.enabled .Values.federation.enabled }}
apiVersion: v1
kind: PersistentVolumeClaim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {{ .Values.persistence.size }}
{{- end }}
```

**Issues:**

1. **No StorageClass Encryption:**
   - Default behavior: Storage is not encrypted at rest
   - PVC does not specify encryption requirements

2. **ReadWriteOnce Only:**
   - Single-node access only
   - No HA replication for federation store

3. **No Backup/Snapshot Policy**

**Remediation:**

```yaml
spec:
  accessModes:
    - ReadWriteOnce
  {{- if .Values.persistence.storageClassName }}
  storageClassName: {{ .Values.persistence.storageClassName }}
  {{- else }}
  # Default to encrypted storage if available
  storageClassName: ebs-gp3-encrypted  # or your platform's encrypted class
  {{- end }}
  resources:
    requests:
      storage: {{ .Values.persistence.size }}
```

And in values-production.yaml:
```yaml
persistence:
  enabled: true
  storageClassName: ebs-gp3-encrypted  # AWS example
  size: 10Gi  # Larger for production
```

---

### 10.2 Volume Mount Security (GOOD)

**Current State (deployment.yaml:234-250):**
```yaml
volumeMounts:
  - name: tls-certs
    mountPath: /certs
    readOnly: true
  {{- if and .Values.federation.enabled .Values.federation.existingSecret }}
  - name: federation-peers
    mountPath: /etc/federation
    readOnly: true
  {{- end }}
  {{- if and .Values.persistence.enabled .Values.federation.enabled }}
  - name: federation-data
    mountPath: /data
  {{- end }}
```

**Assessment:** ✓ GOOD - TLS certs are read-only; federation data writable.

**Note:** Recommendation to add noexec flag (kernel-level, requires StorageClass support):
```yaml
# This would be set on StorageClass, not in Helm
- mountOptions:
    - noexec
    - nodev
    - nosuid
```

---

## 11. DOCKERFILE SECURITY

### 11.1 Multi-Stage Build (EXCELLENT)

**Current State (Dockerfile:1-62):**

Builder stage: `rust:1.94-alpine@sha256:ff0a...` → Runtime stage: `alpine:3.23@sha256:2510...`

**Assessment:** ✓ EXCELLENT - Removes build tools from final image.

**Benefits:**
- Smaller attack surface
- No build dependencies in production
- ~200MB smaller final image

---

### 11.2 Base Image Pinning (EXCELLENT)

**Current State (Dockerfile:4, 42):**
```dockerfile
FROM rust:1.94-alpine@sha256:ff0adc35894eb79586ce752a1b5a9eadc88b938c56d8f2b4b537b6258ff3fa10 AS builder
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
```

**Assessment:** ✓ EXCELLENT - Both base images pinned by SHA256 digest.

**Validates Against:**
- CIS Docker Benchmark 4.1 (Build image with minimal image)
- Container supply chain security

---

### 11.3 User & Privilege Restriction (EXCELLENT)

**Current State (Dockerfile:48-51):**
```dockerfile
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 -S rustgate && adduser -u 10001 -S rustgate -G rustgate
USER 10001
```

**Assessment:** ✓ EXCELLENT - Non-root user with non-privileged UID.

**Validates Against:**
- CIS Docker Benchmark 4.4 (Use USER directive)
- Pod Security Standards (must run as non-root)

---

### 11.4 Read-Only Root Filesystem (EXCELLENT)

**Current State (Dockerfile:38, deployment.yaml:38):**
- Dockerfile: No write to root filesystem (no RUN mkdir /data, etc.)
- Deployment: `readOnlyRootFilesystem: true`

**Assessment:** ✓ EXCELLENT - Combined Dockerfile + SecurityContext approach.

**Validates Against:**
- CIS Docker Benchmark 5.12 (Read-only root filesystem)
- Pod Security Standards (Restricted)

---

### 11.5 No Unnecessary Dependencies (EXCELLENT)

**Current State (Dockerfile:6):**
```dockerfile
RUN apk add --no-cache musl-dev protobuf-dev make
```

Only build tools; runtime only has:
```dockerfile
RUN apk add --no-cache ca-certificates
```

**Assessment:** ✓ EXCELLENT - Minimal dependency footprint.

---

### 11.6 HEALTHCHECK Configuration (EXCELLENT)

**Current State (Dockerfile:59-60):**
```dockerfile
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:9090/healthz || exit 1
```

**Assessment:** ✓ GOOD - Health check present (though depends on wget binary, which is not in Alpine).

**Issue:** `wget` is not included in the image; this HEALTHCHECK will always fail.

**Remediation:**
```dockerfile
# Add wget for healthcheck
RUN apk add --no-cache ca-certificates wget

# Or use busybox wget (included by default in Alpine):
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:9090/healthz || exit 1
```

Alternatively, remove healthcheck and rely on Kubernetes probes (preferred):
```dockerfile
# HEALTHCHECK removed - let Kubernetes handle health checks
```

---

## 12. DOCKER-COMPOSE.YML SECURITY

### 12.1 Security Options (GOOD)

**Current State (docker-compose.yml:38-40):**
```yaml
security_opt:
  - no-new-privileges:true
```

**Assessment:** ✓ GOOD - Prevents privilege escalation via setuid/setgid.

---

### 12.2 Read-Only Filesystem (GOOD)

**Current State (docker-compose.yml:38):**
```yaml
read_only: true
```

**Assessment:** ✓ GOOD - Immutable filesystem.

---

### 12.3 Resource Limits (GOOD)

**Current State (docker-compose.yml:41-45):**
```yaml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '2.0'
```

**Assessment:** ✓ GOOD - Has limits; missing requests.

**Recommendation:**
```yaml
deploy:
  resources:
    reservations:
      cpus: '0.5'
      memory: 256M
    limits:
      cpus: '2.0'
      memory: 512M
```

---

### 12.4 NATS Configuration (MEDIUM RISK)

**Current State (docker-compose.yml:2-18):**
```yaml
nats-server:
  image: nats:2.11-alpine  # Not pinned by digest!
  command: >
    --jetstream
    --store_dir /data
    --http_port 8222
```

**Issues:**

1. **NATS image not pinned by digest** - Same issue as rustgate Helm chart
2. **No authentication configured** - Default NATS has no users/tokens
3. **HTTP admin port exposed** - 8222 is admin interface

**Remediation:**

```yaml
nats-server:
  image: nats:2.11-alpine@sha256:abc123...  # Pin digest
  command: >
    --jetstream
    --store_dir /data
    --http_port 8222
    --user admin
    --pass <secure-password>
    --require_auth
  environment:
    NATS_JWT: /etc/nats/server.jwt
    NATS_SEED: /etc/nats/server.seed
  volumes:
    - ./nats-config:/etc/nats:ro  # Auth config
```

---

## 13. RUNTIME SECURITY

### 13.1 Falco Integration (NOT CONFIGURED - RECOMMENDED)

**Finding:** No runtime security monitoring configured.

**Assessment:** MISSING - Falco is the industry-standard CNCF project for Kubernetes runtime security.

**Recommendation for Production:**

Install Falco to detect:
- Suspicious system calls in containers
- Crypto miners
- Shell spawning in containers
- Unauthorized file access
- Network anomalies

```bash
# Install Falco Helm chart
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco-system --create-namespace \
  --values falco-values.yaml
```

Example Falco rules for rustgate:
```yaml
- rule: Unauthorized Shell in Container
  desc: Detect shell spawned in container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, dash, zsh)
  output: >
    Unauthorized shell (user=%user.name command=%proc.cmdline container=%container.name)
  priority: WARNING
```

---

## 14. SUPPLY CHAIN SECURITY

### 14.1 OCI Image Labels (GOOD)

**Current State (Dockerfile:44-46):**
```dockerfile
LABEL org.opencontainers.image.source="https://github.com/rchiofalo/rustgate" \
      org.opencontainers.image.description="Secure tactical message router with mTLS and NATS bridge" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
```

**Assessment:** ✓ GOOD - Provides image provenance metadata.

**Recommendation:** Add more labels for provenance:
```dockerfile
LABEL org.opencontainers.image.source="https://github.com/rchiofalo/rustgate" \
      org.opencontainers.image.description="Secure tactical message router with mTLS and NATS bridge" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.vendor="rustgate"
```

---

### 14.2 Dependency Scanning (NOT CONFIGURED)

**Finding:** No SBOM (Software Bill of Materials) or dependency scanning in CI/CD.

**Recommendation:** Add:
```bash
# Generate SBOM
cargo sbom > sbom.json

# Scan for vulnerabilities
cargo audit
cargo deny check

# Docker image scanning
trivy image ghcr.io/rchiofalo/rustgate:0.3.0
```

---

## 15. CLUSTER-LEVEL SECURITY (OUT OF SCOPE - DOCUMENTATION)

These are not Helm/container issues but important for the cluster:

### 15.1 Pod Security Standards Enforcement

**Recommendation:** Enforce Restricted PSS at namespace level:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rustgate
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 15.2 Network Policy Enforcement

**Recommendation:** Enable CNI with NetworkPolicy support (Calico, Cilium, Weave):

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml
```

### 15.3 Encryption at Rest

**Recommendation:** Enable etcd encryption:

```yaml
# /etc/kubernetes/enc-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
```

---

## SUMMARY OF CRITICAL FINDINGS

### Immediate Action Required (P0 - Before Production)

1. **Image Digest Pinning** - Pin container image by SHA256, not tag
2. **NetworkPolicy Enablement** - Enable and properly configure NetworkPolicy
3. **NetworkPolicy Fixes** - Add namespace/pod selectors to ingress and egress rules
4. **Secrets Encryption** - Document requirement for cluster-level etcd encryption

### High Priority (P1 - Before Scaling to Production)

5. **Enrollment Credentials** - Remove plaintext fallback; require Kubernetes Secret
6. **Federation Peers** - Use existingSecret exclusively
7. **Ingress TLS** - Mandate TLS, add auto-redirect, document mTLS backend limitation
8. **Storage Encryption** - Use encrypted StorageClass for PVC
9. **NATS Authentication** - Add credentials to docker-compose.yml

### Medium Priority (P2 - Before Full Production HA)

10. **Metrics Authentication** - Restrict metrics port to monitoring namespace
11. **Plaintext Traffic** - Document risks; restrict via NetworkPolicy if enabled
12. **ServiceAccount** - Add explicit ServiceAccount resource template
13. **Falco Integration** - Install runtime security monitoring
14. **Certificate Rotation** - Implement cert-manager for auto-renewal
15. **SBOM Generation** - Add dependency scanning to CI/CD

### Low Priority (P3 - Nice to Have)

16. **Dockerfile wget** - Fix or remove HEALTHCHECK
17. **AppArmor/SELinux** - Add if platform supports
18. **Topology Zones** - Add zone spread for multi-AZ clusters
19. **External Secrets Operator** - Integrate for secret rotation
20. **NATS Image Digest** - Pin docker-compose NATS image by digest

---

## SOURCES & REFERENCES

The findings in this audit are based on:

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission Controller](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes RBAC Best Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes Secrets Best Practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Helm Security Best Practices](https://www.sysdig.com/blog/how-to-secure-helm)
- [Container Image Digest Security](https://edu.chainguard.dev/chainguard/chainguard-images/how-to-use/container-image-digests/)
- [Kubernetes Ingress TLS Termination](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Kubernetes Runtime Security with Falco](https://falco.org/)
- [Pod Disruption Budgets](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)
- [Pod Topology Spread Constraints](https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/)


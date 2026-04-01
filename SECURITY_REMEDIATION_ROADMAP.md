# Security Remediation Roadmap for rustgate

## Overview

This document provides a prioritized checklist for addressing security findings from the comprehensive audit. Issues are grouped by priority and timeline.

---

## PHASE 1: CRITICAL PATH (Weeks 1-2)

Must be completed before any production deployment.

### Issue 1.1: Image Digest Pinning
**Status:** Not Started
**Effort:** 30 minutes
**Owner:** DevOps

**Steps:**
1. Build Docker image and capture SHA256:
   ```bash
   docker build -t ghcr.io/rchiofalo/rustgate:0.3.0 .
   # Output: sha256:abcdef1234567890...
   ```

2. Update helm/values.yaml:
   ```yaml
   image:
     repository: ghcr.io/rchiofalo/rustgate
     tag: "0.3.0@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
     pullPolicy: IfNotPresent
   ```

3. Verify with helm template:
   ```bash
   helm template rustgate helm/ | grep image:
   ```

**Tests:**
- ✓ helm lint passes
- ✓ helm template produces correct image digest

---

### Issue 1.2: Enable NetworkPolicy
**Status:** Not Started
**Effort:** 2 hours
**Owner:** Platform Engineering

**Steps:**
1. Update helm/values-production.yaml:
   ```yaml
   networkPolicy:
     enabled: true
   ```

2. Fix NetworkPolicy ingress rules in helm/templates/networkpolicy.yaml:
   ```yaml
   ingress:
     - from:
         - podSelector:
             matchLabels:
               app.kubernetes.io/name: rustgate
         - namespaceSelector:
             matchLabels:
               name: monitoring
       ports:
         - port: {{ .Values.service.port }}
           protocol: TCP
   ```

3. Fix NetworkPolicy egress DNS rules:
   ```yaml
   egress:
     - to:
         - namespaceSelector:
             matchLabels:
               name: kube-system
           podSelector:
             matchLabels:
               k8s-app: kube-dns
       ports:
         - port: 53
           protocol: UDP
         - port: 53
           protocol: TCP
   ```

4. Fix egress NATS rules:
   ```yaml
   {{- if .Values.nats.enabled }}
   - to:
       - namespaceSelector:
           matchLabels:
             name: nats
       - podSelector:
           matchLabels:
             app: nats-server
     ports:
       - port: 4222
         protocol: TCP
   {{- end }}
   ```

5. Test in staging cluster:
   ```bash
   helm install rustgate helm/ -n rustgate -f helm/values-production.yaml
   kubectl get networkpolicies -n rustgate
   kubectl describe networkpolicy rustgate -n rustgate
   ```

6. Verify traffic flow:
   ```bash
   # Pod should reach NATS
   kubectl exec -it deploy/rustgate -c rustgate -- nslookup nats.nats
   # Pod should NOT reach arbitrary namespaces
   kubectl exec -it deploy/rustgate -c rustgate -- curl http://default-service:8080
   ```

**Tests:**
- ✓ NetworkPolicy resource created
- ✓ Ingress rules allow only specified sources
- ✓ Egress DNS works (kube-dns accessible)
- ✓ Egress NATS works
- ✓ Cross-namespace traffic blocked

---

### Issue 1.3: Remove Plaintext Secrets Path
**Status:** Not Started
**Effort:** 1 hour
**Owner:** DevOps

**Steps:**
1. Update helm/templates/deployment.yaml to require Secret for enrollment:
   ```yaml
   {{- if .Values.enrollment.enabled }}
     {{- if not .Values.enrollment.existingSecret }}
       {{ fail "enrollment.enabled requires enrollment.existingSecret" }}
     {{- end }}
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
   {{- end }}
   ```

2. Remove plaintext fallback entirely

3. Document in helm/values.yaml:
   ```yaml
   enrollment:
     existingSecret: ""  # REQUIRED when enrollment.enabled=true. Create with: kubectl create secret generic rustgate-enrollment-creds --from-literal=ENROLLMENT_USER=admin --from-literal=ENROLLMENT_PASSWORD=...
   ```

**Tests:**
- ✓ helm lint fails if enrollment.enabled=true without existingSecret
- ✓ helm template does not output plaintext credentials

---

### Issue 1.4: Require NATS Secret
**Status:** Not Started
**Effort:** 30 minutes
**Owner:** DevOps

**Steps:**
1. Update helm/templates/deployment.yaml:
   ```yaml
   {{- if .Values.nats.enabled }}
     {{- if .Values.nats.existingSecret }}
       - name: NATS_CREDENTIALS
         valueFrom:
           secretKeyRef:
             name: {{ .Values.nats.existingSecret }}
             key: NATS_CREDENTIALS
     {{- else }}
       {{ fail "nats.enabled requires nats.existingSecret in production" }}
     {{- end }}
   {{- end }}
   ```

2. Update helm/values.yaml:
   ```yaml
   nats:
     existingSecret: ""  # REQUIRED. Create with: kubectl create secret generic rustgate-nats --from-literal=NATS_CREDENTIALS=...
   ```

**Tests:**
- ✓ plaintext nats.credentials path removed
- ✓ existingSecret required

---

### Issue 1.5: Enable Cluster-Level etcd Encryption
**Status:** Not Started
**Effort:** Varies (cluster admin task)
**Owner:** Platform/Security Team

**Steps:**
1. Generate 32-byte encryption key:
   ```bash
   head -c 32 /dev/urandom | base64
   ```

2. Create /etc/kubernetes/enc-config.yaml on control plane:
   ```yaml
   apiVersion: apiserver.config.k8s.io/v1
   kind: EncryptionConfiguration
   resources:
     - resources:
         - secrets
       providers:
         - aescbc:
             keys:
               - name: key1
                 secret: <base64-key>
         - identity: {}
   ```

3. Update kube-apiserver manifest to add:
   ```yaml
   --encryption-provider-config=/etc/kubernetes/enc-config.yaml
   --encryption-provider-config-automatic-reload=true
   ```

4. Restart kube-apiserver (will cause brief outage)

5. Verify all secrets are encrypted:
   ```bash
   etcdctl get /registry/secrets/default/ | file -
   # Should show "data" (encrypted), not readable JSON
   ```

**Tests:**
- ✓ etcd contents encrypted
- ✓ Secrets accessible via kubectl
- ✓ Old unencrypted Secrets can be rotated

---

## PHASE 2: HIGH PRIORITY (Weeks 2-4)

Should be completed before scaling to production HA.

### Issue 2.1: Fix Ingress TLS Configuration
**Status:** Not Started
**Effort:** 2 hours
**Owner:** DevOps/Platform

**Steps:**
1. Install cert-manager (if not present):
   ```bash
   helm repo add jetstack https://charts.jetstack.io
   helm install cert-manager jetstack/cert-manager \
     --namespace cert-manager --create-namespace \
     --set installCRDs=true
   ```

2. Create ClusterIssuer for Let's Encrypt:
   ```yaml
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-prod
   spec:
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: admin@example.com
       privateKeySecretRef:
         name: letsencrypt-prod
       solvers:
         - http01:
             ingress:
               class: nginx
   ```

3. Update helm/values-production.yaml:
   ```yaml
   ingress:
     enabled: true
     className: nginx
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
       nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
       nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
       nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
     hosts:
       - host: rustgate.example.com
         paths:
           - path: /
             pathType: Prefix
     tls:
       - secretName: rustgate-tls
         hosts:
           - rustgate.example.com
   ```

4. Document backend mTLS limitation:
   - Add comment in values.yaml explaining mTLS backend requires service mesh

**Tests:**
- ✓ cert-manager issues certificate
- ✓ Ingress HTTPS endpoint reachable
- ✓ HTTP redirects to HTTPS
- ✓ TLS 1.2+ enforced

---

### Issue 2.2: Use Encrypted StorageClass for PVC
**Status:** Not Started
**Effort:** 1 hour
**Owner:** Platform/Storage

**Steps:**
1. Identify encrypted StorageClass in your cluster:
   ```bash
   kubectl get storageclasses
   # Example: gp3-encrypted (AWS), pd-ssd-encrypted (GCP), etc.
   ```

2. Update helm/values-production.yaml:
   ```yaml
   persistence:
     enabled: true
     storageClassName: gp3-encrypted  # Use your encrypted class
     size: 10Gi

   dataPackage:
     storageClassName: gp3-encrypted
     storageSize: 10Gi
   ```

3. Verify PVC uses encryption:
   ```bash
   kubectl describe pvc rustgate-federation -n rustgate
   # Should show: storageClassName: gp3-encrypted
   ```

**Tests:**
- ✓ PVC uses encrypted StorageClass
- ✓ Data persists correctly
- ✓ Volume snapshots work (if needed)

---

### Issue 2.3: Add Explicit ServiceAccount
**Status:** Not Started
**Effort:** 30 minutes
**Owner:** DevOps

**Steps:**
1. Create helm/templates/serviceaccount.yaml:
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: {{ include "rustgate.fullname" . }}
     labels:
       {{- include "rustgate.labels" . | nindent 4 }}
   automountServiceAccountToken: false
   ```

2. Update helm/templates/deployment.yaml:
   ```yaml
   spec:
     serviceAccountName: {{ include "rustgate.fullname" . }}
     automountServiceAccountToken: false
   ```

3. Verify:
   ```bash
   helm template rustgate helm/ | grep serviceAccountName
   ```

**Tests:**
- ✓ ServiceAccount created
- ✓ Referenced in Deployment
- ✓ automountServiceAccountToken: false

---

### Issue 2.4: Add NATS Authentication
**Status:** Not Started
**Effort:** 2 hours
**Owner:** DevOps

**Steps:**
1. Generate NATS user/password:
   ```bash
   nats-server -c /dev/null -D 2>&1 | grep -i jwt
   # Or use:
   openssl rand -base64 32  # For password
   ```

2. Update docker-compose.yml:
   ```yaml
   nats-server:
     image: nats:2.11-alpine@sha256:abc123...  # Pin digest
     command: >
       --jetstream
       --store_dir /data
       --http_port 8222
       --require_auth
       --user admin
       --pass <generated-password>
   ```

3. Create NATS credentials file and secret:
   ```bash
   # Generate credentials
   nats-server --user admin --pass <password> --gen-credentials --sys=rustgate

   # Create Kubernetes Secret
   kubectl create secret generic rustgate-nats \
     --from-file=NATS_CREDENTIALS=creds.txt
   ```

4. Update Helm values:
   ```yaml
   nats:
     enabled: true
     url: nats://nats:4222
     existingSecret: rustgate-nats
   ```

**Tests:**
- ✓ NATS requires authentication
- ✓ rustgate connects successfully
- ✓ Unauthenticated connections fail

---

### Issue 2.5: Restrict Metrics Port with NetworkPolicy
**Status:** Not Started
**Effort:** 1 hour
**Owner:** Platform

**Steps:**
1. Update helm/templates/networkpolicy.yaml metrics ingress:
   ```yaml
   {{- if .Values.metrics.enabled }}
   - from:
       - namespaceSelector:
           matchLabels:
             name: monitoring
       - podSelector:
           matchLabels:
             app: prometheus
     ports:
       - port: {{ .Values.metrics.port }}
         protocol: TCP
   {{- end }}
   ```

2. Label monitoring namespace:
   ```bash
   kubectl label namespace monitoring monitoring=true
   ```

3. Label Prometheus pods:
   ```bash
   kubectl patch deployment prometheus -n monitoring \
     -p '{"spec":{"template":{"metadata":{"labels":{"app":"prometheus"}}}}}'
   ```

**Tests:**
- ✓ Prometheus can scrape metrics
- ✓ Other pods cannot reach metrics port

---

## PHASE 3: MEDIUM PRIORITY (Weeks 4-6)

Can be completed alongside Phase 2 or after Phase 1 & 2 are in production.

### Issue 3.1: Install Falco for Runtime Security
**Status:** Not Started
**Effort:** 3 hours
**Owner:** Security/Platform

**Steps:**
1. Install Falco Helm chart:
   ```bash
   helm repo add falcosecurity https://falcosecurity.github.io/charts
   helm install falco falcosecurity/falco \
     --namespace falco-system --create-namespace \
     -f falco-values.yaml
   ```

2. Create falco-values.yaml:
   ```yaml
   falco:
     grpc:
       enabled: true
     grpcOutput:
       enabled: true
       service:
         type: ClusterIP
         port: 5060

   ebpf:
     enabled: true

   rules:
     - https://raw.githubusercontent.com/falcosecurity/rules/main/rules/k8s_audit_rules.yaml
   ```

3. Create custom rules for rustgate:
   ```yaml
   - rule: Unauthorized Shell in rustgate
     desc: Detect shell spawned in rustgate container
     condition: >
       spawned_process and
       container and
       container.labels.app = "rustgate" and
       proc.name in (bash, sh, dash, zsh)
     output: >
       Unauthorized shell in rustgate (user=%user.name command=%proc.cmdline)
     priority: WARNING
   ```

4. Set up alerting to security team

**Tests:**
- ✓ Falco pods running
- ✓ Rules loaded
- ✓ Alerts triggered on suspicious activity
- ✓ Integration with SIEM

---

### Issue 3.2: Implement Certificate Auto-Rotation
**Status:** Not Started
**Effort:** 2 hours
**Owner:** DevOps

**Steps:**
1. Create certificate renewal script (helm/cert-renewal-cron.yaml):
   ```bash
   #!/bin/bash
   set -e

   # Check if cert will expire in 30 days
   EXPIRY=$(openssl x509 -enddate -noout -in /certs/server.crt | cut -d= -f2)
   EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
   NOW_EPOCH=$(date +%s)
   DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

   if [ $DAYS_LEFT -lt 30 ]; then
     # Rotate certificate
     kubectl create secret generic rustgate-tls \
       --from-file=tls.crt=./new-server.crt \
       --from-file=tls.key=./new-server.key \
       -n rustgate --dry-run=client -o yaml | kubectl apply -f -
   fi
   ```

2. Add cert-manager renewal (if using cert-manager):
   ```yaml
   certificate:
     apiVersion: cert-manager.io/v1
     kind: Certificate
     metadata:
       name: rustgate
       namespace: rustgate
     spec:
       secretName: rustgate-tls
       issuerRef:
         name: letsencrypt-prod
         kind: ClusterIssuer
       dnsNames:
         - rustgate.example.com
       renewBefore: 720h  # Renew 30 days before expiry
   ```

3. Create CronJob for rotation check:
   ```yaml
   apiVersion: batch/v1
   kind: CronJob
   metadata:
     name: rustgate-cert-check
   spec:
     schedule: "0 0 * * *"  # Daily
     jobTemplate:
       spec:
         template:
           spec:
             serviceAccountName: rustgate-cert-checker
             containers:
               - name: checker
                 image: alpine:3.23
                 command: ["/check-cert.sh"]
             restartPolicy: OnFailure
   ```

**Tests:**
- ✓ Certificates renew before expiry
- ✓ rustgate restarts with new cert
- ✓ TLS handshake succeeds after renewal

---

### Issue 3.3: Add SBOM Generation to CI/CD
**Status:** Not Started
**Effort:** 1 hour
**Owner:** DevOps/Security

**Steps:**
1. Add to CI/CD pipeline (GitHub Actions example):
   ```yaml
   - name: Generate SBOM
     run: |
       cargo install cargo-sbom
       cargo sbom > sbom.json

   - name: Audit dependencies
     run: |
       cargo audit
       cargo deny check

   - name: Scan Docker image
     run: |
       trivy image ghcr.io/rchiofalo/rustgate:${{ github.sha }}

   - name: Upload SBOM
     uses: actions/upload-artifact@v3
     with:
       name: sbom
       path: sbom.json
   ```

2. Store SBOM with image metadata

3. Scan during deployment:
   ```bash
   trivy image --severity CRITICAL,HIGH rustgate:latest
   ```

**Tests:**
- ✓ SBOM generated
- ✓ Vulnerabilities detected
- ✓ Build fails on critical CVEs

---

## PHASE 4: LOW PRIORITY (Ongoing)

Nice-to-have improvements and cleanup.

### Issue 4.1: Fix Dockerfile HEALTHCHECK
**Status:** Not Started
**Effort:** 15 minutes

**Steps:**
1. Remove HEALTHCHECK or add wget:
   ```dockerfile
   # Option 1: Add wget (adds ~3MB to image)
   RUN apk add --no-cache ca-certificates wget

   # Option 2: Remove HEALTHCHECK (Kubernetes probes are sufficient)
   # Delete or comment out:
   # HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
   #     CMD wget --spider -q http://localhost:9090/healthz || exit 1
   ```

---

### Issue 4.2: Pin NATS Image in docker-compose.yml
**Status:** Not Started
**Effort:** 15 minutes

**Steps:**
1. Get current NATS digest:
   ```bash
   docker pull nats:2.11-alpine
   docker inspect nats:2.11-alpine | jq '.[] | .RepoDigests'
   ```

2. Update docker-compose.yml:
   ```yaml
   nats-server:
     image: nats:2.11-alpine@sha256:abc123...
   ```

---

### Issue 4.3: Add AppArmor/SELinux Support
**Status:** Not Started
**Effort:** 3 hours
**Owner:** Security (optional)

Only if your Kubernetes cluster enforces AppArmor or SELinux.

**Steps:**
1. Create AppArmor profile (if supported):
   ```yaml
   securityContext:
     appArmorProfile:
       type: RuntimeDefault
   ```

2. Or create custom SELinux context (if enforced):
   ```yaml
   securityContext:
     seLinuxOptions:
       level: "s0:c123,c456"
   ```

---

### Issue 4.4: Add Zone-Aware Topology Spread
**Status:** Not Started
**Effort:** 30 minutes

**Steps:**
1. Update helm/values-production.yaml:
   ```yaml
   topologySpreadConstraints:
     - maxSkew: 1
       topologyKey: kubernetes.io/hostname
       whenUnsatisfiable: DoNotSchedule
       labelSelector:
         matchLabels:
           app.kubernetes.io/name: rustgate
     - maxSkew: 2
       topologyKey: topology.kubernetes.io/zone
       whenUnsatisfiable: ScheduleAnyway
       labelSelector:
         matchLabels:
           app.kubernetes.io/name: rustgate
   ```

---

## DEPLOYMENT CHECKLIST

Before deploying to production, verify all Phase 1 & 2 items:

```
PHASE 1 (CRITICAL):
- [ ] Image digest pinned in values.yaml
- [ ] NetworkPolicy enabled and rules fixed
- [ ] Plaintext secrets removed
- [ ] NATS credentials in Secret
- [ ] Cluster etcd encryption enabled

PHASE 2 (HIGH):
- [ ] Ingress TLS configured with cert-manager
- [ ] StorageClass encrypted
- [ ] ServiceAccount created
- [ ] NATS authentication enabled
- [ ] Metrics port restricted

PHASE 3 (MEDIUM):
- [ ] Falco installed and alerting
- [ ] Certificate auto-rotation configured
- [ ] SBOM generation in CI/CD
- [ ] Dependency scanning passing

PHASE 4 (LOW):
- [ ] Dockerfile HEALTHCHECK fixed
- [ ] NATS image pinned by digest
- [ ] AppArmor/SELinux configured
- [ ] Zone-aware topology spread
```

---

## Testing Strategy

### Unit Tests
```bash
helm lint helm/
helm template rustgate helm/ | kubeval
```

### Integration Tests
```bash
# Deploy to staging
helm install rustgate helm/ -n rustgate-staging -f helm/values-production.yaml

# Test connectivity
kubectl exec -it deploy/rustgate -c rustgate -- \
  nc -zv nats.nats 4222

# Test health
kubectl port-forward svc/rustgate 9090:9090
curl http://localhost:9090/healthz
```

### Security Tests
```bash
# Verify SecurityContext
kubectl get pod -o jsonpath='{.items[0].spec.securityContext}'

# Verify NetworkPolicy
kubectl get networkpolicies
kubectl describe networkpolicy rustgate

# Verify no privileged containers
kubectl get pods -o jsonpath='{.items[0].spec.containers[0].securityContext}'
```

---

## Rollback Plan

If security issues are found in production:

1. **Immediate:** Scale to 0 and investigate
   ```bash
   kubectl scale deployment rustgate --replicas=0
   ```

2. **Revert:** Rollback to previous version
   ```bash
   helm rollback rustgate -1
   ```

3. **Fix:** Address security issue and re-test
4. **Redeploy:** With new patch version


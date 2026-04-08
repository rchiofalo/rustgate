# Quickstart

This walks you through running a single rustgate instance with self-signed test certificates and a single client connection. For production guidance see [Deployment](../operations/deployment.md).

## 1. Generate test certificates

```bash
# Certificate authority
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem \
  -days 365 -nodes -subj "/CN=rustgate-ca"

# Server certificate
openssl req -newkey rsa:4096 -keyout server-key.pem -out server.csr \
  -nodes -subj "/CN=rustgate-server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem -days 365

mkdir -p certs
cp ca.pem        certs/ca.crt
cp server.pem    certs/server.crt
cp server-key.pem certs/server.key
```

> ⚠️ Test certs only. For production use the [enrollment server](../architecture/enrollment.md) or your existing PKI. See [TLS Certificates](../security/mtls.md).

## 2. Run with Docker Compose

```bash
docker compose up
```

The bundled `docker-compose.yml` mounts `./certs/` into the container and exposes the default mTLS listener on `8089` and the metrics endpoint on `9100`.

## 3. Verify

```bash
# Health
curl -k https://localhost:9100/health/ready

# Metrics
curl -k https://localhost:9100/metrics | head -20
```

You should see `rustgate_build_info`, `rustgate_active_connections`, and the routing/dedup counters.

## 4. Connect a client

Generate a client cert signed by the same CA, then use any mTLS-capable client to dial `localhost:8089`. The client's CN becomes its identity and any X.509 v3 extensions you defined become its group membership — see [Architecture: Overview](../architecture/overview.md) for the full identity model.

Next steps: [Configuration](./configuration.md), [Deployment](../operations/deployment.md), [Observability](../operations/observability.md).

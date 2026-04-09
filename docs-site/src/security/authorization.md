# Authorization

The `rustgate-authz` crate provides per-message RBAC/ABAC authorization. Policies are evaluated inline on the routing hot-path, with a sharded LRU cache that delivers sub-100ns P99 latency on cache hits.

## Policy Backends

| Backend | Flag | Feature |
|---|---|---|
| JSON | `--authz-policy-format json` | (default) |
| Cedar | `--authz-policy-format cedar` | `--features cedar` |

Both backends share the same semantics: **deny by default**. If no rule explicitly permits a message, it is dropped.

## JSON Policy Format

Policies are loaded from `--authz-policy-file` and hot-reloaded on file changes (the last-good policy is preserved on validation failure). Each rule specifies a source identity pattern, a destination pattern, and an action (allow/deny):

```json
{
  "rules": [
    {
      "source": { "cn": "sensor-*", "groups": ["FieldTeam"] },
      "destination": { "groups": ["HQ"] },
      "action": "allow"
    }
  ]
}
```

## Cedar Policy Backend

When compiled with `--features cedar`, the `cedar` policy format is available. Cedar policies use the [Cedar language](https://www.cedarpolicy.com/) for expressive attribute-based access control:

```cedar
permit(
  principal in Group::"FieldTeam",
  action == Action::"route",
  resource in Group::"HQ"
);
```

Cedar policies support the full Cedar language including conditions, context attributes, and hierarchical entity relationships.

## Identity Attributes

The authorization engine receives identity attributes extracted from the mTLS certificate:

- **CN** (Common Name) from the subject
- **Groups** from OU fields
- **SPIFFE ID** from URI SANs (when available)
- **Additional attributes** from subject and SAN fields

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--authz-policy-file` | `RUSTGATE_AUTHZ_POLICY_FILE` | (disabled) |
| `--authz-policy-format` | `RUSTGATE_AUTHZ_POLICY_FORMAT` | `json` |
| `--authz-reload-interval` | `RUSTGATE_AUTHZ_RELOAD_INTERVAL` | `30` (seconds) |
| `--authz-fail-open` | `RUSTGATE_AUTHZ_FAIL_OPEN` | `false` |

## Observability

Every deny decision and policy reload is emitted as a structured audit event. Under `--features metrics`, Prometheus counters track allow/deny rates and cache hit ratios.

## Related

- [Security Posture](./posture.md) for the overall security model.
- [Configuration Reference](../reference/configuration.md) for the full flag list.

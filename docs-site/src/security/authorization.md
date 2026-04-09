# Authorization

The `rustgate-authz` crate provides per-message RBAC/ABAC authorization. Policies are evaluated inline on the routing hot-path, with a sharded LRU cache that delivers sub-100ns P99 latency on cache hits.

## Policy Backends

| Backend | Flag | Feature |
|---|---|---|
| JSON | `--authz-policy-format native` | (default) |
| Cedar | `--authz-policy-format cedar` | `--features cedar` |

Both backends share the same semantics: **deny by default**. If no rule explicitly permits a message, it is dropped.

## JSON Policy Format

Policies are loaded from `--authz-policy-file` and hot-reloaded on file changes (the last-good policy is preserved on validation failure, max 4 MiB). Each rule specifies a subject matcher, a resource matcher, and an effect. Rule IDs must be unique. Unknown fields are rejected (`deny_unknown_fields`):

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {
      "id": "allow-field-team-to-hq",
      "effect": "allow",
      "action": "send",
      "subject": { "groups_any_of": ["FieldTeam"] },
      "resource": { "kind": "group", "group": "HQ" }
    },
    {
      "id": "allow-federation-svc",
      "effect": "allow",
      "action": "federate",
      "subject": { "cn_eq": "federation-svc" },
      "resource": { "kind": "federation" }
    }
  ]
}
```

### Subject Matchers

All fields are optional and AND-combined. An empty `subject` matches any identity:

| Field | Type | Semantics |
|---|---|---|
| `cn_eq` | string | Exact CN match |
| `groups_any_of` | string[] | Subject belongs to at least one group |
| `groups_all_of` | string[] | Subject belongs to every group |
| `spiffe_prefix` | string | SPIFFE ID starts with this prefix |
| `attribute_eq` | object | Exact match on additional identity attributes |

### Resource Matchers

Resources are tagged with a `kind` discriminator:

| Kind | Extra fields | Matches |
|---|---|---|
| `group` | `group` (required) | Messages routed to a specific group |
| `direct` | `target_cn` (optional) | Direct-to-identity messages |
| `broadcast` | — | Broadcast messages |
| `federation` | `peer_id` (optional) | Federation forwarding |
| `nats_subject` | `subject_pattern` (required) | NATS publish (trailing `*` wildcard) |
| `any` | — | Any resource |

### Actions

`send`, `receive`, `federate`, `publish`, `subscribe`

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
| `--authz-policy-format` | `RUSTGATE_AUTHZ_POLICY_FORMAT` | `native` |
| `--authz-reload-interval` | `RUSTGATE_AUTHZ_RELOAD_INTERVAL` | `5` (seconds) |
| `--authz-fail-open` | `RUSTGATE_AUTHZ_FAIL_OPEN` | `false` |

## Observability

Every deny decision and policy reload is emitted as a structured audit event. Under `--features metrics`, Prometheus counters track allow/deny rates and cache hit ratios.

## Related

- [Security Posture](./posture.md) for the overall security model.
- [Configuration Reference](../reference/configuration.md) for the full flag list.

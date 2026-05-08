# rustgate-missions

TAK-compatible **Data Package** storage — the lightweight half of
the TAK Mission Sync feature family
([issue #860](https://github.com/rchiofalo/rustgate/issues/860),
Feature 17). Content-addressed, HMAC-tagged, filesystem-backed.

## What this crate does

- Accepts ZIP-bodied **TAK Mission Packages** through a
  content-addressed store keyed by the SHA-256 hash of the body.
- Validates the package's `MANIFEST/manifest.xml` as a v2
  MissionPackageManifest (best-effort) so the HTTP layer can reject
  malformed uploads early.
- Tags every sidecar metadata blob with HMAC-SHA256 under a
  store-local integrity key, verified in constant time on every
  download via `rustgate_core::crypto::hmac_sha256_verify`. An
  attacker who tampers with the JSON sidecar cannot redirect a
  download by rewriting the `name` or `creator_uid` fields.
- Enforces per-package and per-store size caps so a malicious or
  buggy uploader cannot fill the operator's disk.

## Wire-level scope (HTTP API in `rustgate-admin`)

| Method | Path                       | Purpose                                              |
|--------|----------------------------|------------------------------------------------------|
| POST   | `/api/packages`            | Upload a Mission Package (multipart/form-data, ZIP)  |
| GET    | `/api/packages`            | List stored packages (JSON array)                    |
| GET    | `/api/packages/{hash}`     | Download body by SHA-256 hash                        |
| DELETE | `/api/packages/{hash}`     | Remove                                               |

The HTTP routing lives in
[`rustgate-admin`](../rustgate-admin/README.md) under the `missions`
feature flag; this crate owns the on-disk store, the manifest
parser, and the integrity-tag discipline.

## TAK package format

```
package.zip
├── MANIFEST/
│   └── manifest.xml       (MissionPackageManifest v2)
└── <hash-folder>/
    ├── truststore-root.p12
    ├── server-connection.pref
    └── overlay.kmz
```

The manifest parser ([`manifest::parse_manifest_xml`]) validates
just enough of the v2 schema to confirm:

1. Root element is `<MissionPackageManifest version="2">`.
2. `<Configuration>` parameters are present as a flat
   `name → value` map.
3. At least one `<Content zipEntry="…">` entry exists.

Unrecognised elements and attributes are ignored — a future
schema revision rides through without a parser change.

## Integrity model

Every sidecar (`{hash}.meta.json`) is a `{ meta, tag }` envelope
where `tag` is the lowercase-hex HMAC-SHA256 over the canonical
metadata blob `hash || size || name || creator_uid || upload_time`.

```
                ┌─────────────────────┐
                │ canonical_tag_input │
                └──────────┬──────────┘
                           │
         hash ┐  size ┐  name ┐ creator_uid ┐ upload_time
              └─0x00──┴─0x00──┴────0x00─────┴────0x00────
                           │
                           ▼
                ┌─────────────────────┐
                │  HMAC-SHA256(key)   │
                └──────────┬──────────┘
                           │
                           ▼
                       hex(tag) → sidecar
```

Verification on every download uses
`rustgate_core::crypto::hmac_sha256_verify`, which delegates to
`subtle::ConstantTimeEq` — the timing-side-channel discipline lives
in one place workspace-wide.

## What is **not** here (deferred)

This crate is the **MVP / Feature 17 of #860** only. The longer
Feature 6 — full Missions API — is intentionally out of scope and
remains tracked under the same umbrella issue:

- `POST /api/missions/{name}` — create mission
- `GET  /api/missions/{name}` — metadata
- `POST /api/missions/{name}/packages` — upload to a named mission
- `POST /api/missions/{name}/subscribe` — subscribe a client
- `GET  /api/missions/{name}/changes` — Server-Sent Events stream
- Mission CoT events: `t-x-m-c` (created), `t-x-m-d` (deleted),
  `t-x-m-n` (notification)
- Optional `KeyRing`-encrypted body storage via
  `rustgate_archive::encrypted::EncryptedWriter`

Federation replication of stored packages across rustgate peers is
also deferred — a future federation-V2 message can fan the manifest
plus a content-fetch URL across the mesh.

## Where to look first

- `crates/rustgate-missions/src/store.rs` — `PackageStore`,
  capacity tracking, sidecar envelope layout, HMAC verification.
- `crates/rustgate-missions/src/manifest.rs` — minimal v2 manifest
  parser.
- `crates/rustgate-missions/src/error.rs` — typed error surface
  consumed by the HTTP handler.

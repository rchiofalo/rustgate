# Edge ML Inference Pipeline

The inference pipeline is an optional subsystem that attaches
machine-learning–derived attributes (classification, anomaly score,
predicted intent) to entities **as they flow through the router**. The
router itself stays vendor- and framework-agnostic; only the
`rustgate-inference` crate knows about model formats and tensor shapes.

It is **off by default**. With no `--inference-config` set there is no
behavioural change and no hot-path cost beyond one atomic pointer load on
the router's `OnRouted` slot.

## What it does

1. After a message is admitted through the router's Send-PEP allow path,
   the router fires its `OnRouted` callback. The inference pipeline
   installs one such callback.
2. The callback decodes the routed message's payload via the same
   `EntityCodecRegistry` the router uses for its routed-by-kind metrics,
   so there is no parser-differential between routing and inference.
   Payloads that do not decode to an entity fall through silently.
3. The decoded entity is run through every registered model in order. Each
   model produces an `InferenceResult` — a model name, an optional label, a
   confidence in `[0.0, 1.0]`, and a free-form attribute bag.
4. Each result is wrapped in a JSON envelope and **re-injected into the
   router** as a new `RoutableMessage`, preserving the original source
   identity and destination so ACL, authz, dedup, and egress all re-apply.

The re-injected messages are tagged with `source_protocol = "inference"`.
The callback short-circuits on any inbound message already carrying that
tag, so a synthesized event is never itself re-inferred — this loop guard
is structurally identical to the federation crate's `source_protocol =
"federation"` discipline.

## Threat model & scope

- The pipeline runs **after** admission and Send-PEP, on traffic the
  router already accepted. It is an enrichment stage, not an access
  control.
- Re-injected results go back through `Router::route`, so they are subject
  to the **same** ACL and authz checks as any other message from the
  original source identity. Inference cannot be used to smuggle a message
  past a policy the source could not already satisfy.
- The re-injection sink dispatches on a background task, so a slow model
  cannot stall the routing critical path. Model errors are downgraded to a
  `debug` log; one misbehaving model does not poison the pipeline.

## Building with inference

The pipeline lives behind the `inference` cargo feature on
`rustgate-server`, plus a **backend** feature that selects the model
executor:

```bash
# Deterministic in-memory mock backend (tests, local development):
cargo build -p rustgate-server --features inference-mock
```

`inference-mock` implies `inference`. The mock backend registers one
deterministic model per pipeline stage that emits a fixed label (the
stage's `target`) and confidence — enough to exercise the end-to-end
re-injection path without any native dependencies or model files.

With only the umbrella `inference` feature and **no** backend, the wiring
warns at startup and installs nothing. The ONNX / `ort` real backend is
deferred work and will land behind a future `inference-onnx` feature; it
joins the same backend-selection cascade without changing the flag or the
config shape.

## Enabling at runtime

Point the server at an inference config file:

```bash
rustgate-server --inference-config /etc/rustgate/inference.toml
# or RUSTGATE_INFERENCE_CONFIG=…
```

When set, the server reads and validates the `[inference]` block at
startup, builds the pipeline, installs the back-annotation callback, and
logs the active model count. A missing or invalid config does **not** block
startup — failures log via `warn!` and the server continues without the
pipeline (inference is an opt-in enrichment, not a hard dependency).

## Configuration reference

The config file carries a single `[inference]` block. Field names are
kebab-case at the TOML layer.

```toml
[inference]
# Base directory containing model files. Relative `model-path` values in
# pipeline stages resolve against this. (The mock backend does not read
# files; this is still required for config validation and the real backend.)
models-dir = "/var/lib/rustgate/models"

# Cadence (seconds) at which an optional reload task re-scans the models
# directory. Default: 60.
reload-interval-secs = 60

# One stage per model. Models run in sequence per entity. An empty pipeline
# is permitted (the pipeline becomes a no-op).
[[inference.pipeline]]
model-name = "vehicle-classifier"   # logical name; used for log/metric labels
model-path = "vehicle_v3.onnx"       # resolved against models-dir when relative
target = "classify"                  # classify | anomaly | predict
confidence-threshold = 0.65          # optional per-model override (default 0.5)

[[inference.pipeline]]
model-name = "track-anomaly"
model-path = "anomaly_v1.onnx"
target = "anomaly"
```

Validation rejects: a duplicate `model-name` across stages, a
`confidence-threshold` outside `[0.0, 1.0]`, and an empty `models-dir`.
Unknown keys are rejected (`deny_unknown_fields`).

Results whose confidence falls below the effective threshold (per-model
override, else the pipeline default) are still emitted, but flagged with a
`low_confidence = true` attribute so downstream subscribers can decide
whether to surface them.

## Output envelope

Each re-injected message carries a JSON payload so subscribers can consume
results without depending on `rustgate-inference`:

```json
{
  "model": "vehicle-classifier",
  "label": "tracked-vehicle",
  "confidence": 0.82,
  "attributes": { "low_confidence": false }
}
```

The message's source identity and destination are copied verbatim from the
entity's originating message; only the payload and `source_protocol` are
rewritten.

## Limitations (current)

- **Mock backend only.** The shipped backend is deterministic and does not
  load model files. Real model execution (ONNX via `ort`) is deferred to a
  future `inference-onnx` feature.
- **No live model hot-reload from disk yet.** The `Pipeline` supports
  in-process `reload`, and `reload-interval-secs` is parsed, but the
  server does not yet run a directory-watch reload task — the model set is
  built once at startup.

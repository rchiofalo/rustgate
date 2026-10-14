# rustgate-inference

Edge ML inference pipeline for rustgate. Closes #858.

This crate provides the model-execution surface for attaching
machine-learning–derived attributes (classification, anomaly score,
predicted intent) to entities flowing through the rustgate router. It
keeps the router vendor- and framework-agnostic; only this crate
knows about model formats and tensor shapes.

## What ships in MVP

- `InferenceModel` async trait — extension point for model backends.
- `Pipeline` — hot-reloadable, ordered list of registered models with
  per-model and pipeline-wide confidence-threshold support.
- `MockInferenceModel` (feature `inference-mock`) — deterministic
  in-memory backend used in tests and local development.
- `wiring::router_callback` — `OnRouted` callback that decodes
  routed messages via the supplied `EntityCodecRegistry`, runs every
  registered model, and re-injects annotated `RoutableMessage`s with
  `metadata.source_protocol = "inference"`.
- Provenance loop avoidance — annotated messages are tagged so a
  downstream invocation of the same callback skips them.

## Deferred to follow-up

- ONNX runtime backend (`inference-onnx` feature) — `ort` integration
  with input-tensor projection from `Entity` attributes and output
  decoding into `InferenceResult`. The trait surface in this MVP is
  designed so the ONNX backend slots in without API churn.
- GPU / TensorRT backends.
- On-device training and federated learning.
- Aggregation across results (e.g. majority vote, per-class score
  fusion). The current pipeline returns every model's result; the
  consumer aggregates as it sees fit.

## Configuration

```toml
[inference]
models-dir = "/var/lib/rustgate/models"
reload-interval-secs = 60

[[inference.pipeline]]
model-name = "vehicle-classifier"
model-path = "vehicle_v3.onnx"
target = "classify"
confidence-threshold = 0.65

[[inference.pipeline]]
model-name = "anomaly-detector"
model-path = "anomaly.onnx"
target = "anomaly"
```

`InferenceConfig::validate` rejects duplicate model names, out-of-range
thresholds, and an empty `models-dir`.

## License

AGPL-3.0-only, same as the rest of the workspace. See the workspace `LICENSE` and `NOTICE`.

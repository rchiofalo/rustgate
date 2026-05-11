// Copyright © 2026 Roberto Chiofalo.

// Gated at the Cargo manifest level via `required-features = ["v2"]`
// on the matching `[[bench]]` block — when the `v2` feature is off,
// Cargo skips this target entirely. Source-level cfg gating would
// also work but would conflict with criterion's `main` symbol
// expectations on a default-feature build, since cfg-ing the file
// out empties it and `[[bench]] harness = false` then complains about
// the missing main function.
#![allow(unused_results)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustgate_federation::provenance::FederationMetadata;
use rustgate_federation::v2::convert::xml_to_federated_event;

const POSITION_COT: &[u8] = br#"<event uid="ALPHA-1" type="a-f-G-U-C" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z" how="m-g"><point lat="38.8977" lon="-77.0365" hae="0.0" ce="9999999" le="9999999"/><detail><__group name="Cyan" role="Team Member"/><contact callsign="ALPHA-1"/><status battery="85"/><track course="270.5" speed="1.2"/></detail></event>"#;

fn bench_xml_to_federated_event(c: &mut Criterion) {
    let metadata = FederationMetadata::default();

    let mut group = c.benchmark_group("federation_convert");
    group.throughput(Throughput::Bytes(POSITION_COT.len() as u64));

    group.bench_function("xml_to_event", |b| {
        b.iter(|| black_box(xml_to_federated_event(POSITION_COT, &metadata)))
    });

    group.finish();
}

criterion_group!(benches, bench_xml_to_federated_event);
criterion_main!(benches);

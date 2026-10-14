// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_results)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const POSITION_COT: &[u8] = br#"<event uid="ALPHA-1" type="a-f-G-U-C" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z" how="m-g"><point lat="38.8977" lon="-77.0365" hae="0.0" ce="9999999" le="9999999"/><detail><__group name="Cyan" role="Team Member"/><contact callsign="ALPHA-1"/><status battery="85"/><track course="270.5" speed="1.2"/></detail></event>"#;

fn bench_cot_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("cot_parser");
    group.throughput(Throughput::Bytes(POSITION_COT.len() as u64));

    group.bench_function("parse_position", |b| {
        b.iter(|| black_box(rustgate_cot::parse(POSITION_COT)))
    });

    group.finish();
}

criterion_group!(benches, bench_cot_parse);
criterion_main!(benches);

// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::{LengthPrefixedCodec, XmlStreamCodec};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

fn bench_xml_stream_decode(c: &mut Criterion) {
    let xml = b"<event uid=\"ALPHA-1\" type=\"a-f-G-U-C\" time=\"2024-01-01T00:00:00Z\" start=\"2024-01-01T00:00:00Z\" stale=\"2024-01-01T00:05:00Z\" how=\"m-g\"><point lat=\"38.8977\" lon=\"-77.0365\" hae=\"0.0\" ce=\"9999999\" le=\"9999999\"/><detail><__group name=\"Cyan\" role=\"Team Member\"/><contact callsign=\"ALPHA-1\"/><status battery=\"85\"/></detail></event>";

    let mut group = c.benchmark_group("xml_stream_codec");
    group.throughput(Throughput::Bytes(xml.len() as u64));

    group.bench_function("decode_position", |b| {
        b.iter(|| {
            let mut codec = XmlStreamCodec::new();
            let mut buf = BytesMut::from(&xml[..]);
            black_box(codec.decode(&mut buf))
        })
    });

    group.finish();
}

fn bench_length_prefixed_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("length_prefixed_codec");

    for size in [64, 512, 4096] {
        let payload = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("round_trip_{size}B"), |b| {
            b.iter(|| {
                let mut codec = LengthPrefixedCodec::new(HeaderSize::Four);
                let mut encoded = BytesMut::new();
                codec
                    .encode(BytesMut::from(payload.as_slice()), &mut encoded)
                    .expect("encode");
                black_box(codec.decode(&mut encoded))
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_xml_stream_decode,
    bench_length_prefixed_round_trip
);
criterion_main!(benches);

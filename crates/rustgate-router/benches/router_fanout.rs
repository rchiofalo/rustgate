// Copyright © 2026 Roberto Chiofalo.

//! Criterion benchmark for the router fanout hot path.
//!
//! Exercises [`Router::route_for_egress`] across the three primary
//! destination shapes so future PRs that touch the router can detect
//! regressions in fanout latency / throughput:
//!
//! 1. `Destination::Group(g)` parameterised across 1, 10, 100, 1000
//!    subscribers — the canonical group-fanout cost curve.
//! 2. `Destination::Broadcast` — fans out to every registered session.
//! 3. `Destination::Direct(target)` — single-recipient lookup; the
//!    floor on routing cost when no fanout is involved.
//!
//! Each benchmark routes through [`Router::route_for_egress`] (not
//! [`Router::route`]) because the post-Send-PEP form is what external
//! sinks (NATS bridge, federation, HTTP webhooks, MQTT) consume — a
//! regression in this method's allocation profile or critical-section
//! length would manifest as cross-cutting egress latency.
//!
//! No baseline numbers are committed — operators run criterion locally
//! for tuning. The benchmark is intentionally not gated in CI by an
//! absolute-threshold guard; criterion's per-run noise floor on shared
//! CI runners is too high to support a sub-microsecond latency budget
//! without false positives.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::BTreeSet;
use std::hint::black_box;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, RoutedMessage, Router, SessionHandle,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Subscriber-count sweep matching the issue (#785) parameter set.
const SUBSCRIBER_COUNTS: &[usize] = &[1, 10, 100, 1000];

/// Payload size used across all benches. Chosen to mirror a typical CoT
/// position event after XML escape — not so small that the allocation
/// path is amortised away, not so large that the bench measures
/// `Bytes::clone` more than dispatch.
const PAYLOAD_BYTES: usize = 256;

/// Per-channel capacity for the per-session mpsc sinks. Wide enough that
/// the criterion warm-up and measurement phases never trip the
/// `SessionHandle` circuit breaker on a full channel — the drainer task
/// reads concurrently, but a transient stall on the bench thread must
/// not surface as a `try_send` failure that skews the routing
/// statistics. Defaults are deliberately larger than
/// [`PRIORITY_CHANNEL_CAPACITY`] / [`NORMAL_CHANNEL_CAPACITY`] so the
/// drainer always has headroom.
const BENCH_CHANNEL_CAPACITY: usize = 4 * (PRIORITY_CHANNEL_CAPACITY + NORMAL_CHANNEL_CAPACITY);

fn build_runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build current-thread tokio runtime for bench")
}

fn make_identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
    Arc::new(
        Identity::new(
            cn.to_string(),
            format!("{cn}-fp"),
            groups
                .iter()
                .map(|g| (*g).to_string())
                .collect::<BTreeSet<_>>(),
        )
        .expect("valid bench identity"),
    )
}

/// Spawn a drainer for a single session's channel pair so messages
/// routed during the benchmark do not back up and trip the
/// per-session circuit breaker. The drainer exits when both channels
/// close, which happens when the `SessionHandle` is dropped at
/// teardown.
fn spawn_drainer(
    rt: &Runtime,
    mut prx: mpsc::Receiver<RoutedMessage>,
    mut nrx: mpsc::Receiver<RoutedMessage>,
) {
    rt.spawn(async move {
        loop {
            tokio::select! {
                msg = prx.recv() => {
                    if msg.is_none() {
                        break;
                    }
                }
                msg = nrx.recv() => {
                    if msg.is_none() {
                        break;
                    }
                }
            }
        }
    });
}

/// Build a router with `subscribers` sessions all joined to
/// `"alpha"` plus a sender registered separately. Returns the router
/// and the sender identity for message construction.
fn setup_group(rt: &Runtime, subscribers: usize) -> (Arc<Router>, Arc<Identity>) {
    let router = Arc::new(Router::new());
    let sender = make_identity("sender", &["alpha"]);

    rt.block_on(async {
        // Sender first so it counts toward the population (its own
        // session would receive the broadcast but is excluded from
        // group sends as the source).
        let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        spawn_drainer(rt, prx, nrx);
        router
            .register(SessionHandle::new(sender.clone(), ptx, ntx))
            .await;

        for i in 0..subscribers {
            let cn = format!("sub-{i}");
            let identity = make_identity(&cn, &["alpha"]);
            let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
            let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
            spawn_drainer(rt, prx, nrx);
            router
                .register(SessionHandle::new(identity, ptx, ntx))
                .await;
        }
    });

    (router, sender)
}

/// Build a router with `subscribers` sessions each in their own
/// distinct group so a [`Destination::Broadcast`] visits every group
/// the engine tracks. Returns the router and a sender identity that
/// itself sits in a dedicated `"sender"` group so it is excluded from
/// the broadcast (matching the documented `Destination::Broadcast`
/// "all sessions except the sender" semantics).
fn setup_broadcast(rt: &Runtime, subscribers: usize) -> (Arc<Router>, Arc<Identity>) {
    let router = Arc::new(Router::new());
    let sender = make_identity("sender", &["sender"]);

    rt.block_on(async {
        let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        spawn_drainer(rt, prx, nrx);
        router
            .register(SessionHandle::new(sender.clone(), ptx, ntx))
            .await;

        for i in 0..subscribers {
            let cn = format!("sub-{i}");
            let group = format!("g-{i}");
            let identity = make_identity(&cn, &[group.as_str()]);
            let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
            let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
            spawn_drainer(rt, prx, nrx);
            router
                .register(SessionHandle::new(identity, ptx, ntx))
                .await;
        }
    });

    (router, sender)
}

/// Build a router with a sender + a single direct recipient. The
/// returned recipient identity is what the bench wraps in
/// `Destination::Direct(target)` per iteration.
fn setup_direct(rt: &Runtime) -> (Arc<Router>, Arc<Identity>, Arc<Identity>) {
    let router = Arc::new(Router::new());
    let sender = make_identity("sender", &["alpha"]);
    let target = make_identity("target", &["alpha"]);

    rt.block_on(async {
        let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        spawn_drainer(rt, prx, nrx);
        router
            .register(SessionHandle::new(sender.clone(), ptx, ntx))
            .await;

        let (ptx, prx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        let (ntx, nrx) = mpsc::channel(BENCH_CHANNEL_CAPACITY);
        spawn_drainer(rt, prx, nrx);
        router
            .register(SessionHandle::new(target.clone(), ptx, ntx))
            .await;
    });

    (router, sender, target)
}

/// Construct a `Chat` message with a fixed-size payload. `Chat` rides
/// the normal-priority channel, which has more headroom in the bench
/// (the priority channel is reserved for `Position` / `Alert`). This
/// keeps the drainer task's wakeup pattern uniform across all three
/// benchmark scenarios.
fn make_chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from(vec![0u8; PAYLOAD_BYTES]),
        metadata: Metadata::new(SystemTime::now(), "bench".to_string(), MessageType::Chat),
        entity: None,
    }
}

fn bench_route_group(c: &mut Criterion) {
    let rt = build_runtime();
    let mut group = c.benchmark_group("router_fanout_group");
    group.throughput(Throughput::Elements(1));

    for &subscribers in SUBSCRIBER_COUNTS {
        let (router, sender) = setup_group(&rt, subscribers);

        group.bench_with_input(
            BenchmarkId::from_parameter(subscribers),
            &subscribers,
            |b, _| {
                b.to_async(&rt).iter(|| {
                    let router = Arc::clone(&router);
                    let sender = Arc::clone(&sender);
                    async move {
                        let msg = make_chat(&sender, Destination::Group("alpha".into()));
                        black_box(router.route_for_egress(msg).await)
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_route_broadcast(c: &mut Criterion) {
    let rt = build_runtime();
    let mut group = c.benchmark_group("router_fanout_broadcast");
    group.throughput(Throughput::Elements(1));

    for &subscribers in SUBSCRIBER_COUNTS {
        let (router, sender) = setup_broadcast(&rt, subscribers);

        group.bench_with_input(
            BenchmarkId::from_parameter(subscribers),
            &subscribers,
            |b, _| {
                b.to_async(&rt).iter(|| {
                    let router = Arc::clone(&router);
                    let sender = Arc::clone(&sender);
                    async move {
                        let msg = make_chat(&sender, Destination::Broadcast);
                        black_box(router.route_for_egress(msg).await)
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_route_direct(c: &mut Criterion) {
    let rt = build_runtime();
    let mut group = c.benchmark_group("router_fanout_direct");
    group.throughput(Throughput::Elements(1));

    let (router, sender, target) = setup_direct(&rt);

    group.bench_function("single_recipient", |b| {
        b.to_async(&rt).iter(|| {
            let router = Arc::clone(&router);
            let sender = Arc::clone(&sender);
            let target = Arc::clone(&target);
            async move {
                let msg = make_chat(&sender, Destination::Direct((*target).clone()));
                black_box(router.route_for_egress(msg).await)
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_route_direct,
    bench_route_group,
    bench_route_broadcast,
);
criterion_main!(benches);

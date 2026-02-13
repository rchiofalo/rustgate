# rustgate

Rust-native secure message router with pluggable protocol support. Built for tactical edge deployment.

## Why

Existing tactical messaging servers are Java monoliths requiring 8GB+ RAM, multiple JVM processes, and complex module stacks. They work in garrison but fall apart at the edge where resources are constrained and reliability matters most. Federation-only alternatives exist but don't handle client connections.

rustgate is a lightweight alternative that handles mTLS client connections, routes messages by group membership derived from client certificates, and exposes a pluggable protocol interface for future adapters. Pure Rust, single binary, minimal footprint.

## Status

Early development. Building core routing and transport.

## Building

```
cargo build
```

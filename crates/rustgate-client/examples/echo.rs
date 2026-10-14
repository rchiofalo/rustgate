// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Reference echo client.
//!
//! Connects to a rustgate server, subscribes to inbound traffic, and echoes
//! every received frame back to the server. Run with:
//!
//! ```text
//! cargo run -p rustgate-client --example echo -- \
//!     --addr 127.0.0.1:8089 \
//!     --cert client.crt --key client.key --ca ca.crt
//! ```

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use rustgate_client::{Client, ClientConfig, Codec, ReconnectPolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut addr = "127.0.0.1:8089".to_string();
    let mut cert: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut ca: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--addr" => addr = args.next().unwrap_or_default(),
            "--cert" => cert = args.next().map(PathBuf::from),
            "--key" => key = args.next().map(PathBuf::from),
            "--ca" => ca = args.next().map(PathBuf::from),
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }

    let cert = cert.ok_or_else(|| anyhow::anyhow!("--cert required"))?;
    let key = key.ok_or_else(|| anyhow::anyhow!("--key required"))?;
    let ca = ca.ok_or_else(|| anyhow::anyhow!("--ca required"))?;

    let config = ClientConfig::builder()
        .server_addr(addr)
        .mtls_pem_files(cert, key, ca)
        .codec(Codec::LengthPrefixed4)
        .connect_timeout(Duration::from_secs(10))
        .reconnect(ReconnectPolicy::default())
        .build()?;

    let client = Client::connect(config).await?;
    println!("connected; echoing inbound frames");
    let mut inbound = client.subscribe();

    while let Some(msg) = inbound.next().await {
        let msg = msg?;
        println!("rx {} bytes; echoing back", msg.payload.len());
        client.send(msg.payload).await?;
    }

    client.disconnect().await;
    Ok(())
}

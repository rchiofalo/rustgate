# rustgate-client

Reference client library for connecting to a rustgate server.

`rustgate-client` wraps the same `rustgate-transport` codecs the server uses,
so client code does not have to re-implement TLS bring-up, mTLS configuration,
framing, or reconnection bookkeeping.

## API

- `ClientConfig::builder()` — fluent builder for connection parameters.
  - `.server_addr(host:port)` — required
  - `.mtls_pem_files(cert, key, ca)` or `.mtls_pem_bytes(...)` — required unless `.plaintext(true)`
  - `.codec(Codec::LengthPrefixed4)` — wire framing (defaults to 4-byte length prefix)
  - `.connect_timeout(Duration)` — bound the initial dial
  - `.reconnect(ReconnectPolicy::default())` — opt in to exponential-backoff reconnect
- `Client::connect(config) -> Result<Client>` — TLS handshake, returns connected client
- `client.send(payload) -> Result<()>`
- `client.subscribe() -> impl Stream<Item = Result<Message>>`
- `client.disconnect()` — graceful shutdown with TLS close_notify

## Example

```rust,no_run
use bytes::Bytes;
use futures::StreamExt;
use rustgate_client::{Client, ClientConfig, Codec};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ClientConfig::builder()
        .server_addr("127.0.0.1:8089")
        .mtls_pem_files("client.crt", "client.key", "ca.crt")
        .codec(Codec::LengthPrefixed4)
        .build()?;

    let client = Client::connect(config).await?;
    let mut inbound = client.subscribe();

    client.send(Bytes::from_static(b"hello")).await?;

    if let Some(msg) = inbound.next().await {
        let msg = msg?;
        println!("got {} bytes", msg.payload.len());
    }

    client.disconnect().await;
    Ok(())
}
```

A runnable echo client lives in `examples/echo.rs`.

## Wire-protocol note

The on-wire protocol is opaque framed bytes. The rustgate server determines
routing from the sender's certificate OUs, not from any per-message tag.
Sent payloads go wherever the server's routing rules dictate, and subscribers
receive every inbound frame on the connection.

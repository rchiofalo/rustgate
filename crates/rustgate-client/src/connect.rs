// Copyright © 2026 Roberto Chiofalo.

//! TLS / plaintext dialing helpers.

use std::sync::Arc;

use rustgate_core::net::configure_tactical_socket;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::{ClientConfig, ClientError, Result, TlsMaterial};

/// Internal connection options exposed for tests / advanced callers.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectOptions {
    _private: (),
}

/// Erased async byte stream — either a TLS-wrapped TCP socket or a raw TCP
/// socket when `plaintext` is enabled.
pub(crate) enum Stream {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn dial(config: &ClientConfig) -> Result<Stream> {
    let fut = dial_inner(config);
    if let Some(timeout) = config.connect_timeout {
        match tokio::time::timeout(timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(ClientError::ConnectTimeout(timeout)),
        }
    } else {
        fut.await
    }
}

async fn dial_inner(config: &ClientConfig) -> Result<Stream> {
    let tcp = TcpStream::connect(&config.server_addr).await?;
    // Match listener-side tactical-socket defaults on the dial side —
    // keepalive + `TCP_NODELAY` — so a client emitting single CoT events
    // is not penalized by the peer's delayed-ACK timer.
    configure_tactical_socket(&tcp);
    if config.plaintext {
        return Ok(Stream::Plain(tcp));
    }
    let tls_material = config
        .tls
        .as_ref()
        .ok_or(ClientError::MissingField("tls"))?;
    let tls_config = build_tls_config(tls_material)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name: ServerName<'static> = ServerName::try_from(config.server_name.clone())
        .map_err(|e| ClientError::Tls(format!("invalid server name: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    Ok(Stream::Tls(Box::new(tls)))
}

fn build_tls_config(material: &TlsMaterial) -> Result<rustls::ClientConfig> {
    let (cert_pem, key_pem, ca_pem) = match material {
        TlsMaterial::PemFiles { cert, key, ca } => {
            let c = std::fs::read(cert)?;
            let k = zeroize::Zeroizing::new(std::fs::read(key)?);
            let a = std::fs::read(ca)?;
            (c, k, a)
        }
        TlsMaterial::PemBytes { cert, key, ca } => (
            cert.clone(),
            zeroize::Zeroizing::new(key.to_vec()),
            ca.clone(),
        ),
    };

    // Shared PEM helpers (`rustgate_core::pem`) give us uniform error
    // mapping — every parse failure carries `kind` + `reason` fields via
    // `ConfigError::PemParse`, which we project into `ClientError::CertParse`.
    let certs = rustgate_core::pem::parse_certs(&cert_pem)
        .map_err(|e| ClientError::CertParse(format!("client cert: {e}")))?;
    let key = rustgate_core::pem::parse_key(&key_pem)
        .map_err(|e| ClientError::CertParse(format!("client key: {e}")))?;
    let roots = rustgate_core::pem::parse_ca_store(&ca_pem)
        .map_err(|e| ClientError::CertParse(format!("ca cert: {e}")))?;

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| ClientError::Tls(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::io::Write as _;

    use rustgate_test_utils::certs::TestCa;
    use tempfile::NamedTempFile;
    use zeroize::Zeroizing;

    use super::*;

    /// Issue a fresh CA + client cert fixture. Each test gets its own CA
    /// so there is no hidden coupling through a shared fixture.
    fn fixture() -> (TestCa, rustgate_test_utils::certs::TestCert) {
        let ca = TestCa::new("rustgate-client-connect-tests");
        let client = ca.issue_client_cert("test-client", &["group-a"]);
        (ca, client)
    }

    fn valid_pem_bytes_material() -> TlsMaterial {
        let (ca, client) = fixture();
        TlsMaterial::PemBytes {
            cert: client.cert_pem.into_bytes(),
            key: Zeroizing::new(client.key_pem.into_bytes()),
            ca: ca.cert_pem.into_bytes(),
        }
    }

    #[test]
    fn build_tls_config_accepts_valid_pem_bytes() {
        let material = valid_pem_bytes_material();
        let _ = build_tls_config(&material).expect("valid PEM material must build a ClientConfig");
    }

    #[test]
    fn build_tls_config_rejects_malformed_cert_pem() {
        // Preserve a legitimate key + CA so the first parse failure must
        // be the cert one (tight assertion on the error message).
        let (ca, client) = fixture();
        let material = TlsMaterial::PemBytes {
            cert: b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n".to_vec(),
            key: Zeroizing::new(client.key_pem.into_bytes()),
            ca: ca.cert_pem.into_bytes(),
        };
        match build_tls_config(&material) {
            Err(ClientError::CertParse(msg)) => {
                assert!(
                    msg.starts_with("client cert:"),
                    "error must identify the cert parse stage; got {msg:?}",
                );
            }
            other => panic!("expected CertParse(client cert: ...), got {other:?}"),
        }
    }

    #[test]
    fn build_tls_config_rejects_malformed_key_pem() {
        let (ca, client) = fixture();
        let material = TlsMaterial::PemBytes {
            cert: client.cert_pem.into_bytes(),
            // A cert-shaped PEM is not a private key — the key parser
            // finds no supported tag and fails with a parse error.
            key: Zeroizing::new(ca.cert_pem.clone().into_bytes()),
            ca: ca.cert_pem.into_bytes(),
        };
        match build_tls_config(&material) {
            Err(ClientError::CertParse(msg)) => {
                assert!(
                    msg.starts_with("client key:"),
                    "error must identify the key parse stage; got {msg:?}",
                );
            }
            other => panic!("expected CertParse(client key: ...), got {other:?}"),
        }
    }

    #[test]
    fn build_tls_config_rejects_empty_ca_bundle() {
        // An all-whitespace CA bundle has zero CERTIFICATE blocks —
        // parse_ca_store returns EmptyPem, which must surface as
        // `ca cert:` in the client-facing error to keep diagnostics
        // actionable.
        let (_, client) = fixture();
        let material = TlsMaterial::PemBytes {
            cert: client.cert_pem.into_bytes(),
            key: Zeroizing::new(client.key_pem.into_bytes()),
            ca: b"   \n\n".to_vec(),
        };
        match build_tls_config(&material) {
            Err(ClientError::CertParse(msg)) => {
                assert!(
                    msg.starts_with("ca cert:"),
                    "error must identify the CA parse stage; got {msg:?}",
                );
            }
            other => panic!("expected CertParse(ca cert: ...), got {other:?}"),
        }
    }

    #[test]
    fn build_tls_config_reads_pem_from_files_on_disk() {
        let (ca, client) = fixture();
        let mut cert_f = NamedTempFile::new().unwrap();
        let mut key_f = NamedTempFile::new().unwrap();
        let mut ca_f = NamedTempFile::new().unwrap();
        cert_f.write_all(client.cert_pem.as_bytes()).unwrap();
        key_f.write_all(client.key_pem.as_bytes()).unwrap();
        ca_f.write_all(ca.cert_pem.as_bytes()).unwrap();

        let material = TlsMaterial::PemFiles {
            cert: cert_f.path().to_path_buf(),
            key: key_f.path().to_path_buf(),
            ca: ca_f.path().to_path_buf(),
        };
        let _ = build_tls_config(&material).expect("PEM files on disk must produce a valid config");
    }

    #[test]
    fn build_tls_config_missing_cert_file_returns_io_error() {
        // Nonexistent path triggers `std::fs::read` failure, which the
        // function propagates via `ClientError::Io` (through `?`).
        let (ca, client) = fixture();
        let mut key_f = NamedTempFile::new().unwrap();
        let mut ca_f = NamedTempFile::new().unwrap();
        key_f.write_all(client.key_pem.as_bytes()).unwrap();
        ca_f.write_all(ca.cert_pem.as_bytes()).unwrap();

        let material = TlsMaterial::PemFiles {
            cert: std::path::PathBuf::from("/definitely/does/not/exist/rustgate-client-tests.pem"),
            key: key_f.path().to_path_buf(),
            ca: ca_f.path().to_path_buf(),
        };
        match build_tls_config(&material) {
            Err(ClientError::Io(io_err)) => {
                assert_eq!(
                    io_err.kind(),
                    std::io::ErrorKind::NotFound,
                    "missing cert file must surface NotFound, got {io_err:?}",
                );
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn connect_options_default_is_copy_and_debug() {
        // The type is currently a placeholder for future per-dial
        // overrides; pin Default + Copy + Debug so accidental removal
        // of a derive is caught here.
        let opts = ConnectOptions::default();
        let _copy = opts;
        let rendered = format!("{opts:?}");
        assert!(
            rendered.contains("ConnectOptions"),
            "Debug impl should emit the type name; got {rendered}"
        );
    }
}

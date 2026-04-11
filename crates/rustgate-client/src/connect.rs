//! TLS / plaintext dialing helpers.

use std::sync::Arc;

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
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

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ClientError::CertParse(format!("client cert: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| ClientError::CertParse(format!("client key: {e}")))?;

    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(&ca_pem) {
        let ca = ca.map_err(|e| ClientError::CertParse(format!("ca cert: {e}")))?;
        roots
            .add(ca)
            .map_err(|e| ClientError::CertParse(format!("add ca: {e}")))?;
    }

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| ClientError::Tls(e.to_string()))
}

//! TLS configuration for mTLS server.

use std::io::BufReader;
use std::sync::Arc;

use rustgate_core::error::{Result, RustgateError};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

#[derive(Debug)]
pub struct TlsConfig {
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca_store: Arc<RootCertStore>,
}

impl TlsConfig {
    pub fn from_pem(
        server_cert_pem: &str,
        server_key_pem: &str,
        client_ca_pem: &str,
    ) -> Result<Self> {
        let server_certs = Self::parse_certs(server_cert_pem)?;
        let server_key = Self::parse_key(server_key_pem)?;
        let client_ca_store = Self::parse_ca_store(client_ca_pem)?;

        Ok(Self {
            server_certs,
            server_key,
            client_ca_store: Arc::new(client_ca_store),
        })
    }

    pub fn build_server_config(&self) -> Result<rustls::ServerConfig> {
        let client_verifier = WebPkiClientVerifier::builder(self.client_ca_store.clone())
            .build()
            .map_err(|e| RustgateError::Config(format!("failed to build client verifier: {e}")))?;

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(self.server_certs.clone(), self.server_key.clone_key())
            .map_err(|e| RustgateError::Config(format!("invalid server certificate: {e}")))?;

        Ok(config)
    }

    fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
        let mut reader = BufReader::new(pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RustgateError::Config(format!("failed to parse certificates: {e}")))?;

        if certs.is_empty() {
            return Err(RustgateError::Config(
                "no certificates found in PEM".to_string(),
            ));
        }

        Ok(certs)
    }

    fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
        let mut reader = BufReader::new(pem.as_bytes());

        rustls_pemfile::private_key(&mut reader)
            .map_err(|e| RustgateError::Config(format!("failed to parse private key: {e}")))?
            .ok_or_else(|| RustgateError::Config("no private key found in PEM".to_string()))
    }

    fn parse_ca_store(pem: &str) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();
        let mut reader = BufReader::new(pem.as_bytes());

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| RustgateError::Config(format!("failed to parse CA certificates: {e}")))?;

        if certs.is_empty() {
            return Err(RustgateError::Config(
                "no CA certificates found in PEM".to_string(),
            ));
        }

        for cert in certs {
            store
                .add(cert)
                .map_err(|e| RustgateError::Config(format!("failed to add CA certificate: {e}")))?;
        }

        Ok(store)
    }
}

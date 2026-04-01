//! Outbound mTLS connector for federation peer connections.
//!
//! Establishes TLS client connections to remote federation peers,
//! extracting the server's certificate identity for peer identification.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustgate_core::identity::Identity;
use rustgate_transport::extract_identity;
use rustgate_transport::pem::{parse_ca_store, parse_certs, parse_key};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

/// TCP keepalive idle time before first probe.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Interval between TCP keepalive probes after the idle period.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Outbound mTLS connector for establishing federation peer connections.
///
/// Manages the client-side TLS configuration and provides a `connect` method
/// that establishes an authenticated connection to a remote federation peer.
#[derive(Clone)]
pub struct PeerConnector {
    client_config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for PeerConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnector")
            .field("client_config", &"<ClientConfig>")
            .finish()
    }
}

impl PeerConnector {
    /// Create a new peer connector from PEM-encoded certificate files.
    ///
    /// # Arguments
    /// * `cert` - Path to the client certificate PEM file
    /// * `key` - Path to the client private key PEM file
    /// * `ca` - Path to the CA certificate PEM file for verifying server certs
    /// * `skip_hostname_verify` - If true, skip TLS hostname verification
    ///   (useful when federation peers use certificate CNs that don't match their hostname)
    pub fn new(
        cert: &Path,
        key: &Path,
        ca: &Path,
        skip_hostname_verify: bool,
    ) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read_to_string(cert)
            .with_context(|| format!("reading federation cert from {}", cert.display()))?;
        let key_pem = std::fs::read_to_string(key)
            .with_context(|| format!("reading federation key from {}", key.display()))?;
        let ca_pem = std::fs::read_to_string(ca)
            .with_context(|| format!("reading federation CA from {}", ca.display()))?;

        Self::from_pem(&cert_pem, &key_pem, &ca_pem, skip_hostname_verify)
    }

    /// Create a new peer connector from PEM strings.
    ///
    /// This is the primary constructor used by tests and when certificates
    /// are loaded from configuration rather than files.
    pub fn from_pem(
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
        skip_hostname_verify: bool,
    ) -> anyhow::Result<Self> {
        let certs = parse_certs(cert_pem).context("loading federation client certificate")?;
        let key = parse_key(key_pem).context("loading federation client key")?;
        let root_store = parse_ca_store(ca_pem).context("loading federation CA store")?;

        let config = if skip_hostname_verify {
            build_config_no_hostname_verify(root_store, certs, key)?
        } else {
            build_config_with_hostname_verify(root_store, certs, key)?
        };

        Ok(Self {
            client_config: Arc::new(config),
        })
    }

    /// Connect to a remote federation peer over mTLS.
    ///
    /// Returns the TLS stream and the peer's extracted identity from their
    /// server certificate. TCP keepalive is configured on the connection.
    ///
    /// # Arguments
    /// * `addr` - The remote peer's socket address
    /// * `server_name` - The TLS server name to use for SNI/verification
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> anyhow::Result<(tokio_rustls::client::TlsStream<TcpStream>, Arc<Identity>)> {
        debug!(peer_addr = %addr, server_name = %server_name, "connecting to federation peer");

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| anyhow::anyhow!("TCP connect to {addr}: {e}"))?;

        configure_tcp_keepalive(&tcp);

        let sni: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid server name: {server_name}"))?;

        let connector = TlsConnector::from(Arc::clone(&self.client_config));
        let tls_stream = connector
            .connect(sni, tcp)
            .await
            .map_err(|e| anyhow::anyhow!("TLS handshake with {addr}: {e}"))?;

        debug!(peer_addr = %addr, "TLS handshake completed");

        let identity = extract_server_identity(&tls_stream)
            .with_context(|| format!("extracting identity from peer at {addr}"))?;

        debug!(
            peer_addr = %addr,
            cn = %identity.cn,
            groups = ?identity.groups,
            "federation peer authenticated"
        );

        Ok((tls_stream, Arc::new(identity)))
    }
}

/// Extract the server's identity from a client-side TLS connection.
///
/// Retrieves the peer certificate from the TLS session and extracts
/// the CN, groups (from OU fields), and fingerprint.
fn extract_server_identity(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> anyhow::Result<Identity> {
    let (_, client_conn) = tls_stream.get_ref();

    let certs = client_conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no server certificate presented"))?;

    let server_cert = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty server certificate chain"))?;

    extract_identity(server_cert).map_err(|e| anyhow::anyhow!("identity extraction failed: {e}"))
}

/// Enable TCP keepalive on a socket to detect dead connections.
fn configure_tcp_keepalive(stream: &TcpStream) {
    let sock_ref = socket2::SockRef::from(stream);

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);

    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        warn!(error = %e, "failed to set TCP keepalive on federation connection");
    }
}

/// Build a standard ClientConfig with hostname verification enabled.
fn build_config_with_hostname_verify(
    root_store: RootCertStore,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<rustls::ClientConfig> {
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid client certificate: {e}"))
}

/// Build a ClientConfig that skips hostname verification but still
/// verifies the server certificate against the CA trust chain.
///
/// This is needed for federation peers whose certificate CN/SAN
/// doesn't match the hostname we're connecting to (common in
/// TAK Server federation where peers use descriptive CNs).
fn build_config_no_hostname_verify(
    root_store: RootCertStore,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<rustls::ClientConfig> {
    let verifier = NoHostnameVerifier::new(root_store);

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid client certificate: {e}"))?;

    Ok(config)
}

/// Custom TLS server certificate verifier that validates the certificate
/// chain against a trusted CA store but skips hostname/SNI verification.
///
/// The standard WebPKI verifier requires the server certificate's SAN
/// entries to match the SNI name. For federation, peer certificates
/// typically have a descriptive CN (like "federation-server-prod") that
/// doesn't match the IP/hostname we connect to.
#[derive(Debug)]
struct NoHostnameVerifier {
    roots: Arc<RootCertStore>,
}

impl NoHostnameVerifier {
    fn new(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoHostnameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Delegate to the standard WebPKI verifier for full chain validation.
        // The verifier checks both the certificate chain AND hostname match.
        // We catch only the hostname mismatch error and allow it through,
        // while all other errors (bad chain, expired, untrusted CA, etc.)
        // are propagated normally.
        let webpki_verifier =
            rustls::client::WebPkiServerVerifier::builder(Arc::clone(&self.roots))
                .build()
                .map_err(|e| rustls::Error::General(format!("verifier build error: {e}")))?;

        match webpki_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            // In rustls 0.23+, WebPkiServerVerifier returns the context variant
            // with details about which names are valid. Match both for
            // forward-compatibility with future rustls versions.
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName))
            | Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext { .. },
            )) => {
                // Certificate chain is valid but hostname doesn't match.
                // This is expected for federation — we trust the CA, not the hostname.
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Err(other) => Err(other),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("no crypto provider installed".to_string()))?;
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("no crypto provider installed".to_string()))?;
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use rustgate_test_utils::certs::TestCa;
    use rustgate_transport::{TlsConfig, TlsListener};

    use super::*;

    /// Helper to start a TLS listener for testing the connector.
    async fn start_test_server(ca: &TestCa) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
                .expect("tls config");
        let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handle = tokio::spawn(async move {
            // Accept one connection and hold it until the task is cancelled
            let _session = listener.accept().await.expect("accept");
            // Keep the session alive by sleeping
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn connect_with_hostname_verify() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("test-connector", &["Alpha"]);
        let (addr, server_handle) = start_test_server(&ca).await;

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create connector");

        let (_, identity) = connector.connect(addr, "localhost").await.expect("connect");

        assert_eq!(identity.cn, "localhost");
        server_handle.abort();
    }

    #[tokio::test]
    async fn connect_extracts_server_identity() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha", "Bravo"]);
        let (addr, server_handle) = start_test_server(&ca).await;

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create connector");

        let (_, identity) = connector.connect(addr, "localhost").await.expect("connect");

        // Server cert CN is "localhost"
        assert_eq!(identity.cn, "localhost");
        // Server cert has no OU groups
        assert!(identity.groups.is_empty());
        // Fingerprint should be set
        assert!(!identity.fingerprint.is_empty());

        server_handle.abort();
    }

    #[tokio::test]
    async fn connect_with_skip_hostname_verify() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);
        let (addr, server_handle) = start_test_server(&ca).await;

        // Use skip_hostname_verify to connect with a non-matching server name
        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            true,
        )
        .expect("create connector");

        // Connect with a name that doesn't match the server cert SAN
        let (_, identity) = connector
            .connect(addr, "some-federation-peer")
            .await
            .expect("connect with skip hostname verify");

        assert_eq!(identity.cn, "localhost");
        server_handle.abort();
    }

    #[tokio::test]
    async fn connect_hostname_mismatch_fails_without_skip() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);
        let (addr, server_handle) = start_test_server(&ca).await;

        // Without skip_hostname_verify, non-matching name should fail
        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create connector");

        let result = connector.connect(addr, "wrong-hostname").await;
        assert!(result.is_err(), "should fail with hostname mismatch");

        server_handle.abort();
    }

    #[tokio::test]
    async fn connect_wrong_ca_fails() {
        let ca = TestCa::new("Test CA");
        let other_ca = TestCa::new("Other CA");
        let client_cert = other_ca.issue_client_cert("federation-client", &["Alpha"]);
        let (addr, server_handle) = start_test_server(&ca).await;

        // Client uses other_ca's cert — server cert won't be trusted
        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &other_ca.cert_pem,
            false,
        )
        .expect("create connector");

        let result = connector.connect(addr, "localhost").await;
        assert!(result.is_err(), "should fail with untrusted CA");

        server_handle.abort();
    }

    #[tokio::test]
    async fn connect_unreachable_address_fails() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create connector");

        // Use a port that's (almost certainly) not listening
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("parse addr");
        let result = connector.connect(addr, "localhost").await;
        assert!(
            result.is_err(),
            "should fail connecting to unreachable addr"
        );
    }

    #[test]
    fn from_pem_invalid_cert() {
        let result = PeerConnector::from_pem("not a cert", "not a key", "not a ca", false);
        assert!(result.is_err());
    }

    #[test]
    fn from_pem_empty_cert() {
        let result = PeerConnector::from_pem("", "", "", false);
        assert!(result.is_err());
    }

    #[test]
    fn from_pem_valid_certs() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("test", &[]);

        let result = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn from_pem_skip_hostname_verify() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("test", &[]);

        let result = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn connector_is_clone() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("test", &[]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create");

        let _cloned = connector.clone();
    }

    #[test]
    fn connector_debug() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("test", &[]);

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create");

        let debug = format!("{connector:?}");
        assert!(debug.contains("PeerConnector"));
    }

    #[test]
    fn parse_certs_empty_pem() {
        let result = parse_certs("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_key_empty_pem() {
        let result = parse_key("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ca_store_empty_pem() {
        let result = parse_ca_store("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_certs_valid() {
        let ca = TestCa::new("Test CA");
        let cert = ca.issue_client_cert("test", &[]);
        let result = parse_certs(&cert.cert_pem);
        assert!(result.is_ok());
        assert_eq!(result.expect("certs").len(), 1);
    }

    #[test]
    fn parse_key_valid() {
        let ca = TestCa::new("Test CA");
        let cert = ca.issue_client_cert("test", &[]);
        let result = parse_key(&cert.key_pem);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_ca_store_valid() {
        let ca = TestCa::new("Test CA");
        let result = parse_ca_store(&ca.cert_pem);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn connect_multiple_sequential() {
        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("multi-client", &["Alpha"]);
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
                .expect("tls config");
        let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handle = tokio::spawn(async move {
            for _ in 0..3 {
                let _session = listener.accept().await.expect("accept");
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &ca.cert_pem,
            false,
        )
        .expect("create connector");

        // Connect 3 times with the same connector
        let (_, id1) = connector
            .connect(addr, "localhost")
            .await
            .expect("connect 1");
        assert_eq!(id1.cn, "localhost");

        let (_, id2) = connector
            .connect(addr, "localhost")
            .await
            .expect("connect 2");
        assert_eq!(id2.cn, "localhost");

        let (_, id3) = connector
            .connect(addr, "localhost")
            .await
            .expect("connect 3");
        assert_eq!(id3.cn, "localhost");

        handle.abort();
    }

    #[tokio::test]
    async fn connect_with_skip_hostname_verify_still_validates_ca() {
        let ca = TestCa::new("Trusted CA");
        let other_ca = TestCa::new("Untrusted CA");
        let client_cert = ca.issue_client_cert("client", &[]);
        let (addr, server_handle) = start_test_server(&ca).await;

        // Use skip_hostname_verify=true but with wrong CA
        let connector = PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &other_ca.cert_pem, // Wrong CA!
            true,
        )
        .expect("create connector");

        let result = connector.connect(addr, "any-name").await;
        assert!(
            result.is_err(),
            "skip_hostname_verify should still validate CA chain"
        );

        server_handle.abort();
    }
}

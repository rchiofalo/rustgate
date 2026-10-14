// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the enrollment HTTPS server.
//!
//! Spins up a real enrollment server on localhost with ephemeral certs,
//! then makes HTTP requests over TLS to verify endpoint behavior.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustgate_core::b64;
use rustgate_enrollment::{Credentials, CsrSigner, EnrollmentServer};
use rustgate_test_utils::certs::TestCa;
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Find a free TCP port by binding to port 0 and immediately releasing.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind for port discovery");
    listener.local_addr().expect("local_addr").port()
}

/// Connect to the given address, retrying briefly while the background server
/// finishes binding its listener.
///
/// `spawn_server_with` launches the server in a detached tokio task and
/// returns immediately, so the first `TcpStream::connect` can race the
/// listener `bind` and hit `ECONNREFUSED`. Retry for up to ~2 s to cover
/// slow-starting runners without masking a genuinely dead server.
async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
    let mut last_err = None;
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    panic!(
        "TCP connect to {addr} never succeeded after retries: {:?}",
        last_err
    );
}

/// Build test infrastructure: CA, server cert, signer, credentials.
struct TestEnv {
    addr: SocketAddr,
    server_cert_pem: String,
    server_key_pem: String,
    ca_cert_pem: String,
    ca_key_pem: String,
}

impl TestEnv {
    fn new() -> Self {
        let ca = TestCa::new("Test Enrollment CA");
        let server = ca.issue_server_cert("localhost", &["localhost"]);

        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse socket addr");

        Self {
            addr,
            server_cert_pem: server.cert_pem,
            server_key_pem: server.key_pem,
            ca_cert_pem: ca.cert_pem,
            ca_key_pem: ca.key_pem,
        }
    }

    /// Spawn the enrollment server as a background task.
    fn spawn_server(&self) -> tokio::task::JoinHandle<()> {
        self.spawn_server_with_rate_limit(10)
    }

    /// Spawn the enrollment server with a custom CSR rate limit (per minute).
    fn spawn_server_with_rate_limit(&self, max_per_minute: usize) -> tokio::task::JoinHandle<()> {
        self.spawn_server_with(max_per_minute, None)
    }

    /// Spawn the server with a rate limit and optional callback fired on
    /// every rate-limited request.
    fn spawn_server_with(
        &self,
        max_per_minute: usize,
        on_rate_limit: Option<rustgate_enrollment::RateLimitCallback>,
    ) -> tokio::task::JoinHandle<()> {
        let signer = CsrSigner::from_pem(&self.ca_cert_pem, &self.ca_key_pem, "TestOrg")
            .expect("build signer for server");
        let credentials = Credentials::new(
            "admin".to_string(),
            zeroize::Zeroizing::new("secret".to_string()),
        );
        let mut server = EnrollmentServer::new(signer, credentials)
            .with_rate_limit(max_per_minute, std::time::Duration::from_secs(60));
        if let Some(cb) = on_rate_limit {
            server = server.with_rate_limit_callback(cb);
        }

        let addr = self.addr;
        let cert_pem = self.server_cert_pem.clone();
        let key_pem = self.server_key_pem.clone();

        tokio::spawn(async move {
            let _ = server.run(addr, &cert_pem, &key_pem).await;
        })
    }

    /// Build a TLS connector that trusts the test CA.
    fn tls_connector(&self) -> TlsConnector {
        let mut root_store = rustls::RootCertStore::empty();
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_slice_iter(self.ca_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse CA cert");
        for cert in certs {
            root_store.add(cert).expect("add CA cert to root store");
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        TlsConnector::from(Arc::new(tls_config))
    }

    /// Send an HTTP request to the enrollment server and return the response.
    async fn send_request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> hyper::Response<hyper::body::Incoming> {
        let tcp = connect_with_retry(self.addr).await;

        let server_name = rustls_pki_types::ServerName::try_from("localhost").expect("server name");
        let tls = self
            .tls_connector()
            .connect(server_name, tcp)
            .await
            .expect("TLS connect");

        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("HTTP handshake");

        let _conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        sender.send_request(req).await.expect("send request")
    }
}

fn encode_basic_auth(user: &str, pass: &str) -> String {
    let encoded = b64::encode(format!("{user}:{pass}"));
    format!("Basic {encoded}")
}

fn generate_csr(cn: &str) -> String {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let key = KeyPair::generate().expect("keygen");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;

    let csr = params.serialize_request(&key).expect("csr");
    csr.pem().expect("pem")
}

#[tokio::test]
async fn sign_client_valid_csr() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let csr = generate_csr("test-client");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/signClient/v2",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let body = resp.collect().await.expect("collect body").to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid JSON");
    assert!(json.get("signedCert").is_some(), "missing signedCert key");
    assert!(json.get("ca0").is_some(), "missing ca0 key");
}

#[tokio::test]
async fn missing_auth_returns_401() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/signClient/v2",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 401);

    let www_auth = resp
        .headers()
        .get("WWW-Authenticate")
        .expect("should have WWW-Authenticate header");
    assert!(
        www_auth.to_str().expect("header to str").contains("Basic"),
        "WWW-Authenticate should indicate Basic auth"
    );
}

#[tokio::test]
async fn wrong_credentials_returns_401() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/signClient/v2",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "wrong"))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn oversized_body_rejected() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 70KB body exceeds the 64KB limit
    let oversized = vec![b'A'; 70 * 1024];
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/signClient/v2",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(oversized)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn xml_content_negotiation() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let csr = generate_csr("xml-client");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/signClient/v2",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Accept", "application/xml")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("Content-Type")
        .expect("should have Content-Type")
        .to_str()
        .expect("header to str");
    assert!(
        content_type.contains("application/xml"),
        "expected XML content type, got: {content_type}"
    );

    let body = resp.collect().await.expect("collect body").to_bytes();
    let body_str = std::str::from_utf8(&body).expect("body is UTF-8");
    assert!(
        body_str.contains("<enrollment>"),
        "XML response should contain enrollment element"
    );
}

#[tokio::test]
async fn get_tls_config() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/Marti/api/tls/config",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let body = resp.collect().await.expect("collect body").to_bytes();
    let body_str = std::str::from_utf8(&body).expect("body is UTF-8");
    assert!(
        body_str.contains("certificateConfig"),
        "should contain certificateConfig"
    );
    assert!(
        body_str.contains("TestOrg"),
        "should contain the organization name"
    );
}

#[tokio::test]
async fn csr_rate_limit_returns_429_and_fires_callback() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let env = TestEnv::new();
    let counter = Arc::new(AtomicU64::new(0));
    let cb_counter = Arc::clone(&counter);
    let cb: rustgate_enrollment::RateLimitCallback = Arc::new(move || {
        let _ = cb_counter.fetch_add(1, Ordering::Relaxed);
    });

    // Allow only 2 requests per minute per IP, with a callback registered.
    let _server = env.spawn_server_with(2, Some(cb));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let make_req = || {
        let csr = generate_csr("rl-client");
        Request::builder()
            .method("POST")
            .uri(format!(
                "https://localhost:{}/Marti/api/tls/signClient/v2",
                env.addr.port()
            ))
            .header("Authorization", encode_basic_auth("admin", "secret"))
            .header("Host", "localhost")
            .body(Full::new(Bytes::from(csr)))
            .expect("build request")
    };

    // First two requests should succeed.
    for _ in 0..2 {
        let resp = env.send_request(make_req()).await;
        assert_eq!(resp.status(), 200, "request under limit should succeed");
    }

    // Third request from the same IP must be rejected with 429.
    let resp = env.send_request(make_req()).await;
    assert_eq!(
        resp.status(),
        429,
        "third request should exceed the rate limit"
    );

    let body = resp.collect().await.expect("collect body").to_bytes();
    let body_str = std::str::from_utf8(&body).expect("body is UTF-8");
    assert!(
        body_str.contains("rate limit"),
        "429 body should mention rate limit, got: {body_str}"
    );

    assert!(
        counter.load(Ordering::Relaxed) >= 1,
        "rate-limit callback should fire on rejection"
    );
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let env = TestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/nonexistent", env.addr.port()))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 404);
}

// -------------------------------------------------------------------------
// F-40: refuse to start without TLS (issue #767)
//
// PKCS#12 enrollment responses embed unencrypted certificate bags
// integrity-protected only by the standardized "atakatak" password.
// TLS is therefore the only real confidentiality boundary on this
// endpoint; running plaintext would leak client certs to anyone on the
// path. `EnrollmentServer::run` must reject an empty cert_pem or
// key_pem up front, with an error that names the invariant.
// -------------------------------------------------------------------------

#[tokio::test]
async fn run_rejects_empty_cert_pem_to_prevent_plaintext() {
    let env = TestEnv::new();
    let signer =
        CsrSigner::from_pem(&env.ca_cert_pem, &env.ca_key_pem, "TestOrg").expect("build signer");
    let credentials = Credentials::new(
        "admin".to_string(),
        zeroize::Zeroizing::new("secret".to_string()),
    );
    let server = EnrollmentServer::new(signer, credentials);

    let err = server
        .run(env.addr, "   \n\t", &env.server_key_pem)
        .await
        .expect_err("run() must refuse to start without a TLS cert");

    let msg = err.to_string();
    assert!(
        msg.contains("TLS"),
        "error must mention TLS requirement, got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("plaintext")
            || msg.to_lowercase().contains("refusing to start")
            || msg.to_lowercase().contains("refuse"),
        "error must explain the refusal, got: {msg}"
    );
}

#[tokio::test]
async fn run_rejects_empty_key_pem_to_prevent_plaintext() {
    let env = TestEnv::new();
    let signer =
        CsrSigner::from_pem(&env.ca_cert_pem, &env.ca_key_pem, "TestOrg").expect("build signer");
    let credentials = Credentials::new(
        "admin".to_string(),
        zeroize::Zeroizing::new("secret".to_string()),
    );
    let server = EnrollmentServer::new(signer, credentials);

    let err = server
        .run(env.addr, &env.server_cert_pem, "")
        .await
        .expect_err("run() must refuse to start without a TLS key");

    assert!(
        err.to_string().contains("TLS"),
        "error must mention TLS requirement, got: {err}"
    );
}

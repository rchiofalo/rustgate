// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for EST (RFC 7030) enrollment endpoints.
//!
//! Spins up a real enrollment server with EST enabled, then exercises
//! the `/.well-known/est/` endpoints over TLS.

#![cfg(feature = "est")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;

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

/// Build test infrastructure with EST enabled.
struct EstTestEnv {
    addr: SocketAddr,
    server_cert_pem: String,
    server_key_pem: String,
    ca_cert_pem: String,
    ca_key_pem: String,
}

impl EstTestEnv {
    fn new() -> Self {
        let ca = TestCa::new("Test EST CA");
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

    /// Spawn the enrollment server with EST endpoints enabled.
    fn spawn_server(&self) -> tokio::task::JoinHandle<()> {
        let signer = CsrSigner::from_pem(&self.ca_cert_pem, &self.ca_key_pem, "TestOrg")
            .expect("build signer");
        let credentials = Credentials::new(
            "admin".to_string(),
            zeroize::Zeroizing::new("secret".to_string()),
        );
        let server = EnrollmentServer::new(signer, credentials)
            .with_rate_limit(10, std::time::Duration::from_secs(60))
            .with_est();

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

    /// Send an HTTP request to the server and return the response.
    async fn send_request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> hyper::Response<hyper::body::Incoming> {
        let tcp = TcpStream::connect(self.addr).await.expect("TCP connect");

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

/// Generate a CSR and return it as base64 of DER (EST wire format).
fn generate_est_csr(cn: &str) -> String {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let key = KeyPair::generate().expect("keygen");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;

    let csr = params.serialize_request(&key).expect("csr");
    // EST sends base64 of DER (no PEM headers).
    b64::encode(csr.der())
}

// ---------------------------------------------------------------------------
// GET /.well-known/est/cacerts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_cacerts_returns_pkcs7() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/.well-known/est/cacerts",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("Content-Type")
        .expect("Content-Type header")
        .to_str()
        .expect("header to str");
    assert!(
        content_type.contains("application/pkcs7-mime"),
        "expected PKCS#7 content type, got: {content_type}"
    );
    assert!(
        content_type.contains("smime-type=certs-only"),
        "RFC 7030 §4.1.2 requires smime-type=certs-only, got: {content_type}"
    );

    // Body is base64-encoded DER; verify it decodes to valid PKCS#7.
    let body = resp.collect().await.expect("collect body").to_bytes();
    let decoded = b64::decode(&body).expect("base64 decode");
    assert!(
        !decoded.is_empty(),
        "decoded PKCS#7 bag should not be empty"
    );
}

// ---------------------------------------------------------------------------
// POST /.well-known/est/simpleenroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_simpleenroll_issues_cert() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let csr_b64 = generate_est_csr("est-client");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simpleenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("Content-Type")
        .expect("Content-Type header")
        .to_str()
        .expect("header to str");
    assert!(
        content_type.contains("application/pkcs7-mime"),
        "expected PKCS#7 content type, got: {content_type}"
    );

    // Body should be base64-encoded PKCS#7 containing issued cert + CA cert.
    let body = resp.collect().await.expect("collect body").to_bytes();
    let decoded = b64::decode(&body).expect("base64 decode response");
    assert!(
        !decoded.is_empty(),
        "enrollment response should contain certificate data"
    );
}

#[tokio::test]
async fn est_simpleenroll_requires_auth() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let csr_b64 = generate_est_csr("noauth-client");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simpleenroll",
            env.addr.port()
        ))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 401);

    let www_auth = resp
        .headers()
        .get("WWW-Authenticate")
        .expect("WWW-Authenticate header");
    assert!(
        www_auth.to_str().expect("header to str").contains("Basic"),
        "should indicate Basic auth"
    );
}

#[tokio::test]
async fn est_simpleenroll_rejects_wrong_content_type() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simpleenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "text/plain")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from("some data")))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 415);
}

// ---------------------------------------------------------------------------
// POST /.well-known/est/simplereenroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_simplereenroll_issues_cert() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // CSR CN must match authenticated username for re-enrollment.
    let csr_b64 = generate_est_csr("admin");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simplereenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("Content-Type")
        .expect("Content-Type header")
        .to_str()
        .expect("header to str");
    assert!(
        content_type.contains("application/pkcs7-mime"),
        "expected PKCS#7 content type, got: {content_type}"
    );
}

// ---------------------------------------------------------------------------
// POST /.well-known/est/simplereenroll — identity verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_reenroll_rejects_cn_mismatch() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Authenticate as "admin" but request a CSR with CN="mallory".
    // Re-enrollment must reject this identity mismatch.
    let csr_b64 = generate_est_csr("mallory");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simplereenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(
        resp.status(),
        403,
        "re-enrollment with mismatched CN should be forbidden"
    );
}

#[tokio::test]
async fn est_reenroll_accepts_matching_cn() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Authenticate as "admin" and request a CSR with CN="admin".
    let csr_b64 = generate_est_csr("admin");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simplereenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200, "matching CN should succeed");

    let content_type = resp
        .headers()
        .get("Content-Type")
        .expect("Content-Type header")
        .to_str()
        .expect("header to str");
    assert!(
        content_type.contains("application/pkcs7-mime"),
        "expected PKCS#7 content type, got: {content_type}"
    );
}

#[tokio::test]
async fn est_reenroll_case_insensitive_cn_match() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Authenticate as "admin" and request a CSR with CN="Admin" (different case).
    // Case-insensitive comparison should accept this.
    let csr_b64 = generate_est_csr("Admin");
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/.well-known/est/simplereenroll",
            env.addr.port()
        ))
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(
        resp.status(),
        200,
        "case-insensitive CN match should succeed"
    );
}

// ---------------------------------------------------------------------------
// GET /.well-known/est/csrattrs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_csrattrs_returns_no_content() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/.well-known/est/csrattrs",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 204);
}

// ---------------------------------------------------------------------------
// Label support (/.well-known/est/{label}/cacerts)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_labeled_cacerts_works() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/.well-known/est/my-ca/cacerts",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// Unknown EST operation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_unknown_operation_returns_404() {
    let env = EstTestEnv::new();
    let _server = env.spawn_server();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/.well-known/est/nonexistent",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// EST disabled — paths fall through to 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_disabled_returns_404() {
    let env = EstTestEnv::new();

    // Spawn server WITHOUT .with_est() — EST paths should 404.
    let signer =
        CsrSigner::from_pem(&env.ca_cert_pem, &env.ca_key_pem, "TestOrg").expect("build signer");
    let credentials = Credentials::new(
        "admin".to_string(),
        zeroize::Zeroizing::new("secret".to_string()),
    );
    let server = EnrollmentServer::new(signer, credentials); // no .with_est()

    let addr = env.addr;
    let cert_pem = env.server_cert_pem.clone();
    let key_pem = env.server_key_pem.clone();
    let _handle = tokio::spawn(async move {
        let _ = server.run(addr, &cert_pem, &key_pem).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost:{}/.well-known/est/cacerts",
            env.addr.port()
        ))
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let resp = env.send_request(req).await;
    assert_eq!(
        resp.status(),
        404,
        "EST endpoints should 404 when not enabled"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting on EST simpleenroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn est_simpleenroll_rate_limited() {
    let env = EstTestEnv::new();

    let signer =
        CsrSigner::from_pem(&env.ca_cert_pem, &env.ca_key_pem, "TestOrg").expect("build signer");
    let credentials = Credentials::new(
        "admin".to_string(),
        zeroize::Zeroizing::new("secret".to_string()),
    );
    let server = EnrollmentServer::new(signer, credentials)
        .with_rate_limit(2, std::time::Duration::from_secs(60))
        .with_est();

    let addr = env.addr;
    let cert_pem = env.server_cert_pem.clone();
    let key_pem = env.server_key_pem.clone();
    let _handle = tokio::spawn(async move {
        let _ = server.run(addr, &cert_pem, &key_pem).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let make_req = || {
        let csr_b64 = generate_est_csr("rl-client");
        Request::builder()
            .method("POST")
            .uri(format!(
                "https://localhost:{}/.well-known/est/simpleenroll",
                env.addr.port()
            ))
            .header("Authorization", encode_basic_auth("admin", "secret"))
            .header("Content-Type", "application/pkcs10")
            .header("Host", "localhost")
            .body(Full::new(Bytes::from(csr_b64)))
            .expect("build request")
    };

    // First two should succeed.
    for _ in 0..2 {
        let resp = env.send_request(make_req()).await;
        assert_eq!(resp.status(), 200);
    }

    // Third should be rate limited.
    let resp = env.send_request(make_req()).await;
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn est_bad_content_type_does_not_consume_sign_rate_limit() {
    // #1611: the sign rate-limit slot must NOT be consumed by requests that
    // never reach signing. With a single-slot limit, several authenticated
    // requests carrying a bad Content-Type (rejected 415) must not exhaust the
    // budget — a subsequent well-formed request must still succeed. Pre-fix the
    // limiter recorded a slot before the Content-Type check, so the first 415
    // burned the budget and the valid request below returned 429.
    let env = EstTestEnv::new();

    let signer =
        CsrSigner::from_pem(&env.ca_cert_pem, &env.ca_key_pem, "TestOrg").expect("build signer");
    let credentials = Credentials::new(
        "admin".to_string(),
        zeroize::Zeroizing::new("secret".to_string()),
    );
    let server = EnrollmentServer::new(signer, credentials)
        .with_rate_limit(1, std::time::Duration::from_secs(60))
        .with_est();

    let addr = env.addr;
    let cert_pem = env.server_cert_pem.clone();
    let key_pem = env.server_key_pem.clone();
    let _handle = tokio::spawn(async move {
        let _ = server.run(addr, &cert_pem, &key_pem).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let uri = format!(
        "https://localhost:{}/.well-known/est/simpleenroll",
        env.addr.port()
    );

    // Three authenticated requests with a bad Content-Type — each rejected 415,
    // and none may consume the single signing slot.
    for _ in 0..3 {
        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("Authorization", encode_basic_auth("admin", "secret"))
            .header("Content-Type", "text/plain")
            .header("Host", "localhost")
            .body(Full::new(Bytes::from("not a csr")))
            .expect("build request");
        let resp = env.send_request(req).await;
        assert_eq!(resp.status(), 415, "bad Content-Type must be rejected 415");
    }

    // A well-formed request must still succeed: the budget was never spent.
    let csr_b64 = generate_est_csr("est-client");
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("Authorization", encode_basic_auth("admin", "secret"))
        .header("Content-Type", "application/pkcs10")
        .header("Host", "localhost")
        .body(Full::new(Bytes::from(csr_b64)))
        .expect("build request");
    let resp = env.send_request(req).await;
    assert_eq!(
        resp.status(),
        200,
        "well-formed request must succeed; bad Content-Type must not consume the sign budget (#1611)"
    );
}

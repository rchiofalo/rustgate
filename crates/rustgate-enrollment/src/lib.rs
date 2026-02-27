//! Certificate enrollment for rustgate.
//!
//! HTTPS endpoint (no client cert required) that accepts a username/password
//! and PKCS#10 CSR, signs it with the server CA, and returns a client
//! certificate. Implements the Marti-compatible certificate signing flow
//! so TAK clients can self-provision without manual `.p12` distribution.

mod signing;

pub use signing::CsrSigner;

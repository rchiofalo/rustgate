//! Certificate enrollment for rustgate.
//!
//! HTTPS endpoint (no client cert required) that accepts a username/password
//! and PKCS#10 CSR, signs it with the server CA, and returns a client
//! certificate. Implements the Marti-compatible certificate signing flow
//! so TAK clients can self-provision without manual `.p12` distribution.

pub mod auth;
pub mod contacts;
pub mod datapackage;
pub mod error;
pub mod response;
pub mod server;
pub mod signing;

pub use auth::Credentials;
pub use contacts::{ContactInfo, ContactsProvider};
pub use datapackage::DataPackageStore;
pub use error::EnrollmentError;
pub use server::EnrollmentServer;
pub use signing::CsrSigner;

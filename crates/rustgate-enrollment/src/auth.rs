// Copyright © 2026 Roberto Chiofalo.

//! HTTP Basic Auth credential validation.

use rustgate_core::b64;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Enrollment credentials for HTTP Basic Auth.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    /// Wrapped in [`Zeroizing`] so the password is wiped from memory on drop.
    password: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// Create a new set of credentials.
    ///
    /// Accepts the password already wrapped in [`Zeroizing`] so the caller
    /// never holds an unzeroized copy. Use `Zeroizing::new(password)` at
    /// the point closest to the original source (CLI arg, env var, file).
    pub fn new(username: String, password: Zeroizing<String>) -> Self {
        Self { username, password }
    }

    /// Validate a Basic Auth header value. Returns the username on success.
    ///
    /// Expects the raw `Authorization` header value (e.g., `"Basic dXNlcjpwYXNz"`).
    pub fn validate(&self, authorization: Option<&str>) -> Option<&str> {
        let header = authorization?;
        let encoded = header.strip_prefix("Basic ")?;

        let decoded = b64::decode(encoded).ok()?;
        let text = std::str::from_utf8(&decoded).ok()?;
        let (user, pass) = text.split_once(':')?;

        // Both comparisons always execute — no short-circuit — so an attacker
        // cannot distinguish "wrong username" from "wrong password" via timing.
        let user_ok = user.as_bytes().ct_eq(self.username.as_bytes());
        let pass_ok = pass.as_bytes().ct_eq(self.password.as_bytes());
        if (user_ok & pass_ok).into() {
            Some(&self.username)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials::new("admin".to_string(), Zeroizing::new("secret".to_string()))
    }

    fn encode_basic(user: &str, pass: &str) -> String {
        let encoded = b64::encode(format!("{user}:{pass}"));
        format!("Basic {encoded}")
    }

    #[test]
    fn valid_auth() {
        let c = creds();
        let header = encode_basic("admin", "secret");
        assert_eq!(c.validate(Some(&header)), Some("admin"));
    }

    #[test]
    fn wrong_password() {
        let c = creds();
        let header = encode_basic("admin", "wrong");
        assert_eq!(c.validate(Some(&header)), None);
    }

    #[test]
    fn wrong_username() {
        let c = creds();
        let header = encode_basic("other", "secret");
        assert_eq!(c.validate(Some(&header)), None);
    }

    #[test]
    fn missing_header() {
        let c = creds();
        assert_eq!(c.validate(None), None);
    }

    #[test]
    fn bearer_rejected() {
        let c = creds();
        assert_eq!(c.validate(Some("Bearer sometoken")), None);
    }

    #[test]
    fn invalid_base64() {
        let c = creds();
        assert_eq!(c.validate(Some("Basic !!!invalid!!!")), None);
    }

    #[test]
    fn no_colon_separator() {
        let encoded = b64::encode("nocolon");
        let header = format!("Basic {encoded}");
        let c = creds();
        assert_eq!(c.validate(Some(&header)), None);
    }

    #[test]
    fn password_with_colons() {
        let c = Credentials::new(
            "admin".to_string(),
            Zeroizing::new("pass:with:colons".to_string()),
        );
        let header = encode_basic("admin", "pass:with:colons");
        assert_eq!(c.validate(Some(&header)), Some("admin"));
    }

    #[test]
    fn empty_password() {
        let c = Credentials::new("admin".to_string(), Zeroizing::new(String::new()));
        let header = encode_basic("admin", "");
        assert_eq!(c.validate(Some(&header)), Some("admin"));
    }
}

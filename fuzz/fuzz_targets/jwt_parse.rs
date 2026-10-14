// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_federation::jwt::{FederationClaims, JwtAuthority};

fuzz_target!(|data: &[u8]| {
    // Fuzz the full JWT validation path: base64url decode, HMAC verify, JSON parse.
    // Uses a fixed secret so the fuzzer can explore token format handling.
    let secret = b"fuzz-secret-key-must-be-32-bytes!";
    if let Ok(authority) = JwtAuthority::new(secret.to_vec(), "fuzz-issuer") {
        if let Ok(token) = std::str::from_utf8(data) {
            let _ = authority.validate(token);
        }
    }

    // Also fuzz the claims JSON deserialization directly
    let _ = serde_json::from_slice::<FederationClaims>(data);
});

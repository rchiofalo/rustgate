// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

//! Fuzz target: JSON policy parsing + compilation must not panic on any
//! input. Parsed rule sets are also compiled into a `NativeEngine` so the
//! compiler's validation paths are exercised too.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(rs) = rustgate_authz::parser::parse_json(data) {
        let _ = rustgate_authz::NativeEngine::new(rs);
    }
});

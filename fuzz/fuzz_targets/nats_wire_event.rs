// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_nats::WireEvent;

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON deserialization of NATS wire events.
    // This is the path taken when receiving messages from NATS subscribers.
    if let Ok(event) = serde_json::from_slice::<WireEvent>(data) {
        // If parsing succeeds, verify re-serialization doesn't panic
        let _ = serde_json::to_vec(&event);
    }
});

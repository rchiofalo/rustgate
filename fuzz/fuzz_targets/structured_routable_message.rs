// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_core::message::RoutableMessage;

fuzz_target!(|msg: RoutableMessage| {
    // Exercise Display impls and basic accessors with structured inputs.
    let _dest = msg.destination.to_string();
    let _mtype = msg.metadata.message_type.to_string();
    let _source = msg.source.to_string();
    let _payload_len = msg.payload.len();
});

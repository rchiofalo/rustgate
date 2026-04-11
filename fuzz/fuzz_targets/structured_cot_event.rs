// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_cot::CotEvent;

fuzz_target!(|event: CotEvent| {
    // Exercise the CotEvent fields with structured inputs.
    let _uid = &event.uid;
    let _etype = &event.event_type;
    let _dest = format!("{:?}", event.destination);
    let _mtype = event.message_type.to_string();
    let _pos = event.position.map(|p| (p.lat, p.lon, p.hae));
    let _ttl = event.ttl;
    let _group = &event.source_group;
});

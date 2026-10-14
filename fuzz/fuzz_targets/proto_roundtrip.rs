// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_proto::{proto_to_xml, xml_to_proto};

fuzz_target!(|data: &[u8]| {
    // Fuzz XML -> protobuf conversion
    if let Ok(proto_bytes) = xml_to_proto(data) {
        // If encoding succeeds, verify the roundtrip back to XML doesn't panic
        let _ = proto_to_xml(&proto_bytes);
    }

    // Fuzz protobuf -> XML conversion with arbitrary bytes
    let _ = proto_to_xml(data);
});

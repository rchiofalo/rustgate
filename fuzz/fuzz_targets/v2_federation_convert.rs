// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_federation::provenance::FederationMetadata;
use rustgate_federation::v2::convert::xml_to_federated_event;

fuzz_target!(|data: &[u8]| {
    let metadata = FederationMetadata::default();
    let _ = xml_to_federated_event(data, &metadata);
});

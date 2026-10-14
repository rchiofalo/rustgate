// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! V1 federation protocol: length-prefixed XML over mTLS.
//!
//! This is the legacy TAK Server federation wire format where each message
//! is framed with a 4-byte big-endian length header followed by raw XML.

pub mod client;
pub mod server;

pub use client::V1Client;
pub use server::V1Server;

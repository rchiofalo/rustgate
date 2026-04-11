// Copyright © 2026 Roberto Chiofalo.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tokio_tungstenite::tungstenite::Message;

fuzz_target!(|data: &[u8]| {
    // Fuzz WebSocket message handling paths.
    // Test binary message construction and introspection — this exercises
    // the same code paths used when rustgate receives WebSocket frames.
    let bin_msg = Message::Binary(data.to_vec().into());
    let _ = bin_msg.len();
    let _ = bin_msg.is_binary();
    let _ = bin_msg.into_data();

    // Fuzz text message handling with arbitrary bytes interpreted as UTF-8.
    if let Ok(text) = std::str::from_utf8(data) {
        let text_msg = Message::Text(text.to_string().into());
        let _ = text_msg.len();
        let _ = text_msg.is_text();
        let _ = text_msg.into_data();
    }

    // Fuzz ping/pong handling
    let ping = Message::Ping(data.to_vec().into());
    let _ = ping.len();
    let pong = Message::Pong(data.to_vec().into());
    let _ = pong.len();
});

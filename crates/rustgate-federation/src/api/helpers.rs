//! JSON response helpers and URL decoding utilities.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Serialize;

use super::types::{ErrorResponse, SuccessResponse};

/// Build a 500 Internal Server Error response with a plain-text body.
pub(crate) fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// Build a 200 OK JSON response wrapping `data` in a `{"data": ...}` envelope.
pub(crate) fn json_ok<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Build a 201 Created JSON response wrapping `data` in a `{"data": ...}` envelope.
pub(crate) fn json_created<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Build a JSON error response with the given status code and message.
pub(crate) fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.to_string(),
    })
    .unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Simple percent-decoding for URL path segments.
pub(crate) fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let decoded = hex_byte(hi, lo);
            result.push(decoded as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

pub(crate) fn hex_byte(hi: u8, lo: u8) -> u8 {
    (hex_nibble(hi) << 4) | hex_nibble(lo)
}

pub(crate) fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

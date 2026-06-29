// Copyright © 2026 Roberto Chiofalo.

//! Minimal `multipart/form-data` body slicing.
//!
//! TAK clients (ATAK, WinTAK, iTAK) upload Mission Packages with a
//! single `multipart/form-data` form whose `file` field carries the
//! ZIP body. The full RFC 7578 surface (nested parts, transfer
//! encodings, content-type negotiation per part) is overkill for
//! that one shape; pulling in `multer` or `axum::extract::Multipart`
//! would add a heavy parser tree and an `axum`/`hyper-multer` dep
//! footprint for what is fundamentally a four-line scan.
//!
//! This module exposes three helpers used by the admin HTTP layer
//! when it forwards an upload to [`crate::PackageStore::upload`]:
//!
//! - [`extract_boundary`] — pull the boundary token out of a
//!   `Content-Type: multipart/form-data; boundary=…` header.
//! - [`extract_multipart_field`] — return the raw bytes of the part
//!   whose `Content-Disposition` header contains
//!   `name="<field>"`. The bytes are returned by reference so the
//!   uploader avoids one allocation on the hot path.
//! - [`extract_multipart_filename`] — return the `filename="…"`
//!   attribute of the first part that carries one, used for the
//!   sidecar's display name.
//!
//! The helpers are deliberately tolerant — unknown headers are
//! ignored, attribute ordering is irrelevant, and a malformed body
//! returns `None` rather than panicking. They were originally
//! authored under `rustgate-enrollment::datapackage` for the legacy
//! Marti package endpoint; this module hosts them now so the admin
//! crate does not need to take an enrollment dependency to ship the
//! REST API.

/// Extract the `boundary=` token from a `Content-Type` header value.
///
/// Returns `None` if the header is not a multipart form, the
/// boundary token is missing, or the value is empty after trimming
/// surrounding quotes.
pub fn extract_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed
            .strip_prefix("boundary=")
            .map(|b| b.trim_matches('"'))
    })
}

/// Return the raw bytes of the multipart part whose
/// `Content-Disposition` header contains `name="<field>"`.
///
/// The returned slice borrows from `body`, so the caller must hold
/// the body buffer alive for the slice's lifetime.
pub fn extract_multipart_field<'a>(
    body: &'a [u8],
    boundary: &str,
    field: &str,
) -> Option<&'a [u8]> {
    let boundary_marker = format!("--{boundary}");
    let body_str = std::str::from_utf8(body).ok()?;
    let disposition_needle = format!("name=\"{field}\"");

    let mut search_start = 0;
    for part in body_str.split(&boundary_marker) {
        let part_offset = body_str[search_start..]
            .find(part)
            .map(|i| i + search_start)?;
        search_start = part_offset + part.len();

        if !part.contains(&disposition_needle) {
            continue;
        }
        let content_start = part.find("\r\n\r\n").map(|i| i + 4)?;
        let content = part.get(content_start..)?;
        let content = content.trim_end_matches("\r\n--").trim_end_matches("\r\n");
        let offset = part_offset + content_start;
        return body.get(offset..offset + content.len());
    }
    None
}

/// Return the `filename="…"` attribute of the first
/// `Content-Disposition` header in `body` that carries one.
///
/// Used for the package's display name when the upload's multipart
/// form does not provide a separate `name` field.
pub fn extract_multipart_filename(body: &[u8], boundary: &str) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    let boundary_marker = format!("--{boundary}");
    for part in body_str.split(&boundary_marker) {
        if let Some(pos) = part.find("filename=\"") {
            let start = pos + "filename=\"".len();
            let rest = part.get(start..)?;
            let end = rest.find('"')?;
            let name = rest.get(..end)?;
            // Reject control characters in the filename. It becomes the
            // package display name and is later interpolated into a
            // `Content-Disposition` response header on download, so a CR / LF /
            // NUL would allow header / response splitting (#1608). Such a
            // filename is never legitimate — drop it (the caller falls back to
            // a generated name) rather than store an injection vector.
            if name.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
                return None;
            }
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn extract_boundary_handles_quotes_and_padding() {
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=----WebKitFormBoundary"),
            Some("----WebKitFormBoundary")
        );
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=\"abc\""),
            Some("abc")
        );
        assert_eq!(extract_boundary("application/json"), None);
    }

    #[test]
    fn extract_multipart_field_returns_byte_slice() {
        let boundary = "----TEST";
        let body = "------TEST\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\nContent-Type: application/zip\r\n\r\nZIP-BYTES-HERE\r\n------TEST--\r\n";
        let got = extract_multipart_field(body.as_bytes(), boundary, "file").unwrap();
        assert_eq!(got, b"ZIP-BYTES-HERE");
    }

    #[test]
    fn extract_multipart_filename_finds_attribute() {
        let boundary = "----X";
        let body = "------X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"my.zip\"\r\n\r\nbody\r\n------X--\r\n";
        let got = extract_multipart_filename(body.as_bytes(), boundary).unwrap();
        assert_eq!(got, "my.zip");
    }

    #[test]
    fn extract_multipart_filename_rejects_control_characters() {
        // A filename containing CR / LF / NUL must not be returned: it becomes
        // the package display name and is later interpolated into a
        // `Content-Disposition` response header on download, so the bytes would
        // allow header / response splitting (#1608).
        let boundary = "----X";
        let body = |fname: &str| {
            format!(
                "------X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\n\r\nbody\r\n------X--\r\n"
            )
        };
        // A clean filename still round-trips.
        assert_eq!(
            extract_multipart_filename(body("clean.zip").as_bytes(), boundary).as_deref(),
            Some("clean.zip")
        );
        // CR/LF/NUL filenames are dropped (None → caller uses a generated name).
        assert!(
            extract_multipart_filename(body("a\r\nSet-Cookie: evil").as_bytes(), boundary)
                .is_none()
        );
        assert!(extract_multipart_filename(body("a\nb").as_bytes(), boundary).is_none());
        assert!(extract_multipart_filename(body("a\0b").as_bytes(), boundary).is_none());
    }

    #[test]
    fn extract_returns_none_for_missing_field() {
        let boundary = "----T";
        let body =
            "------T\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nx\r\n------T--\r\n";
        assert!(extract_multipart_field(body.as_bytes(), boundary, "file").is_none());
    }
}

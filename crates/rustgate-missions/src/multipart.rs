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

/// Find the first byte offset of `needle` within `haystack`.
///
/// A non-allocating substring search over raw bytes. Returns the
/// starting index, or `None` when `needle` does not occur. An empty
/// `needle` matches at offset 0 (mirroring `str::find`).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Yield the byte ranges between successive `delimiter` occurrences in
/// `body`, mirroring `str::split` over raw bytes.
///
/// Each yielded `(start, end)` pair is the half-open range of a segment
/// in `body`. Offsets are tracked directly as the scan advances, so the
/// overall walk is O(n) — the previous `body_str[..].find(part)`
/// re-search was O(n·m) per part, a CPU-amplification DoS on the
/// mission-package upload path (#1618).
fn split_parts<'a>(body: &'a [u8], delimiter: &'a [u8]) -> impl Iterator<Item = (usize, usize)> {
    let mut cursor = 0usize;
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        match body
            .get(cursor..)
            .and_then(|rest| find_bytes(rest, delimiter))
        {
            Some(rel) => {
                let start = cursor;
                let end = cursor + rel;
                cursor = end + delimiter.len();
                Some((start, end))
            }
            None => {
                done = true;
                Some((cursor.min(body.len()), body.len()))
            }
        }
    })
}

/// Return the raw bytes of the multipart part whose
/// `Content-Disposition` header contains `name="<field>"`.
///
/// The body is scanned as raw bytes — only each part's header block (up
/// to the `\r\n\r\n` separator) is decoded as UTF-8 to match the field
/// name. The content range is returned verbatim, so a binary part (e.g.
/// a ZIP body) is no longer rejected by a whole-body UTF-8 decode
/// (#1498). The returned slice borrows from `body`, so the caller must
/// hold the body buffer alive for the slice's lifetime.
pub fn extract_multipart_field<'a>(
    body: &'a [u8],
    boundary: &str,
    field: &str,
) -> Option<&'a [u8]> {
    let boundary_marker = format!("--{boundary}");
    let disposition_needle = format!("name=\"{field}\"");

    for (start, end) in split_parts(body, boundary_marker.as_bytes()) {
        let part = body.get(start..end)?;
        // Locate the header/content boundary first; decode ONLY the
        // header block as UTF-8 so binary content never gates the match.
        let Some(sep) = find_bytes(part, b"\r\n\r\n") else {
            continue;
        };
        let header = std::str::from_utf8(part.get(..sep)?).ok()?;
        if !header.contains(&disposition_needle) {
            continue;
        }
        let content_start = start + sep + 4;
        let mut content_end = end;
        // Trim the trailing `\r\n` (and a `\r\n--` if the boundary marker
        // abutted the content) without UTF-8-decoding the payload.
        if body.get(content_end.saturating_sub(2)..content_end) == Some(b"--") {
            content_end = content_end.saturating_sub(2);
        }
        if body.get(content_end.saturating_sub(2)..content_end) == Some(b"\r\n") {
            content_end = content_end.saturating_sub(2);
        }
        return body.get(content_start..content_end.max(content_start));
    }
    None
}

/// Return the `filename="…"` attribute of the first
/// `Content-Disposition` header in `body` that carries one.
///
/// Used for the package's display name when the upload's multipart
/// form does not provide a separate `name` field. Only each part's
/// header block is decoded as UTF-8, so a binary content payload does
/// not block the scan (#1498).
pub fn extract_multipart_filename(body: &[u8], boundary: &str) -> Option<String> {
    let boundary_marker = format!("--{boundary}");
    for (start, end) in split_parts(body, boundary_marker.as_bytes()) {
        let part = body.get(start..end)?;
        // Decode only the header block (up to `\r\n\r\n`, or the whole
        // part when no content separator is present) as UTF-8.
        let header_end = find_bytes(part, b"\r\n\r\n").unwrap_or(part.len());
        let Ok(header) = std::str::from_utf8(part.get(..header_end)?) else {
            continue;
        };
        if let Some(pos) = header.find("filename=\"") {
            let value_start = pos + "filename=\"".len();
            let rest = header.get(value_start..)?;
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
    fn extract_multipart_field_finds_target_in_later_part() {
        // Exercises the offset tracking across multiple parts (#1618): the
        // target field is the second form field, so the returned byte slice is
        // correct only if the running offset accumulated past the first part
        // (the old code re-searched the body for each part instead).
        let boundary = "B";
        let body = "--B\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\nfirst-value\r\n\
                    --B\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nSECOND-PAYLOAD\r\n\
                    --B--\r\n";
        let got = extract_multipart_field(body.as_bytes(), boundary, "file").unwrap();
        assert_eq!(got, b"SECOND-PAYLOAD");
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

    #[test]
    fn extract_multipart_field_accepts_binary_zip_body() {
        // A real ZIP body is binary (the local-file-header magic `PK\x03\x04`
        // plus non-UTF-8 bytes such as 0xFF/0xFE). The previous whole-body
        // UTF-8 decode rejected every genuine upload (#1498); the byte scan
        // must return the raw content verbatim.
        let boundary = "----TEST";
        let mut body = Vec::new();
        body.extend_from_slice(
            b"------TEST\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\nContent-Type: application/zip\r\n\r\n",
        );
        let zip_bytes: &[u8] =
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00\xff\xfe\xfd\xfc\x00\x01\x02\x03";
        body.extend_from_slice(zip_bytes);
        body.extend_from_slice(b"\r\n------TEST--\r\n");

        // The body is not valid UTF-8, proving the scan never decodes content.
        assert!(std::str::from_utf8(&body).is_err());

        let got = extract_multipart_field(&body, boundary, "file").unwrap();
        assert_eq!(got, zip_bytes);

        // The header block still decodes, so the filename is recovered too.
        assert_eq!(
            extract_multipart_filename(&body, boundary).as_deref(),
            Some("a.zip")
        );
    }
}

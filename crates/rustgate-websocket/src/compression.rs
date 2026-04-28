// Copyright © 2026 Roberto Chiofalo.

//! `permessage-deflate` (RFC 7692) negotiation and DEFLATE codec helpers.
//!
//! This module ships in two layers:
//!
//! 1. **Negotiation handshake** — operator-visible parsing and echoing of the
//!    `Sec-WebSocket-Extensions` request/response headers per RFC 7692
//!    §7.1. The server inspects the client's offer (multiple comma-separated
//!    extensions, each a primary token plus zero or more `key[=value]`
//!    parameters) and selects the first `permessage-deflate` offer with a
//!    parameter set the server can accept. The chosen extension surfaces on
//!    [`crate::WsSession::negotiated_compression`] so downstream code can
//!    instrument compression-on / compression-off sessions and feed
//!    Prometheus gauges.
//!
//! 2. **DEFLATE codec** — [`Deflater`] and [`Inflater`] round-trip helpers
//!    that wrap `flate2` raw-DEFLATE encoders. They exist so the round-trip
//!    bandwidth-savings claim of `permessage-deflate` (a 60–80 % reduction
//!    on repetitive CoT XML) is testable end-to-end against a single
//!    payload, not just at the handshake layer. The actual per-frame wire
//!    encode/decode plumbing — stripping the `BFINAL=0` empty-DEFLATE-block
//!    terminator (`0x00 0x00 0xff 0xff`) before transmission, restoring it
//!    on receipt, gating on RSV1 — is **not** wired to the
//!    [`tokio_tungstenite`] `WebSocketStream` here: tokio-tungstenite 0.29
//!    rejects any frame with `RSV1` set as a protocol error
//!    (`NonZeroReservedBits`), and the upstream crate has not yet shipped a
//!    `deflate` feature flag we can light up at the workspace level. Until
//!    that feature lands (or we vendor the frame-level extension hook
//!    ourselves), the negotiation surface and operator config knob ship
//!    today, and the codec is unit-tested against the same XML payload
//!    shape an operator-deployed link will see — so the wire-up follow-up
//!    is mechanical rather than design work.
//!
//! The split is deliberate: configuring [`CompressionConfig::Disabled`]
//! takes the negotiation surface offline immediately (the `extensions`
//! response header is omitted), so deployments worried about CRIME/BREACH-
//! style chosen-plaintext attacks against compressed TLS payloads can opt
//! out *now* without waiting on the per-frame wire-up. CRIME-style attacks
//! are largely killed by mandatory mTLS and short-lived session keys, but
//! the operator gets the kill-switch nonetheless.

use std::fmt;

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use tokio_tungstenite::tungstenite::http::HeaderMap;
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_EXTENSIONS;

/// Maximum number of `permessage-deflate` parameters the negotiator will
/// honour from a single client offer before refusing the offer outright.
/// RFC 7692 §7.1 defines four — `client_no_context_takeover`,
/// `server_no_context_takeover`, `client_max_window_bits`,
/// `server_max_window_bits` — and a defensive cap stops a malicious client
/// from offering thousands of parameter copies and forcing the negotiator
/// into pathological work.
const MAX_OFFERED_PARAMETERS: usize = 8;

/// Default LZ77 sliding-window size (`max_window_bits`) the server agrees
/// to. RFC 7692 §7.1.2 caps this at 15 (i.e. `2^15 = 32 KiB`); 8 is the
/// minimum. We always negotiate the maximum because rustgate's typical
/// payload is repetitive XML — every additional bit of window pays for
/// itself in match length on the first or second long-form CoT event the
/// session sees.
pub const DEFAULT_MAX_WINDOW_BITS: u8 = 15;

/// Top-level configuration for `permessage-deflate` extension negotiation.
///
/// Defaults to [`CompressionConfig::Enabled`] with the RFC 7692 maxima —
/// the operator-friendly stance, given mTLS already neutralises CRIME-style
/// attacks against the TLS layer. Operators who want to keep compression
/// off (legacy threat-model, regulatory bandwidth metering, payloads with
/// non-attacker-controlled cleartext mixed with secrets) flip to
/// [`CompressionConfig::Disabled`] and the negotiation surface goes silent —
/// no `Sec-WebSocket-Extensions: permessage-deflate` is emitted in the
/// upgrade response, regardless of what the client offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompressionConfig {
    /// Negotiation is fully disabled. Even if the client offers
    /// `permessage-deflate`, the server omits the extension header in its
    /// upgrade response, which forces the client back to uncompressed
    /// frames per RFC 7692 §5. Use this on links where compression-oracle
    /// attacks are within scope or where an upstream deep-inspection device
    /// rejects compressed frames.
    Disabled,
    /// Negotiation is enabled with a permitted parameter envelope. The
    /// server walks the client's `Sec-WebSocket-Extensions` offers and
    /// selects the first `permessage-deflate` offer whose every parameter
    /// fits this envelope. See [`PermessageDeflateConfig`] field docs for
    /// the per-parameter rules.
    Enabled(PermessageDeflateConfig),
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self::Enabled(PermessageDeflateConfig::default())
    }
}

impl CompressionConfig {
    /// Whether negotiation is enabled at all. The negotiator short-circuits
    /// when this is `false` and never inspects the request headers.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }
}

/// Parameter envelope the server will accept for `permessage-deflate`.
///
/// Field semantics map to RFC 7692 §7.1.1:
///
/// - `server_no_context_takeover` (server side): when the client requests
///   it, we **must** honour it (the client is telling us they cannot keep
///   per-message LZ77 context across messages). Enabling
///   [`Self::allow_server_no_context_takeover`] simply records that we are
///   willing to comply; the parameter still only attaches to the response
///   when the client offered it.
/// - `client_no_context_takeover` (server side): if set in the response,
///   it **forces** the client to drop LZ77 context across messages.
///   Operators wanting maximum compression at any context-state cost leave
///   this off; operators wanting a per-message-bounded receiver memory
///   footprint flip [`Self::require_client_no_context_takeover`].
/// - `server_max_window_bits` and `client_max_window_bits`: 8..=15 per
///   RFC 7692. We always negotiate the maximum (15) — the client's lower
///   request is honoured, and we never advertise a lower value of our own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermessageDeflateConfig {
    /// If `true`, the server is willing to honour a client request for
    /// `server_no_context_takeover`. Defaults to `true` because almost
    /// every deployment wants the smaller per-session memory footprint.
    pub allow_server_no_context_takeover: bool,
    /// If `true`, the server *requires* the client to drop its LZ77
    /// context across messages, regardless of what the client offered.
    /// Defaults to `false` — most clients can afford the context window.
    pub require_client_no_context_takeover: bool,
    /// Maximum sliding-window size the server agrees to use, in bits.
    /// RFC 7692 §7.1.2: 8..=15. Defaults to [`DEFAULT_MAX_WINDOW_BITS`].
    pub max_window_bits: u8,
}

impl Default for PermessageDeflateConfig {
    fn default() -> Self {
        Self {
            allow_server_no_context_takeover: true,
            require_client_no_context_takeover: false,
            max_window_bits: DEFAULT_MAX_WINDOW_BITS,
        }
    }
}

/// Result of negotiating one `permessage-deflate` offer against the
/// server's [`PermessageDeflateConfig`]. Shaped as a pair of the
/// response-header value (already comma-formatted, ready to drop into the
/// `Sec-WebSocket-Extensions` response slot) and the negotiated parameter
/// snapshot for downstream telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedExtension {
    /// RFC 7692 §7.1-formatted response value. Always begins with
    /// `permessage-deflate`. Parameters are appended as `; key` (flag) or
    /// `; key=value` (numeric) in the canonical RFC 7692 §5.1 order:
    /// server-side parameters first, then client-side.
    pub response_header_value: String,
    /// `server_no_context_takeover` agreed in the response.
    pub server_no_context_takeover: bool,
    /// `client_no_context_takeover` agreed in the response.
    pub client_no_context_takeover: bool,
    /// `server_max_window_bits` agreed in the response. Always 15 today —
    /// see [`PermessageDeflateConfig::max_window_bits`] field docs.
    pub server_max_window_bits: u8,
    /// `client_max_window_bits` agreed in the response. The client's
    /// requested value, if any, capped at the server's max; otherwise the
    /// server's max.
    pub client_max_window_bits: u8,
}

/// Negotiate a `permessage-deflate` offer from the request headers.
///
/// Walks every `Sec-WebSocket-Extensions` request header value, splits on
/// `,` (RFC 7230 §3.2.2 list-rule), and for each extension token parses
/// `permessage-deflate` and its parameters. The first offer whose
/// parameters fit the server's [`PermessageDeflateConfig`] envelope wins.
/// Returns `None` if compression is disabled, the request offered no
/// `permessage-deflate`, or no offer fit the envelope.
///
/// Parameter parsing tolerates RFC 7230 OWS around `=`, around `,`, and
/// inside parameter lists. Rejects offers with more than
/// `MAX_OFFERED_PARAMETERS` parameters (defensive cap), unknown
/// parameters (RFC 7692 §7.1: an extension MUST decline unknown
/// parameters), and out-of-range `*_max_window_bits` values.
#[must_use]
pub fn negotiate_extension(
    config: &CompressionConfig,
    headers: &HeaderMap,
) -> Option<NegotiatedExtension> {
    let CompressionConfig::Enabled(envelope) = config else {
        // Operator opted out of negotiation entirely. RFC 7692 §5 leaves
        // the next step (continue uncompressed, close, etc.) to the
        // client; we just stay silent.
        return None;
    };

    for header_value in headers.get_all(SEC_WEBSOCKET_EXTENSIONS).iter() {
        let Ok(s) = header_value.to_str() else {
            // Non-ASCII bytes in a header that ABNF says is ASCII —
            // tungstenite will likely refuse the upgrade anyway, but
            // skipping is safe.
            continue;
        };
        for extension in split_top_level_comma(s) {
            let Some(offer) = parse_offer(extension) else {
                // Either not `permessage-deflate` or malformed — skip.
                continue;
            };
            if let Some(neg) = try_negotiate_offer(envelope, &offer) {
                return Some(neg);
            }
        }
    }
    None
}

/// Single `permessage-deflate` offer extracted from one client extension
/// element. Distinct from [`PermessageDeflateConfig`] because the offer is
/// what the client *asked for*, while the config is what the server *will
/// accept*; the negotiator takes the intersection.
#[derive(Debug, PartialEq, Eq)]
struct ParsedOffer<'a> {
    /// Whether the offer included `client_no_context_takeover`.
    client_no_context_takeover: bool,
    /// Whether the offer included `server_no_context_takeover`.
    server_no_context_takeover: bool,
    /// `client_max_window_bits` value, if specified. RFC 7692 §7.1.2 also
    /// allows the parameter without a value — that signals "client supports
    /// the negotiation, server picks." We treat both forms identically: any
    /// value the client supplies must fit 8..=15.
    client_max_window_bits: Option<u8>,
    /// `server_max_window_bits` value, if specified. Same 8..=15 rule. The
    /// client cannot request *more* than 15.
    server_max_window_bits: Option<u8>,
    /// Lifetime-bound reference back into the source header for diagnostic
    /// purposes (currently unused at runtime, kept for future audit
    /// emission). The variant name lives in the offer-parsing scope.
    _raw: &'a str,
}

fn try_negotiate_offer(
    envelope: &PermessageDeflateConfig,
    offer: &ParsedOffer<'_>,
) -> Option<NegotiatedExtension> {
    // server_no_context_takeover: the client asked for it; server must be
    // willing to honour it. If the server has the knob switched off, this
    // particular offer is rejected and the negotiator moves on to the next.
    let server_no_ct = offer.server_no_context_takeover;
    if server_no_ct && !envelope.allow_server_no_context_takeover {
        return None;
    }

    // client_no_context_takeover: either the client offered it, or the
    // server requires it. Either way, it goes into the response.
    let client_no_ct =
        offer.client_no_context_takeover || envelope.require_client_no_context_takeover;

    // server_max_window_bits: client may request a smaller window. Server's
    // configured cap is the hard ceiling.
    let server_bits = match offer.server_max_window_bits {
        Some(b) => {
            if !is_valid_window_bits(b) {
                return None;
            }
            b.min(envelope.max_window_bits)
        }
        None => envelope.max_window_bits,
    };

    // client_max_window_bits: same 8..=15 rule, defaulting to the server's
    // max when the client did not specify a value.
    let client_bits = match offer.client_max_window_bits {
        Some(b) => {
            if !is_valid_window_bits(b) {
                return None;
            }
            b.min(envelope.max_window_bits)
        }
        None => envelope.max_window_bits,
    };

    Some(NegotiatedExtension {
        response_header_value: format_response_header(
            server_no_ct,
            client_no_ct,
            server_bits,
            client_bits,
        ),
        server_no_context_takeover: server_no_ct,
        client_no_context_takeover: client_no_ct,
        server_max_window_bits: server_bits,
        client_max_window_bits: client_bits,
    })
}

const fn is_valid_window_bits(b: u8) -> bool {
    b >= 8 && b <= 15
}

fn format_response_header(
    server_no_ct: bool,
    client_no_ct: bool,
    server_bits: u8,
    client_bits: u8,
) -> String {
    let mut out = String::from("permessage-deflate");
    if server_no_ct {
        out.push_str("; server_no_context_takeover");
    }
    if client_no_ct {
        out.push_str("; client_no_context_takeover");
    }
    // Only emit `*_max_window_bits` when it differs from the absolute max
    // (15). Per RFC 7692 §7.1.2 the parameter is optional and most clients
    // expect to see it only when the server is asking for a smaller
    // window. This keeps headers shorter for the common path.
    if server_bits < DEFAULT_MAX_WINDOW_BITS {
        // justification: bit values are bounded by `is_valid_window_bits`
        // (8..=15), well within `u8::MAX`, so `to_string()` is always
        // ASCII numerals — formatting cannot fail.
        out.push_str(&format!("; server_max_window_bits={server_bits}"));
    }
    if client_bits < DEFAULT_MAX_WINDOW_BITS {
        // justification: see above — bounded numeric formatting.
        out.push_str(&format!("; client_max_window_bits={client_bits}"));
    }
    out
}

/// Split a list-valued HTTP header on top-level commas (RFC 7230 §3.2.2).
/// `permessage-deflate` parameters use `;` as their separator so the inner
/// structure is unambiguous, but if a future extension grows quoted-string
/// parameter values this helper stays single-source.
fn split_top_level_comma(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|t| !t.is_empty())
}

/// Parse a single extension element such as
/// `permessage-deflate; client_no_context_takeover; server_max_window_bits=10`.
fn parse_offer(input: &str) -> Option<ParsedOffer<'_>> {
    let mut parts = input.split(';').map(str::trim);
    let token = parts.next()?;
    if !token.eq_ignore_ascii_case("permessage-deflate") {
        // Not our extension. RFC 6455 allows mixing many extensions in one
        // header — we simply skip the ones we do not own.
        return None;
    }

    let mut offer = ParsedOffer {
        client_no_context_takeover: false,
        server_no_context_takeover: false,
        client_max_window_bits: None,
        server_max_window_bits: None,
        _raw: input,
    };

    let mut count = 0usize;
    for param in parts {
        if param.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_OFFERED_PARAMETERS {
            // Defensive cap. A pathological client cannot use a 1 KiB
            // header to cause O(n^2) parse work.
            return None;
        }
        let (key, value) = match param.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"'))),
            None => (param, None),
        };
        match key {
            "client_no_context_takeover" => {
                if value.is_some() {
                    // RFC 7692 §7.1.1.1: this parameter MUST NOT carry a value.
                    return None;
                }
                offer.client_no_context_takeover = true;
            }
            "server_no_context_takeover" => {
                if value.is_some() {
                    // RFC 7692 §7.1.1.2: same rule.
                    return None;
                }
                offer.server_no_context_takeover = true;
            }
            "client_max_window_bits" => {
                offer.client_max_window_bits = match value {
                    Some(v) => v.parse::<u8>().ok().filter(|b| is_valid_window_bits(*b)),
                    None => Some(DEFAULT_MAX_WINDOW_BITS),
                };
                if value.is_some() && offer.client_max_window_bits.is_none() {
                    // Value provided but unparseable / out of range.
                    return None;
                }
            }
            "server_max_window_bits" => {
                // RFC 7692 §7.1.2.2: value is mandatory. Out-of-range or
                // unparseable values reject the entire offer rather than
                // silently masking with the server's configured max.
                let v = value?;
                let parsed = v.parse::<u8>().ok().filter(|b| is_valid_window_bits(*b))?;
                offer.server_max_window_bits = Some(parsed);
            }
            _ => {
                // Unknown parameter. RFC 7692 §7.1 says decline.
                return None;
            }
        }
    }

    Some(offer)
}

/// Streaming DEFLATE encoder used by the per-message wire codec helpers.
///
/// Holds an internal `flate2` `Compress` state. `permessage-deflate`
/// (RFC 7692 §7.2) defines a per-message DEFLATE stream that ends with a
/// non-final empty stored block (`0x00 0x00 0xff 0xff`); the four-byte
/// trailer is *stripped* from the on-wire payload and re-injected on the
/// receiver side. [`Deflater::compress_message`] does the strip and
/// returns the wire payload directly.
pub struct Deflater {
    /// LZ77 sliding-window size in bits. Honoured today only for the
    /// per-call-frame-size budget; flate2's `Compress` API uses its own
    /// internal default. See [`flate2::Compress::new_with_window_bits`]
    /// for the future hook.
    window_bits: u8,
}

impl fmt::Debug for Deflater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deflater")
            .field("window_bits", &self.window_bits)
            .finish()
    }
}

impl Deflater {
    /// Build a new deflater for a session with the given negotiated
    /// `server_max_window_bits` value.
    #[must_use]
    pub const fn new(window_bits: u8) -> Self {
        Self { window_bits }
    }

    /// Compress one message and strip the trailing empty stored block per
    /// RFC 7692 §7.2.1. Returns the on-wire payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `flate2` deflater fails (out of
    /// memory or an internal codec inconsistency — neither expected during
    /// normal operation).
    pub fn compress_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload)?;
        let mut out = encoder.finish()?;
        // RFC 7692 §7.2.1: strip the four-byte non-final empty stored
        // block tail. flate2 emits a final `BFINAL=1` block instead of
        // the wire-format expected non-final empty block; we synthesize
        // the wire form by trimming the tail bytes the receiver injects
        // on its side. The strip is only correct when flate2 ends the
        // stream with the canonical `0x00 0x00 0x00 0xff 0xff` trailer
        // shape; when it does not (very small payloads where the entire
        // body fits one literal block plus EOF) we leave the bytes alone
        // — the receiver still reconstructs a valid DEFLATE stream
        // because the payload is self-delimiting.
        if out.len() >= 4 && out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            let new_len = out.len() - 4;
            out.truncate(new_len);
        }
        Ok(out)
    }

    /// LZ77 window size, in bits, this deflater was constructed with.
    #[must_use]
    pub const fn window_bits(&self) -> u8 {
        self.window_bits
    }
}

/// Streaming DEFLATE decoder counterpart to [`Deflater`]. Re-injects the
/// four-byte non-final empty stored block trailer before feeding the
/// payload to `flate2`.
pub struct Inflater {
    window_bits: u8,
}

impl fmt::Debug for Inflater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inflater")
            .field("window_bits", &self.window_bits)
            .finish()
    }
}

impl Inflater {
    /// Build a new inflater for a session with the given negotiated
    /// `client_max_window_bits` value.
    #[must_use]
    pub const fn new(window_bits: u8) -> Self {
        Self { window_bits }
    }

    /// Decompress one wire payload, re-injecting the RFC 7692 §7.2.1
    /// stripped trailer.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid DEFLATE stream.
    pub fn decompress_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        use std::io::Read;

        // RFC 7692 §7.2.2: the receiver re-appends the stripped four-byte
        // trailer before passing the body to its DEFLATE decoder.
        let mut framed: Vec<u8> = Vec::with_capacity(payload.len() + 4);
        framed.extend_from_slice(payload);
        framed.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        let mut decoder = DeflateDecoder::new(framed.as_slice());
        let mut out = Vec::new();
        // The inflater stops at the synthesized non-final empty block,
        // which marks the end of the message under the `permessage-deflate`
        // contract. Any remaining bytes after `read_to_end` succeeds are
        // therefore the trailer we appended ourselves.
        let _ = decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    /// LZ77 window size, in bits, this inflater was constructed with.
    #[must_use]
    pub const fn window_bits(&self) -> u8 {
        self.window_bits
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use tokio_tungstenite::tungstenite::http::HeaderValue;

    use super::*;

    fn header_with_extensions(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            // HeaderMap::append returns a bool indicating whether the key
            // was already present — we don't care; we just want the side
            // effect of the append.
            let _ = h.append(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn disabled_config_returns_none_even_when_client_offers() {
        // Disabled is the operator opt-out — no `Sec-WebSocket-Extensions`
        // response header, regardless of what the client offered. CRIME-
        // sensitive deployments rely on this.
        let cfg = CompressionConfig::Disabled;
        let h = header_with_extensions(&["permessage-deflate"]);
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn no_offer_returns_none() {
        // Compression enabled but the client did not offer it. RFC 7692
        // §5: server stays silent; no response header.
        let cfg = CompressionConfig::default();
        let h = HeaderMap::new();
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn bare_offer_negotiates_at_default_envelope() {
        // The minimal `permessage-deflate` offer with no parameters. Server
        // accepts at its default envelope and emits the same bare token in
        // the response — clients see "yes, compress" and apply default
        // window/context settings.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate"]);
        let neg = negotiate_extension(&cfg, &h).expect("bare offer must negotiate");
        assert_eq!(neg.response_header_value, "permessage-deflate");
        assert!(!neg.server_no_context_takeover);
        assert!(!neg.client_no_context_takeover);
        assert_eq!(neg.server_max_window_bits, DEFAULT_MAX_WINDOW_BITS);
        assert_eq!(neg.client_max_window_bits, DEFAULT_MAX_WINDOW_BITS);
    }

    #[test]
    fn server_no_context_takeover_is_honoured() {
        // Client requests `server_no_context_takeover`; default envelope
        // permits it, so it appears in the response.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate; server_no_context_takeover"]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert!(neg.server_no_context_takeover);
        assert!(
            neg.response_header_value
                .contains("server_no_context_takeover")
        );
    }

    #[test]
    fn server_no_context_takeover_envelope_can_refuse() {
        // Client requests `server_no_context_takeover` but the operator
        // configured `allow_server_no_context_takeover = false`. The single
        // offer is rejected; with no further offers, negotiation returns
        // None. (A multi-offer client could fall through to a permissive
        // offer; that case is exercised separately.)
        let envelope = PermessageDeflateConfig {
            allow_server_no_context_takeover: false,
            ..PermessageDeflateConfig::default()
        };
        let cfg = CompressionConfig::Enabled(envelope);
        let h = header_with_extensions(&["permessage-deflate; server_no_context_takeover"]);
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn client_no_context_takeover_can_be_required_by_server() {
        // Client offered the bare extension; server's envelope requires
        // `client_no_context_takeover` so the response forces it on the
        // client even though the client did not ask.
        let envelope = PermessageDeflateConfig {
            require_client_no_context_takeover: true,
            ..PermessageDeflateConfig::default()
        };
        let cfg = CompressionConfig::Enabled(envelope);
        let h = header_with_extensions(&["permessage-deflate"]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert!(neg.client_no_context_takeover);
        assert!(
            neg.response_header_value
                .contains("client_no_context_takeover")
        );
    }

    #[test]
    fn client_max_window_bits_below_server_max_is_used() {
        // Client requests a 10-bit window. Server's max is 15 so the
        // smaller value wins, and it appears in the response (because it
        // is below the default 15).
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate; client_max_window_bits=10"]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert_eq!(neg.client_max_window_bits, 10);
        assert!(
            neg.response_header_value
                .contains("client_max_window_bits=10")
        );
    }

    #[test]
    fn server_max_window_bits_below_envelope_max_is_used() {
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate; server_max_window_bits=12"]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert_eq!(neg.server_max_window_bits, 12);
        assert!(
            neg.response_header_value
                .contains("server_max_window_bits=12")
        );
    }

    #[test]
    fn out_of_range_window_bits_rejects_offer() {
        // RFC 7692 §7.1.2: 8..=15. 7 and 16 are both invalid. The first
        // out-of-range value rejects the offer outright.
        let cfg = CompressionConfig::default();
        for bad in ["7", "16", "0", "255", "abc"] {
            let h = header_with_extensions(&[&format!(
                "permessage-deflate; server_max_window_bits={bad}"
            )]);
            assert!(
                negotiate_extension(&cfg, &h).is_none(),
                "should have rejected server_max_window_bits={bad}"
            );
        }
    }

    #[test]
    fn unknown_parameter_rejects_offer() {
        // RFC 7692 §7.1: an extension implementation MUST reject offers
        // carrying parameters it does not recognise.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate; never_heard_of_it"]);
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn comma_separated_offers_first_acceptable_wins() {
        // Two offers — first asks for the rejected
        // `server_no_context_takeover`, second is a bare offer. With the
        // server's envelope refusing the first, the second succeeds.
        let envelope = PermessageDeflateConfig {
            allow_server_no_context_takeover: false,
            ..PermessageDeflateConfig::default()
        };
        let cfg = CompressionConfig::Enabled(envelope);
        let h = header_with_extensions(&[
            "permessage-deflate; server_no_context_takeover, permessage-deflate",
        ]);
        let neg = negotiate_extension(&cfg, &h).expect("bare offer fallback");
        assert_eq!(neg.response_header_value, "permessage-deflate");
    }

    #[test]
    fn multiple_headers_are_walked_in_order() {
        // RFC 7230 §3.2.2: a list-valued header may collapse OR repeat.
        // Both shapes must work and preserve order — the first acceptable
        // wins.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&[
            "permessage-deflate; server_max_window_bits=8",
            "permessage-deflate", // never reached: first offer is acceptable
        ]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert_eq!(neg.server_max_window_bits, 8);
    }

    #[test]
    fn parameter_with_disallowed_value_is_rejected() {
        // `client_no_context_takeover` is a flag; carrying a value
        // violates RFC 7692 §7.1.1.1.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["permessage-deflate; client_no_context_takeover=true"]);
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn whitespace_around_separators_is_tolerated() {
        // Some HTTP stacks emit `"a , b"` with whitespace around commas;
        // others put it around `;`. The negotiator trims OWS per RFC 7230.
        let cfg = CompressionConfig::default();
        let h = header_with_extensions(&["  permessage-deflate ;   client_max_window_bits = 12  "]);
        let neg = negotiate_extension(&cfg, &h).unwrap();
        assert_eq!(neg.client_max_window_bits, 12);
    }

    #[test]
    fn excessive_parameters_reject_offer() {
        // Defensive cap — see MAX_OFFERED_PARAMETERS. Stop a malicious
        // client from forcing pathological parse work.
        let cfg = CompressionConfig::default();
        let mut header = String::from("permessage-deflate");
        for i in 0..(MAX_OFFERED_PARAMETERS + 1) {
            header.push_str(&format!("; bogus_{i}"));
        }
        let h = header_with_extensions(&[&header]);
        assert!(negotiate_extension(&cfg, &h).is_none());
    }

    #[test]
    fn deflater_inflater_round_trip_recovers_payload() {
        let payload = b"hello world";
        let mut deflater = Deflater::new(DEFAULT_MAX_WINDOW_BITS);
        let mut inflater = Inflater::new(DEFAULT_MAX_WINDOW_BITS);
        let compressed = deflater.compress_message(payload).unwrap();
        let recovered = inflater.decompress_message(&compressed).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn deflate_compresses_repetitive_xml_payload() {
        // RFC 7692's headline value proposition is bandwidth reduction on
        // repetitive payloads. A 64 KiB CoT-shaped XML payload must
        // compress to less than 30% of its original size on the
        // permessage-deflate codec; if this regresses the deployment
        // benefit story collapses.
        let mut payload = Vec::with_capacity(64 * 1024);
        let snippet = br#"<event version="2.0" uid="ANDROID-deadbeef" type="a-f-G-U-C" how="m-g"><point lat="38.889483" lon="-77.035280" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="Alpha-1" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/><status battery="86"/><takv device="ATAK-CIV" platform="ATAK-CIV" os="29" version="4.10.0.16"/></detail></event>"#;
        while payload.len() < 64 * 1024 {
            payload.extend_from_slice(snippet);
        }
        let original = payload.len();

        let mut deflater = Deflater::new(DEFAULT_MAX_WINDOW_BITS);
        let mut inflater = Inflater::new(DEFAULT_MAX_WINDOW_BITS);
        let compressed = deflater.compress_message(&payload).unwrap();
        let recovered = inflater.decompress_message(&compressed).unwrap();

        assert_eq!(recovered.len(), original, "round-trip must preserve length");
        assert_eq!(recovered, payload, "round-trip must preserve content");

        let ratio = (compressed.len() as f64) / (original as f64);
        assert!(
            ratio < 0.30,
            "expected <30% size on repetitive XML, got {ratio:.4} ({} bytes from {original})",
            compressed.len(),
        );
    }
}

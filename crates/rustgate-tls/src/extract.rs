// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! X.509 certificate parsing and identity extraction.

use std::collections::{BTreeMap, BTreeSet};

use rustgate_core::error::{Result, RustgateError, TransportError};
use rustgate_core::identity::{AttrValue, Identity};
use rustgate_core::revocation;
use rustgate_core::sanitize::sanitize_for_log;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tracing::warn;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_EXT_EXTENDED_KEY_USAGE,
    OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
};
use x509_parser::prelude::*;

/// Per-category SAN count cap. RFC 5280 does not bound the number of
/// `subjectAltName` entries, and an adversarial or misconfigured CA
/// could issue a cert with thousands of SANs that would bloat the
/// resident memory of every session and dominate the cost of every
/// subsequent `Subject::compute_hash` on the dataplane hot path.
///
/// 32 is deliberately generous for legitimate SPIFFE / multi-domain
/// deployments (a single cert rarely names more than a handful of
/// hosts) while small enough to bound the amplification.
const MAX_SAN_ENTRIES_PER_CATEGORY: usize = 32;

/// Total per-identity attribute-bag byte budget. Once cumulative
/// key+value bytes exceed this, further SAN entries are dropped and a
/// warning is emitted on the `authz` target. The threshold is a soft
/// ceiling: small overshoots are acceptable because the check runs
/// after each insertion, not per-byte.
const MAX_ATTR_BAG_BYTES: usize = 4 * 1024;

/// Most issuer certificates recorded per session for revocation matching.
/// Real chains have one or two intermediates; cross-signed ones a few more.
const MAX_CHAIN_REVOCATION_KEYS: usize = 32;

/// Most signature verifications spent rebuilding issuer paths, the same as
/// webpki's default per-handshake signature budget.
const MAX_PATH_SIGNATURE_CHECKS: usize = 100;

/// Extract identity from a presented chain: the leaf ([`extract_identity`])
/// plus the `(issuer, serial)` revocation key of every CA certificate that is
/// on some issuer path from the leaf, so the revocation sweep can evict
/// sessions whose intermediate is revoked (ADR 0025).
///
/// The client controls which extra certificates it sends and in what order,
/// so a certificate is recorded only when its key verifies the signature of a
/// certificate already on a path, and every such branch is followed. The
/// search is complete within its limits (100 signature verifications, 32
/// recorded certificates); a chain that exceeds them is rejected
/// rather than recorded partially, so padding or self-signed twins cannot
/// hide the copy of an intermediate that chains to the trust anchor. A
/// session with a valid alternate path through a revoked certificate is
/// evicted too (fail-closed).
///
/// # Errors
///
/// Fails like [`extract_identity`], and when the chain exceeds the search
/// limits.
pub fn extract_identity_with_chain(chain: &[CertificateDer<'_>]) -> Result<Identity> {
    let leaf = chain.first().ok_or(TransportError::EmptyCertChain)?;
    let identity = extract_identity(leaf)?;

    let keys = issuer_path_keys(chain).ok_or_else(|| {
        RustgateError::from(TransportError::Other(
            "client certificate chain is too large to check for revocation".to_string(),
        ))
    })?;
    if keys.is_empty() {
        return Ok(identity);
    }
    let mut attrs = (*identity.attributes).clone();
    let _ = attrs.insert(
        revocation::ATTR_CHAIN_REVOCATION_KEYS.to_string(),
        AttrValue::Set(keys),
    );
    Ok(identity.with_attributes(attrs))
}

/// Breadth-first search up from the leaf through the presented
/// certificates. A certificate joins the search when its subject is the
/// issuer of a certificate already found and its key verifies that
/// certificate's signature. Returns the revocation key of each one found, or
/// `None` when the search hit a limit before it finished.
fn issuer_path_keys(chain: &[CertificateDer<'_>]) -> Option<Vec<String>> {
    let Some(provider) = rustls::crypto::CryptoProvider::get_default() else {
        return Some(Vec::new());
    };
    let algs = provider.signature_verification_algorithms.all;
    let Some(Ok((_, leaf))) = chain.first().map(|d| X509Certificate::from_der(d.as_ref())) else {
        return Some(Vec::new());
    };
    // Byte-identical copies add nothing; drop them so a client that repeats
    // a certificate is not charged for it.
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    let pool: Vec<X509Certificate<'_>> = chain
        .iter()
        .skip(1)
        .filter(|&d| seen.insert(d.as_ref()))
        .filter_map(|d| X509Certificate::from_der(d.as_ref()).ok().map(|(_, c)| c))
        .collect();

    let mut found = vec![false; pool.len()];
    let mut budget = MAX_PATH_SIGNATURE_CHECKS;
    let mut keys = Vec::new();
    let mut queue = std::collections::VecDeque::from([&leaf]);
    while let Some(current) = queue.pop_front() {
        for (i, candidate) in pool.iter().enumerate() {
            if found[i] || candidate.subject().as_raw() != current.issuer().as_raw() {
                continue;
            }
            match signed_by(current, candidate, algs, &mut budget) {
                Some(true) => {}
                Some(false) => continue,
                None => return None,
            }
            found[i] = true;
            if let Some(issuer) = first_issuer_cn(candidate) {
                keys.push(revocation::chain_key(
                    &revocation::canonical_issuer(&issuer),
                    &revocation::serial_hex(&candidate.tbs_certificate.serial.to_bytes_be()),
                ));
                if keys.len() > MAX_CHAIN_REVOCATION_KEYS {
                    return None;
                }
            }
            queue.push_back(candidate);
        }
    }
    Some(keys)
}

/// Whether `issuer`'s key verifies `child`'s signature, trying the installed
/// provider's algorithms that match both the signature and key algorithm.
/// Each verification spends one unit of `budget`; `None` once it runs out.
fn signed_by(
    child: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    algs: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm],
    budget: &mut usize,
) -> Option<bool> {
    let (Some(sig_oid), Some(key_oid)) = (
        oid_tlv(&child.signature_algorithm.algorithm),
        oid_tlv(&issuer.public_key().algorithm.algorithm),
    ) else {
        return Some(false);
    };
    let public_key = &issuer.public_key().subject_public_key.data;
    let message = child.tbs_certificate.as_ref();
    let signature = &child.signature_value.data;
    for alg in algs.iter().filter(|alg| {
        alg.signature_alg_id().as_ref().starts_with(&sig_oid)
            && alg.public_key_alg_id().as_ref().starts_with(&key_oid)
    }) {
        *budget = budget.checked_sub(1)?;
        if alg.verify_signature(public_key, message, signature).is_ok() {
            return Some(true);
        }
    }
    Some(false)
}

/// DER encoding of an OID (tag, length, value), the prefix of an
/// AlgorithmIdentifier's contents. `None` for an OID too long for a
/// short-form length, which no supported algorithm uses.
fn oid_tlv(oid: &x509_parser::der_parser::oid::Oid<'_>) -> Option<Vec<u8>> {
    let value = oid.as_bytes();
    let len = u8::try_from(value.len()).ok().filter(|l| *l < 0x80)?;
    let mut tlv = Vec::with_capacity(value.len() + 2);
    tlv.push(0x06);
    tlv.push(len);
    tlv.extend_from_slice(value);
    Some(tlv)
}

/// The first issuer CN that is a plain string type.
fn first_issuer_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.issuer().iter_rdn().find_map(|rdn| {
        rdn.iter().find_map(|attr| {
            (attr.attr_type() == &OID_X509_COMMON_NAME)
                .then(|| attr.attr_value().as_str().ok().map(str::to_string))
                .flatten()
        })
    })
}

/// Extract identity from an X.509 certificate.
///
/// Parses the certificate DER and extracts:
/// - CN (Common Name) → `Identity.cn`
/// - OU (Organizational Unit) fields → `Identity.groups`
/// - SHA-256 fingerprint → `Identity.fingerprint`
pub fn extract_identity(cert_der: &CertificateDer<'_>) -> Result<Identity> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| TransportError::Other(format!("failed to parse X.509 certificate: {e}")))?;

    let cn = sanitize_for_log(&extract_cn(&cert)?);
    let groups = extract_groups(&cert)
        .into_iter()
        .map(|g| sanitize_for_log(&g))
        .collect();
    let fingerprint = compute_fingerprint(cert_der);

    let (attributes, spiffe_id) = extract_attributes(&cert, cert_der);

    let tenant =
        first_subject_attr(&cert, &OID_X509_ORGANIZATION_NAME).map(|o| sanitize_for_log(&o));

    let mut identity = Identity::new(cn, fingerprint, groups).map_err(|e| {
        RustgateError::from(TransportError::Other(format!(
            "invalid identity from certificate: {e}"
        )))
    })?;
    identity = identity.with_attributes(attributes);
    if let Some(tenant) = tenant {
        identity = identity.with_tenant(tenant);
    }
    if let Some(spiffe) = spiffe_id {
        identity = identity.with_spiffe_id(spiffe);
    }
    Ok(identity)
}

/// Extract ABAC attributes and (optionally) a SPIFFE ID from a parsed cert.
///
/// Never fails: missing SANs / subject fields simply yield an empty map.
/// The returned map is populated with the following keys when data is
/// present:
///
/// - `spiffe_id` (Str) — first URI SAN starting with `spiffe://`
/// - `san_dns` (Set) — all DNS SANs, sorted and deduplicated
/// - `san_email` (Set) — all RFC822 SANs, sorted and deduplicated
/// - `san_uri` (Set) — all URI SANs, sorted and deduplicated
/// - `org` (Str) — first subject O (organizationName) value
/// - `country` (Str) — first subject C (countryName) value
/// - `issuer_cn` (Str) — first issuer CN value
/// - `cert_serial` (Str) — certificate serial number as lowercase hex,
///   two hex chars per byte of its minimal big-endian magnitude, with no
///   `0x` prefix (see [`rustgate_core::revocation::serial_hex`]). A
///   one-byte serial `0x01` formats as `"01"`, not `"1"`. The `0x00` that
///   DER prepends to a serial with its high bit set is not included, so a
///   policy rule comparing `cert_serial` with string equality must use the
///   same format. CRL entries are encoded identically for revocation.
/// - `cert_not_after` (Int) — certificate `notAfter` as Unix seconds
fn extract_attributes(
    cert: &X509Certificate<'_>,
    cert_der: &CertificateDer<'_>,
) -> (BTreeMap<String, AttrValue>, Option<String>) {
    let mut attrs: BTreeMap<String, AttrValue> = BTreeMap::new();
    let mut spiffe_id: Option<String> = None;

    // Subject organization (O).
    if let Some(org) = first_subject_attr(cert, &OID_X509_ORGANIZATION_NAME) {
        let _ = attrs.insert("org".to_string(), AttrValue::Str(sanitize_for_log(&org)));
    }
    // Subject country (C).
    if let Some(country) = first_subject_attr(cert, &OID_X509_COUNTRY_NAME) {
        let _ = attrs.insert(
            "country".to_string(),
            AttrValue::Str(sanitize_for_log(&country)),
        );
    }
    // Issuer CN and serial use the shared revocation encoding so the
    // revocation sweep can match them against CRL entries (ADR 0025).
    if let Some(cn) = first_issuer_cn(cert) {
        let _ = attrs.insert(
            revocation::ATTR_ISSUER_CN.to_string(),
            AttrValue::Str(revocation::canonical_issuer(&cn)),
        );
    }

    // Certificate serial (lowercase hex of the big-endian magnitude).
    let serial_hex = revocation::serial_hex(&cert.tbs_certificate.serial.to_bytes_be());
    let _ = attrs.insert(
        revocation::ATTR_CERT_SERIAL.to_string(),
        AttrValue::Str(serial_hex),
    );

    // Certificate notAfter as Unix seconds, for expiry-based eviction.
    // `timestamp()` is already an i64 for any representable ASN.1 time
    // (pre-1970 and post-2050 GeneralizedTime included), so no clamp or
    // fallible conversion is needed.
    let _ = attrs.insert(
        revocation::ATTR_CERT_NOT_AFTER.to_string(),
        AttrValue::Int(cert.validity().not_after.timestamp()),
    );

    // SAN extension — URI / DNS / email.
    //
    // Counts are capped at `MAX_SAN_ENTRIES_PER_CATEGORY` and the total
    // attribute-bag byte footprint is capped at `MAX_ATTR_BAG_BYTES`.
    // The caps are defensive: the X.509 spec places no upper bound on
    // the SAN list, and an adversarial CA could ship a cert with
    // thousands of SANs that would bloat session memory and dominate
    // `Subject::compute_hash` on every hot-path evaluation. Overflow
    // is dropped silently after a single warn! — we never refuse the
    // handshake because a SPIFFE-style cert with many URIs is
    // legitimate up to our generous limit.
    if let Ok(exts) = cert.extensions_map()
        && let Some(ext) = exts.get(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
    {
        let mut dns_names: Vec<String> = Vec::new();
        let mut emails: Vec<String> = Vec::new();
        let mut uris: Vec<String> = Vec::new();
        let mut dns_overflow = false;
        let mut email_overflow = false;
        let mut uri_overflow = false;
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(s) => {
                    if dns_names.len() < MAX_SAN_ENTRIES_PER_CATEGORY {
                        dns_names.push(sanitize_for_log(s));
                    } else {
                        dns_overflow = true;
                    }
                }
                GeneralName::RFC822Name(s) => {
                    if emails.len() < MAX_SAN_ENTRIES_PER_CATEGORY {
                        emails.push(sanitize_for_log(s));
                    } else {
                        email_overflow = true;
                    }
                }
                GeneralName::URI(s) => {
                    let sanitized = sanitize_for_log(s);
                    // SPIFFE ID extraction: only accept URIs that pass the
                    // canonicalizer/validator (RFC 3986 scheme "spiffe",
                    // valid trust-domain charset, non-empty path). A
                    // malformed SPIFFE-looking URI is treated as a plain
                    // URI SAN — we still record it under `san_uri`, but it
                    // will not populate `Identity.spiffe_id` and cannot
                    // match a `spiffe_prefix` policy rule.
                    //
                    // SPIFFE ID discovery runs regardless of the cap so a
                    // URI list that exceeds the cap cannot hide the
                    // first valid SPIFFE entry behind cap-induced
                    // truncation.
                    if spiffe_id.is_none()
                        && let Some(canonical) = canonicalize_spiffe_id(&sanitized)
                    {
                        spiffe_id = Some(canonical);
                    }
                    if uris.len() < MAX_SAN_ENTRIES_PER_CATEGORY {
                        uris.push(sanitized);
                    } else {
                        uri_overflow = true;
                    }
                }
                _ => {}
            }
        }
        if dns_overflow || email_overflow || uri_overflow {
            warn!(
                target: "authz",
                cap = MAX_SAN_ENTRIES_PER_CATEGORY,
                dns_overflow,
                email_overflow,
                uri_overflow,
                "cert SAN count exceeds per-category cap; extra entries dropped"
            );
        }
        if !dns_names.is_empty() {
            dns_names.sort();
            dns_names.dedup();
            insert_if_within_budget(&mut attrs, "san_dns", AttrValue::Set(dns_names));
        }
        if !emails.is_empty() {
            emails.sort();
            emails.dedup();
            insert_if_within_budget(&mut attrs, "san_email", AttrValue::Set(emails));
        }
        if !uris.is_empty() {
            uris.sort();
            uris.dedup();
            insert_if_within_budget(&mut attrs, "san_uri", AttrValue::Set(uris));
        }
    }

    if let Some(ref id) = spiffe_id {
        let _ = attrs.insert("spiffe_id".to_string(), AttrValue::Str(id.clone()));
    }

    let _ = cert_der; // reserved for future use (e.g. SKI).
    (attrs, spiffe_id)
}

/// Estimate the heap footprint of an attribute value for budget
/// accounting. This is deliberately loose: it counts UTF-8 byte lengths
/// and a small per-entry constant, which is close enough to the
/// in-memory footprint for the purpose of a "don't let a misbehaving
/// cert bloat the session" cap.
fn attr_byte_cost(key: &str, value: &AttrValue) -> usize {
    const PER_ENTRY_OVERHEAD: usize = 16;
    let value_bytes = match value {
        AttrValue::Str(s) => s.len(),
        AttrValue::Int(_) => std::mem::size_of::<i64>(),
        AttrValue::Bool(_) => 1,
        AttrValue::Set(items) => items
            .iter()
            .map(|s| s.len() + PER_ENTRY_OVERHEAD)
            .sum::<usize>(),
    };
    key.len() + value_bytes + PER_ENTRY_OVERHEAD
}

/// Sum the byte cost of an attribute map.
fn current_bag_bytes(attrs: &BTreeMap<String, AttrValue>) -> usize {
    attrs.iter().map(|(k, v)| attr_byte_cost(k, v)).sum()
}

/// Insert an attribute iff it fits within `MAX_ATTR_BAG_BYTES`. If the
/// candidate entry would push the bag over the budget, emit a single
/// warning and drop it. This is the "last line of defence" for the
/// attribute bag size — per-category SAN count caps already bound the
/// common case; this catches pathological individual values (e.g. a
/// single enormous URI SAN).
fn insert_if_within_budget(attrs: &mut BTreeMap<String, AttrValue>, key: &str, value: AttrValue) {
    let cost = attr_byte_cost(key, &value);
    let current = current_bag_bytes(attrs);
    if current + cost > MAX_ATTR_BAG_BYTES {
        warn!(
            target: "authz",
            key,
            candidate_bytes = cost,
            current_bytes = current,
            budget = MAX_ATTR_BAG_BYTES,
            "cert attribute bag would exceed byte budget; dropping entry"
        );
        return;
    }
    let _ = attrs.insert(key.to_string(), value);
}

/// Canonicalize a SPIFFE ID per the [SPIFFE ID spec][spec].
///
/// Per the spec, the scheme (`spiffe`) and the trust-domain authority are
/// **case-insensitive** while the path is **case-sensitive**. Trust-domain
/// names may contain only lowercase ASCII letters, digits, dots, dashes, and
/// underscores and must be at most 255 bytes. This helper lowercases the
/// scheme and trust domain, leaves the path alone, and returns `None` if the
/// input is not a syntactically valid SPIFFE ID.
///
/// Dropping invalid SPIFFE-looking URIs is a defense-in-depth measure: a
/// policy author writing `spiffe_prefix: "spiffe://prod/"` should not have
/// that match a cert presenting `spiffe://PROD%2Fadmin` or similar malformed
/// input.
///
/// [spec]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
fn canonicalize_spiffe_id(uri: &str) -> Option<String> {
    const SCHEME: &str = "spiffe://";
    if uri.len() < SCHEME.len() {
        return None;
    }
    let (scheme, rest) = uri.split_at(SCHEME.len());
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    // Trust domain ends at the first `/` or end-of-string.
    let (trust_domain, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if trust_domain.is_empty() || trust_domain.len() > 255 {
        return None;
    }
    // Trust domain charset: ASCII lowercase letters, digits, dot, dash, underscore.
    // The spec is case-insensitive for the authority, so we also accept uppercase
    // letters and lowercase them below.
    let charset_ok = trust_domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !charset_ok {
        return None;
    }
    // Reject empty path segments like `spiffe://trust/foo//bar` and any
    // literal percent-encoding ambiguity in the path by requiring each path
    // segment to be non-empty. The spec allows percent-encoding but we stay
    // conservative: segment must be at least one character.
    if !path.is_empty() {
        for segment in path.split('/').skip(1) {
            if segment.is_empty() {
                return None;
            }
        }
    }
    let mut canonical = String::with_capacity(SCHEME.len() + trust_domain.len() + path.len());
    canonical.push_str("spiffe://");
    // Lowercase the trust domain.
    for b in trust_domain.bytes() {
        canonical.push(b.to_ascii_lowercase() as char);
    }
    canonical.push_str(path);
    Some(canonical)
}

fn first_subject_attr(
    cert: &X509Certificate<'_>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Option<String> {
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == oid
                && let Ok(v) = attr.attr_value().as_str()
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Extract the Common Name (CN) from the certificate's subject.
///
/// NOTE: The CN is returned with its original casing from the certificate.
/// Case-insensitive matching is enforced at the ACL lookup layer
/// (`GroupAcl::can_send` / `can_receive`), not at extraction time.
/// This preserves the original CN for logging and identity display
/// while ensuring security checks are case-insensitive.
fn extract_cn(cert: &X509Certificate<'_>) -> Result<String> {
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                let cn = attr
                    .attr_value()
                    .as_str()
                    .map_err(|e| {
                        RustgateError::from(TransportError::Other(format!(
                            "invalid CN encoding: {e}"
                        )))
                    })?
                    .to_string();
                return Ok(cn);
            }
        }
    }

    Err(TransportError::MissingCommonName.into())
}

/// Extract `groups` from the cert's OU fields.
///
/// Each `OU=` RDN contributes one or more group names to the identity.
/// Two encodings are accepted per RDN, in priority order:
///
/// 1. **JSON array of strings** — if the OU value parses as a JSON array
///    of strings (e.g. `["R,D", "ops"]`), each element becomes one group
///    verbatim. This is the recommended form when any group name contains
///    characters that collide with the comma-separated fallback (commas
///    most notably, but also leading/trailing whitespace).
///
/// 2. **Comma-separated list** — otherwise, the value is split on `,` and
///    each trimmed non-empty fragment becomes one group. This preserves
///    the historical convention of packing multiple memberships into a
///    single RDN (e.g. `OU=operators,analysts`).
///
/// **Operator note on comma-separated form:** RFC 4514 allows escaping
/// commas inside a DN attribute with `\,`, but x509-parser unescapes them
/// before this function sees the string, so an OU of `R\,D,ops` arrives
/// here as `R,D,ops` and becomes three groups rather than two. If any
/// group name must contain a literal comma, use the JSON array form or
/// issue multiple OU RDNs instead.
fn extract_groups(cert: &X509Certificate<'_>) -> BTreeSet<String> {
    let mut groups = BTreeSet::new();

    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_ORGANIZATIONAL_UNIT
                && let Ok(ou) = attr.attr_value().as_str()
            {
                // Try JSON array form first. Only attempt the parse when
                // the value looks like an array (`[...]`) so malformed
                // JSON in an ordinary comma-list like `[stale` doesn't
                // silently fall through — that would have been rejected
                // by valid_group_id downstream anyway.
                let trimmed = ou.trim();
                if trimmed.starts_with('[')
                    && let Ok(array) = serde_json::from_str::<Vec<String>>(trimmed)
                {
                    for name in array {
                        let name = name.trim();
                        if !name.is_empty() {
                            let _ = groups.insert(name.to_string());
                        }
                    }
                    continue;
                }
                // Fall back to comma-separated list.
                for group in ou.split(',') {
                    let group = group.trim();
                    if !group.is_empty() {
                        let _ = groups.insert(group.to_string());
                    }
                }
            }
        }
    }

    groups
}

/// Extended Key Usage purpose expected from a certificate.
///
/// Used with [`validate_key_usage`] to enforce that client-presented
/// certificates include the correct EKU extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedKeyUsage {
    /// Certificate must include `id-kp-clientAuth`.
    ClientAuth,
    /// Certificate must include `id-kp-serverAuth`.
    ServerAuth,
}

/// Validate that the certificate contains the expected Extended Key Usage extension.
///
/// Returns `Ok(())` if the certificate has the required EKU, or an error if:
/// - The certificate has no EKU extension at all
/// - The EKU extension does not include the expected purpose
///
/// This prevents a server certificate from being used as a client certificate
/// and vice versa, even if the CA signature is valid.
pub fn validate_key_usage(cert_der: &CertificateDer<'_>, expected: ExpectedKeyUsage) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| TransportError::Other(format!("failed to parse X.509 certificate: {e}")))?;

    let extensions_map = cert.extensions_map().map_err(|e| {
        RustgateError::from(TransportError::Other(format!(
            "failed to parse certificate extensions: {e}"
        )))
    })?;

    let eku_ext = extensions_map
        .get(&OID_X509_EXT_EXTENDED_KEY_USAGE)
        .ok_or_else(|| {
            RustgateError::from(TransportError::Other(
                "certificate has no Extended Key Usage extension".to_string(),
            ))
        })?;

    let parsed = eku_ext.parsed_extension();
    if let ParsedExtension::ExtendedKeyUsage(eku) = parsed {
        let has_usage = match expected {
            ExpectedKeyUsage::ClientAuth => eku.client_auth,
            ExpectedKeyUsage::ServerAuth => eku.server_auth,
        };

        if has_usage {
            Ok(())
        } else {
            Err(TransportError::MissingKeyUsage {
                expected: format!("{expected:?}"),
            }
            .into())
        }
    } else {
        Err(
            TransportError::Other("failed to parse Extended Key Usage extension".to_string())
                .into(),
        )
    }
}

fn compute_fingerprint(cert_der: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use rustgate_test_utils::certs::TestCa;
    use rustls::pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    use super::*;

    fn parse_cert_pem(pem: &str) -> CertificateDer<'static> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    }

    #[test]
    fn extracts_spiffe_id_from_uri_san() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert_with_attrs(
            "alice",
            &[],
            Some("spiffe://example.org/svc/alice"),
            None,
            None,
            &[],
            &[],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.spiffe_id.as_deref(),
            Some("spiffe://example.org/svc/alice")
        );
        assert_eq!(
            id.attributes.get("spiffe_id"),
            Some(&AttrValue::Str("spiffe://example.org/svc/alice".into()))
        );
        assert!(matches!(
            id.attributes.get("san_uri"),
            Some(AttrValue::Set(_))
        ));
    }

    #[test]
    fn extracts_dns_and_email_sans() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert_with_attrs(
            "bob",
            &[],
            None,
            None,
            None,
            &["b.example.com", "a.example.com"],
            &["bob@example.com"],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        let dns = id.attributes.get("san_dns").unwrap();
        match dns {
            AttrValue::Set(v) => assert_eq!(
                v,
                &vec!["a.example.com".to_string(), "b.example.com".into()]
            ),
            other => panic!("expected Set, got {other:?}"),
        }
        assert_eq!(
            id.attributes.get("san_email"),
            Some(&AttrValue::Set(vec!["bob@example.com".into()]))
        );
        assert!(id.spiffe_id.is_none());
    }

    #[test]
    fn extracts_subject_org_and_country() {
        let ca = TestCa::new("attr-ca");
        let cert =
            ca.issue_client_cert_with_attrs("carol", &[], None, Some("Acme"), Some("US"), &[], &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.attributes.get("org"),
            Some(&AttrValue::Str("Acme".into()))
        );
        assert_eq!(
            id.attributes.get("country"),
            Some(&AttrValue::Str("US".into()))
        );
    }

    #[test]
    fn extracts_issuer_cn_and_cert_serial() {
        let ca = TestCa::new("issuer-root");
        let cert = ca.issue_client_cert("dave", &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.attributes.get("issuer_cn"),
            Some(&AttrValue::Str("issuer-root".into()))
        );
        match id.attributes.get("cert_serial") {
            Some(AttrValue::Str(s)) => {
                assert!(!s.is_empty());
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
            }
            other => panic!("expected cert_serial Str, got {other:?}"),
        }
    }

    #[test]
    fn extract_identity_canonicalizes_spiffe_trust_domain() {
        let ca = TestCa::new("attr-ca");
        // Cert presents an uppercase trust domain; extraction must lowercase it.
        let cert = ca.issue_client_cert_with_attrs(
            "carol",
            &[],
            Some("spiffe://Example.ORG/ns/prod/svc"),
            None,
            None,
            &[],
            &[],
        );
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert_eq!(
            id.spiffe_id.as_deref(),
            Some("spiffe://example.org/ns/prod/svc"),
            "trust domain must be lowercased per SPIFFE spec"
        );
    }

    #[test]
    fn canonicalize_spiffe_lowercases_trust_domain_only() {
        assert_eq!(
            canonicalize_spiffe_id("spiffe://Example.ORG/ns/Prod/Svc"),
            Some("spiffe://example.org/ns/Prod/Svc".to_string()),
            "trust domain case-insensitive, path case-sensitive"
        );
        assert_eq!(
            canonicalize_spiffe_id("SPIFFE://trust.example/svc"),
            Some("spiffe://trust.example/svc".to_string()),
            "scheme case-insensitive"
        );
        assert_eq!(
            canonicalize_spiffe_id("spiffe://trust.example"),
            Some("spiffe://trust.example".to_string()),
            "trailing slash optional"
        );
    }

    #[test]
    fn canonicalize_spiffe_rejects_malformed() {
        assert!(canonicalize_spiffe_id("http://trust.example/foo").is_none());
        assert!(
            canonicalize_spiffe_id("spiffe://").is_none(),
            "empty authority"
        );
        assert!(
            canonicalize_spiffe_id("spiffe:///path").is_none(),
            "empty trust domain"
        );
        assert!(
            canonicalize_spiffe_id("spiffe://trust!bad/svc").is_none(),
            "disallowed charset in authority"
        );
        assert!(
            canonicalize_spiffe_id("spiffe://trust/foo//bar").is_none(),
            "empty path segment"
        );
        assert!(
            canonicalize_spiffe_id(&format!("spiffe://{}/svc", "a".repeat(256))).is_none(),
            "authority > 255 bytes"
        );
    }

    #[test]
    fn san_count_cap_truncates_dns_list() {
        let ca = TestCa::new("attr-ca");
        // Issue cert with 40 DNS SANs; cap is 32. The attribute bag
        // must report at most 32 entries and the cap must trigger
        // without failing the handshake.
        let names: Vec<String> = (0..40).map(|i| format!("host{i:02}.example.com")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let cert = ca.issue_client_cert_with_attrs("capper", &[], None, None, None, &refs, &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        match id.attributes.get("san_dns") {
            Some(AttrValue::Set(v)) => {
                assert!(
                    v.len() <= MAX_SAN_ENTRIES_PER_CATEGORY,
                    "san_dns should be capped at {} entries, got {}",
                    MAX_SAN_ENTRIES_PER_CATEGORY,
                    v.len()
                );
            }
            other => panic!("expected san_dns Set, got {other:?}"),
        }
    }

    #[test]
    fn attr_byte_cost_tracks_string_length() {
        // Sanity check the budget accounting so a regression in
        // `attr_byte_cost` can't silently disable the soft cap.
        let short = AttrValue::Str("ab".into());
        let long = AttrValue::Str("a".repeat(100));
        assert!(attr_byte_cost("k", &long) > attr_byte_cost("k", &short));

        let set = AttrValue::Set(vec!["a".into(), "b".into()]);
        let cost = attr_byte_cost("s", &set);
        assert!(cost >= 2 /* bytes */ + 2 * 16 /* per-entry overhead */);
    }

    #[test]
    fn no_sans_yields_no_san_attrs_but_still_succeeds() {
        let ca = TestCa::new("attr-ca");
        let cert = ca.issue_client_cert("eve", &[]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert!(id.spiffe_id.is_none());
        assert!(id.attributes.get("san_dns").is_none());
        assert!(id.attributes.get("san_email").is_none());
        assert!(id.attributes.get("san_uri").is_none());
        // cert_serial and issuer_cn always present
        assert!(id.attributes.contains_key("cert_serial"));
        assert!(id.attributes.contains_key("issuer_cn"));
    }

    #[test]
    fn ou_comma_separated_splits_into_groups() {
        // Backward-compatible form: `OU=analysts,operators` yields two
        // groups. Exercises the fallback branch when the OU value is
        // not a JSON array.
        let ca = TestCa::new("ou-ca");
        let cert = ca.issue_client_cert("user", &["analysts", "operators"]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert!(id.groups.contains("analysts"));
        assert!(id.groups.contains("operators"));
        assert_eq!(id.groups.len(), 2);
    }

    #[test]
    fn ou_json_array_preserves_commas_in_group_names() {
        // JSON array form carries commas through unchanged. The single
        // element passed to the test helper becomes the entire OU
        // value (single-element `join(",")` is a no-op), so the OU is
        // literally `["R,D","ops"]` and must parse into two groups.
        let ca = TestCa::new("ou-ca");
        let cert = ca.issue_client_cert("user", &[r#"["R,D","ops"]"#]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert!(
            id.groups.contains("R,D"),
            "expected literal comma preserved, got {:?}",
            id.groups
        );
        assert!(id.groups.contains("ops"));
        assert_eq!(id.groups.len(), 2);
    }

    #[test]
    fn ou_malformed_json_array_falls_back_to_comma_split() {
        // An OU that looks like a JSON array prefix but fails to parse
        // falls through to the comma-separated path. `[stale,foo` is
        // not a valid JSON array; the comma splitter then yields
        // `[stale` and `foo` — neither would pass downstream group-id
        // validation, but this test pins the extractor's behaviour so
        // callers can rely on a single well-defined fallback.
        let ca = TestCa::new("ou-ca");
        let cert = ca.issue_client_cert("user", &["[stale,foo"]);
        let der = parse_cert_pem(&cert.cert_pem);
        let id = extract_identity(&der).unwrap();
        assert!(id.groups.contains("[stale"));
        assert!(id.groups.contains("foo"));
    }
}

// Copyright © 2026 Roberto Chiofalo.

//! `generate-config` — emit an annotated TOML template covering every
//! option rustgate reads from a config file.
//!
//! Unlike [`crate::diagnostics::cert_info`] and friends, this subcommand
//! takes no inputs: it introspects the clap schema for [`crate::cli::Cli`]
//! at runtime and renders one commented block per key. Operators feed the
//! output to `rustgate.toml`, uncomment the keys they want to override,
//! and the server's existing CLI / env / file precedence chain takes over
//! from there.
//!
//! # Output contract
//!
//! The template is grouped into human-labeled sections that mirror the
//! field order in the `define_config_file!` invocation — mechanically
//! stable so that `diff`ing the template between releases highlights
//! exactly which options were added, removed, or changed. Each block is
//! shaped:
//!
//! ```text
//! # <help text from the clap arg, wrapped to 72 columns>
//! # env: RUSTGATE_FOO
//! # default: "0.0.0.0:4433"
//! #foo = "0.0.0.0:4433"
//! ```
//!
//! Fields that are *required* when the server runs (no default and
//! `required_unless_present_*` triggers the error) are emitted
//! uncommented with an obvious `REPLACE_ME` placeholder so a
//! copy-pasted template fails loudly at startup rather than silently
//! keeping a placeholder in production.
//!
//! Fields that are `Option<T>` with no default get a commented-out
//! `#key = "<unset>"` placeholder so operators can see the TOML syntax
//! for the key. The `<unset>` string is *not* a valid runtime value —
//! uncommenting alone will not opt the option in; the placeholder must
//! be replaced with a real literal. This matches how the TOML loader
//! treats an absent key (Option remains None) and still keeps the key
//! visible in the template for discovery.
//!
//! Addresses Finding F-180 (issue #900).

use std::fmt::Write as _;

use anyhow::Result;
use clap::{Arg, CommandFactory};

use crate::cli::{CONFIG_FILE_FIELDS, Cli};

/// Column at which long help lines wrap inside a `# ` comment prefix.
///
/// 72 keeps the rendered template within the 79-column envelope most
/// editors show without horizontal scroll once the `# ` prefix is
/// accounted for.
const WRAP_COLUMN: usize = 72;

/// Placeholder emitted for uncommented required keys so a copy-pasted
/// template fails loudly at server startup instead of silently running
/// with an empty string.
const REQUIRED_PLACEHOLDER: &str = "REPLACE_ME";

/// Unique marker emitted when [`CONFIG_FILE_FIELDS`] contains a field
/// name that does not appear in `Cli::command().get_arguments()` —
/// indicates schema drift between the two macro-driven lists.
///
/// Deliberately *not* the literal word "WARNING" because multi-line
/// clap help text already uses that word for genuine runtime caveats
/// (see the `--acl-api-bind` arg), which would confuse a naive
/// `grep WARNING` check in CI.
const SCHEMA_DRIFT_MARKER: &str = "SCHEMA_DRIFT";

/// Section headers inserted when the named field is reached during the
/// walk over [`CONFIG_FILE_FIELDS`]. The first entry labels the top of
/// the file; subsequent entries introduce new categories. Fields not
/// named here continue the previously-opened section.
///
/// Keeping this table beside the generator (rather than tagging each
/// field at the macro call site) isolates "documentation style" changes
/// from the authoritative `define_config_file!` field list.
const SECTION_MARKERS: &[(&str, &str)] = &[
    ("bind", "TLS / mTLS"),
    ("framing", "Framing and encoding"),
    ("nats_url", "NATS / JetStream bridge"),
    ("http_config_file", "HTTP egress bridge"),
    ("enrollment_bind", "Certificate enrollment / EST"),
    ("metrics_bind", "Prometheus metrics endpoint"),
    ("max_connections", "Connection limits and backpressure"),
    ("websocket_bind", "WebSocket transport"),
    ("mqtt_bind", "MQTT transport"),
    ("tcp_bind", "Plaintext TCP / UDP transports"),
    ("federation_v1_bind", "Federation"),
    ("replay_window", "Client rate limiting"),
    ("group_acl_file", "Authorization (ACL and authz engine)"),
    ("archive_dir", "Archives, audit log, access log"),
    ("otel_endpoint", "OpenTelemetry tracing"),
    ("dedup_window_secs", "Deduplication and CoT delta encoding"),
];

/// Curated list of fields included in `generate-config --minimal`.
///
/// These are the keys an operator typically has to set on a fresh
/// install: the mTLS triple plus the most-edited transport / framing
/// knobs. Anything else (NATS, federation, peer-discovery, archives,
/// observability, etc.) is intentionally omitted to keep the minimal
/// template short and focused. Operators can grow into the full
/// template by re-running without `--minimal`.
///
/// Keep the list in the same order it appears in the full template so
/// section headers continue to make sense when subset-rendered.
const MINIMAL_FIELDS: &[&str] = &[
    // TLS / mTLS — required to start at all.
    "cert",
    "key",
    "ca",
    "bind",
    "tls_min_version",
    // Framing / encoding — wrong values here are the most common
    // copy-paste failure mode for new deployments.
    "framing",
    "encoding",
    // Connection limits — operators almost always want to tune these
    // before exposing the listener.
    "max_connections",
];

/// Build options for [`build_template_with_opts`]. Splitting from the
/// zero-arg [`build_template`] keeps the existing test surface (key
/// presence, section ordering, etc.) untouched.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BuildOpts {
    /// When `true`, emit only [`MINIMAL_FIELDS`] — bare-essentials
    /// template for fresh deployments. Defaults to `false` (full
    /// template with every config knob).
    pub(crate) minimal: bool,
}

/// Entry point wired from `main.rs`. Writes the template to stdout so
/// operators can redirect it with `rustgate generate-config > rustgate.toml`.
pub(crate) fn run(opts: BuildOpts) -> Result<()> {
    let template = build_template_with_opts(opts);
    print!("{template}");
    Ok(())
}

/// Render the *full* template as a single string. Equivalent to
/// `build_template_with_opts(BuildOpts::default())` and preserved for
/// existing tests that pin the full output shape.
#[cfg(test)]
pub(crate) fn build_template() -> String {
    build_template_with_opts(BuildOpts::default())
}

/// Render the template under the supplied [`BuildOpts`]. Splitting the
/// rendering this way keeps the field-driven test surface (key
/// presence, section ordering, schema-drift detection) on the full
/// template, while the minimal mode is exercised by its own dedicated
/// tests.
pub(crate) fn build_template_with_opts(opts: BuildOpts) -> String {
    let cmd = Cli::command();
    let mut out = String::with_capacity(16 * 1024);

    if opts.minimal {
        writeln!(
            &mut out,
            "# rustgate minimal configuration template\n\
             # Generated by `rustgate generate-config --minimal`.\n\
             #\n\
             # This template covers only the bare-essentials a fresh deployment\n\
             # needs: the mTLS triple, the listen address, framing/encoding,\n\
             # and connection limits. For every other option the server\n\
             # applies its default. Re-run without `--minimal` to see the full\n\
             # set of knobs.\n\
             #\n\
             # Fields marked REQUIRED must be set before the server will start (the\n\
             # lines are emitted uncommented with an obvious placeholder so a\n\
             # copy-pasted template fails loudly rather than silently running with\n\
             # an empty value).\n"
        )
        .expect("writeln! to String cannot fail");
    } else {
        writeln!(
            &mut out,
            "# rustgate configuration template\n\
             # Generated by `rustgate generate-config`.\n\
             #\n\
             # Uncomment and edit only the keys you want to override; the server\n\
             # applies the defaults shown for every other key. CLI flags and the\n\
             # matching RUSTGATE_* environment variables still take precedence over\n\
             # values loaded from this file.\n\
             #\n\
             # Fields marked REQUIRED must be set before the server will start (the\n\
             # lines are emitted uncommented with an obvious placeholder so a\n\
             # copy-pasted template fails loudly rather than silently running with\n\
             # an empty value).\n"
        )
        .expect("writeln! to String cannot fail");
    }

    for field in CONFIG_FILE_FIELDS {
        if opts.minimal && !MINIMAL_FIELDS.contains(field) {
            // Skip non-essential fields entirely. We deliberately do not
            // emit a `# (skipped)` placeholder — the whole point of the
            // minimal template is to be short.
            continue;
        }
        if let Some(label) = section_for(field) {
            writeln!(&mut out, "# ---------- {label} ----------\n")
                .expect("writeln! to String cannot fail");
        }
        match lookup_arg(&cmd, field) {
            Some(arg) => render_field(&mut out, field, arg),
            None => {
                // Should only happen if a ConfigFile field was added
                // without a matching #[arg] on Cli. Surface it with a
                // stable, grep-able marker (not the word "WARNING"
                // itself, which appears legitimately inside multi-line
                // help text — e.g. the ACL API arg) so CI notices
                // without false positives.
                writeln!(
                    &mut out,
                    "# {SCHEMA_DRIFT_MARKER}: no Cli::command() arg for field `{field}`; fix the Cli struct.\n"
                )
                .expect("writeln! to String cannot fail");
            }
        }
    }

    out
}

/// Return the section title when `field` opens a new section, else `None`.
fn section_for(field: &str) -> Option<&'static str> {
    SECTION_MARKERS
        .iter()
        .find(|(marker, _)| *marker == field)
        .map(|(_, label)| *label)
}

/// Find the clap `Arg` whose snake-case id matches `field`.
fn lookup_arg<'a>(cmd: &'a clap::Command, field: &str) -> Option<&'a Arg> {
    cmd.get_arguments().find(|a| a.get_id().as_str() == field)
}

/// Convert a snake_case field name to the kebab-case TOML key that the
/// `#[serde(rename_all = "kebab-case")]` on `ConfigFile` expects.
fn to_kebab_case(field: &str) -> String {
    field.replace('_', "-")
}

/// Emit one field block: a wrapped help comment, an `env:` line (if any),
/// a `default:` line, and the `key = value` line (commented-out unless
/// the field is required).
fn render_field(out: &mut String, field: &str, arg: &Arg) {
    let help = effective_help(arg);
    for line in wrap_comment(&help, WRAP_COLUMN) {
        writeln!(out, "# {line}").expect("writeln! to String cannot fail");
    }

    if let Some(env) = arg.get_env()
        && let Some(env_str) = env.to_str()
    {
        writeln!(out, "# env: {env_str}").expect("writeln! to String cannot fail");
    }

    let default = default_value(arg);
    let kebab = to_kebab_case(field);
    let is_required = is_required(arg);

    match (default.as_deref(), is_required) {
        (Some(value), _) => {
            writeln!(out, "# default: {value}").expect("writeln! to String cannot fail");
            writeln!(out, "#{kebab} = {value}\n").expect("writeln! to String cannot fail");
        }
        (None, true) => {
            writeln!(
                out,
                "# REQUIRED: no default — must be supplied to start the server."
            )
            .expect("writeln! to String cannot fail");
            writeln!(out, "{kebab} = \"{REQUIRED_PLACEHOLDER}\"\n")
                .expect("writeln! to String cannot fail");
        }
        (None, false) => {
            // Optional field with no default: still emit a commented-out
            // sample assignment so operators can see the TOML syntax for
            // the key. The `<unset>` placeholder is a clear signal that
            // uncommenting alone will NOT produce valid TOML — the
            // value must be replaced with a real literal. Keeping the
            // key visible here also makes the template round-trip
            // (after required placeholders are filled in), which the
            // `template_parses_as_config_file_mirror_*` test pins.
            writeln!(
                out,
                "# default: <unset> — leave commented to keep the option disabled."
            )
            .expect("writeln! to String cannot fail");
            writeln!(out, "#{kebab} = \"<unset>\"\n").expect("writeln! to String cannot fail");
        }
    }
}

/// Return the best help string we have for `arg`. Prefers the long form
/// (full doc comment) over the short form (first line only), falling
/// back to "No help available." so the template never emits a bare
/// `# ` block that looks like a formatting bug.
fn effective_help(arg: &Arg) -> String {
    if let Some(long) = arg.get_long_help() {
        long.to_string()
    } else if let Some(short) = arg.get_help() {
        short.to_string()
    } else {
        "No help available.".to_string()
    }
}

/// Wrap `text` at `column` boundaries, respecting existing newlines.
/// Each output line is at most `column` characters long unless a single
/// token exceeds the width (then it is emitted on its own line). Empty
/// lines in the input are preserved as bare comment separators.
fn wrap_comment(text: &str, column: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
                continue;
            }
            if current.len() + 1 + word.len() > column {
                out.push(std::mem::take(&mut current));
                current.push_str(word);
            } else {
                current.push(' ');
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    out
}

/// Extract the first default value from `arg`, formatted as a TOML
/// literal. clap stores defaults as `OsStr` so we lossily coerce to
/// string (anything non-UTF-8 would already be a configuration bug).
///
/// Returns `None` when the arg has no default — either because it is
/// `Option<T>` without `default_value_t`, or because clap stores the
/// empty-string default (`default_value = ""`) alongside a
/// `required_unless_present_*` constraint, which we promote to the
/// "required, show placeholder" branch.
fn default_value(arg: &Arg) -> Option<String> {
    let mut values = arg.get_default_values().iter();
    let first = values.next()?;
    let s = first.to_string_lossy();
    // Empty-string defaults paired with `required_unless_present_*`
    // mean "no meaningful default" for our purposes — fall through to
    // the required branch.
    if s.is_empty() && is_required(arg) {
        return None;
    }
    Some(format_toml_literal(arg, &s))
}

/// Heuristic for "required" that combines clap's explicit `required`
/// flag with the conditional `required_unless_present_*` chain. clap
/// does not expose a single boolean for the latter, so we detect it via
/// the empty-string default trick used in the Cli struct.
fn is_required(arg: &Arg) -> bool {
    if arg.is_required_set() {
        return true;
    }
    // `required_unless_present_any` / `required_unless_present` produce
    // args that clap does not mark as unconditionally required, but
    // whose `default_value = ""` signals that an empty string is not a
    // valid runtime value. The Cli struct uses exactly that pattern for
    // `cert`, `key`, and `ca`.
    if let Some(first) = arg.get_default_values().first()
        && first.is_empty()
        && arg.get_id().as_str() != "crl"
    {
        // `crl` is genuinely Optional — default is None, not empty string.
        return true;
    }
    false
}

/// Render `value` as a TOML literal for the appropriate type. The
/// representation is driven by the arg's [`clap::builder::ValueParser`]
/// `TypeId` rather than by lexical inspection of `value` — that lets
/// `tls-min-version = "1.2"` stay quoted (the backing type is
/// [`String`]) even though `"1.2"` also happens to parse as `f64`.
///
/// Recognised types render bare: [`bool`], integer and floating-point
/// primitives. Everything else (including custom enum types that clap
/// surfaces via [`clap::ValueEnum`]) is double-quoted.
///
/// This is a presentation concern only — the TOML loader accepts either
/// spelling, but a bare `5` reads better than `"5"` in a config file,
/// and a quoted `"1.2"` is required by the `tls-min-version` String
/// field.
fn format_toml_literal(arg: &Arg, value: &str) -> String {
    use std::any::TypeId;
    // clap exposes the `TypeId` of each arg's parsed target via
    // `ValueParser::type_id()` → `AnyValueId`, which compares against
    // `std::any::TypeId` through `PartialEq<TypeId>`. We check each
    // primitive explicitly because `AnyValueId` has no `contains`
    // implementation.
    let tid = arg.get_value_parser().type_id();
    let is_bare = tid == TypeId::of::<bool>()
        || tid == TypeId::of::<i8>()
        || tid == TypeId::of::<i16>()
        || tid == TypeId::of::<i32>()
        || tid == TypeId::of::<i64>()
        || tid == TypeId::of::<i128>()
        || tid == TypeId::of::<isize>()
        || tid == TypeId::of::<u8>()
        || tid == TypeId::of::<u16>()
        || tid == TypeId::of::<u32>()
        || tid == TypeId::of::<u64>()
        || tid == TypeId::of::<u128>()
        || tid == TypeId::of::<usize>()
        || tid == TypeId::of::<f32>()
        || tid == TypeId::of::<f64>();
    if is_bare {
        return value.to_string();
    }
    // Everything else (String, PathBuf, ValueEnum-derived types, …) is
    // quoted. Escape `"` and `\` per TOML basic-string rules.
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;
    use crate::cli::CONFIG_FILE_FIELDS;

    #[test]
    fn template_is_nonempty_and_utf8() {
        let t = build_template();
        assert!(!t.is_empty(), "template should not be empty");
        assert!(t.is_ascii() || t.chars().all(|c| c == '\n' || !c.is_control()));
    }

    #[test]
    fn template_contains_every_config_file_field_as_kebab_key() {
        let t = build_template();
        for field in CONFIG_FILE_FIELDS {
            let kebab = to_kebab_case(field);
            // Each field surfaces somewhere — either as `#key = default`
            // or as uncommented `key = "REPLACE_ME"` for required keys.
            let has_key = t.contains(&format!("#{kebab} = ")) || t.contains(&format!("{kebab} = "));
            assert!(
                has_key,
                "template missing an emitted line for field `{field}` (kebab `{kebab}`)"
            );
        }
    }

    #[test]
    fn template_has_no_schema_drift_markers() {
        // A `# SCHEMA_DRIFT:` marker appears only when a ConfigFile
        // field lacks a matching Cli arg — CI should catch schema
        // drift between the two macro-driven lists.
        let t = build_template();
        let drift: Vec<&str> = t
            .lines()
            .filter(|l| l.contains(SCHEMA_DRIFT_MARKER))
            // Drop the self-referential definition line in this module
            // if it happens to be included in the test environment.
            .filter(|l| {
                l.trim_start_matches('#')
                    .trim_start()
                    .starts_with(SCHEMA_DRIFT_MARKER)
            })
            .collect();
        assert!(
            drift.is_empty(),
            "template emitted SCHEMA_DRIFT markers:\n{}",
            drift.join("\n")
        );
    }

    #[test]
    fn required_tls_fields_are_uncommented_with_placeholder() {
        let t = build_template();
        for required in ["cert", "key", "ca"] {
            assert!(
                t.contains(&format!("{required} = \"REPLACE_ME\"")),
                "expected uncommented `{required} = \"REPLACE_ME\"` in template"
            );
            assert!(
                t.contains("# REQUIRED: "),
                "expected a REQUIRED: marker for `{required}`"
            );
        }
    }

    #[test]
    fn bind_has_default_and_is_commented_out() {
        let t = build_template();
        assert!(
            t.contains("#bind = \"0.0.0.0:4433\""),
            "bind should be commented-out with its default"
        );
        assert!(
            t.contains("# default: \"0.0.0.0:4433\""),
            "bind should advertise its default in a comment"
        );
    }

    #[test]
    fn section_headers_appear_in_order() {
        let t = build_template();
        let mut last_pos = 0usize;
        for (_, label) in SECTION_MARKERS {
            let marker = format!("# ---------- {label} ----------");
            let pos = t
                .find(&marker)
                .unwrap_or_else(|| panic!("missing section header `{label}`"));
            assert!(
                pos >= last_pos,
                "section header `{label}` appears out of order \
                 (pos {pos} < previous {last_pos})"
            );
            last_pos = pos;
        }
    }

    #[test]
    fn env_vars_are_documented_when_present() {
        let t = build_template();
        // bind has `env = "RUSTGATE_BIND"`.
        assert!(
            t.contains("# env: RUSTGATE_BIND"),
            "template should document RUSTGATE_BIND env var for bind"
        );
    }

    #[test]
    fn boolean_defaults_render_without_quotes() {
        let t = build_template();
        // fips_required has `default_value_t = false`.
        assert!(
            t.contains("#fips-required = false"),
            "boolean defaults should render as bare `true` / `false`"
        );
    }

    #[test]
    fn integer_defaults_render_without_quotes() {
        let t = build_template();
        // federation_max_hops default is 8 (closes #758 — was 10
        // before the inbound enforcement bound was made configurable
        // and aligned with the historical hard-coded MAX_FEDERATION_HOPS).
        assert!(
            t.contains("#federation-max-hops = 8"),
            "integer defaults should render as bare numeric literals"
        );
    }

    #[test]
    fn option_fields_without_default_emit_commented_unset_placeholder() {
        let t = build_template();
        // nats_url is Option<String> with no default and is not required.
        // The template emits a commented-out `#nats-url = "<unset>"`
        // line so operators can see the TOML syntax. The line MUST
        // stay commented — uncommenting alone (without replacing the
        // placeholder) would not produce valid TOML semantics for an
        // Option field that the server expects to be absent.
        assert!(t.contains("# env: RUSTGATE_NATS_URL"));
        assert!(
            t.contains("#nats-url = \"<unset>\""),
            "optional field nats-url should emit a `#key = \"<unset>\"` placeholder"
        );
        assert!(
            !t.contains("nats-url = \"REPLACE_ME\""),
            "optional field nats-url must NOT be marked REPLACE_ME (that's reserved for required fields)"
        );
    }

    #[test]
    fn kebab_case_conversion() {
        assert_eq!(to_kebab_case("bind"), "bind");
        assert_eq!(to_kebab_case("federation_max_hops"), "federation-max-hops");
        assert_eq!(
            to_kebab_case("federation_peer_discovery_consul_addr"),
            "federation-peer-discovery-consul-addr"
        );
    }

    #[test]
    fn wrap_comment_respects_column() {
        let long = "This is a long sentence that should wrap at the requested column \
                    width so that the rendered template stays within a readable envelope \
                    for operators skimming the file.";
        let wrapped = wrap_comment(long, 40);
        for line in &wrapped {
            assert!(
                line.len() <= 40,
                "wrapped line exceeds 40 columns: `{line}` (len {})",
                line.len()
            );
        }
    }

    #[test]
    fn wrap_comment_preserves_paragraph_breaks() {
        let input = "First paragraph.\n\nSecond paragraph.";
        let wrapped = wrap_comment(input, 80);
        let expected: Vec<String> = vec![
            "First paragraph.".to_string(),
            String::new(),
            "Second paragraph.".to_string(),
        ];
        assert_eq!(wrapped, expected);
    }

    #[test]
    fn format_toml_literal_uses_type_id() {
        let cmd = Cli::command();
        // bind is a String type — must quote even for values that look
        // numeric.
        let bind = lookup_arg(&cmd, "bind").expect("bind arg");
        assert_eq!(format_toml_literal(bind, "hello"), "\"hello\"");
        assert_eq!(format_toml_literal(bind, "1.2"), "\"1.2\"");
        assert_eq!(format_toml_literal(bind, "42"), "\"42\"");
        // fips_required is a bool type — bare literal.
        let fips = lookup_arg(&cmd, "fips_required").expect("fips_required arg");
        assert_eq!(format_toml_literal(fips, "true"), "true");
        assert_eq!(format_toml_literal(fips, "false"), "false");
        // federation_max_hops is u8 (post-#758) — bare integer.
        let hops = lookup_arg(&cmd, "federation_max_hops").expect("federation_max_hops arg");
        assert_eq!(format_toml_literal(hops, "8"), "8");
        // Escape round-trip on a String field.
        assert_eq!(
            format_toml_literal(bind, "path with \"quote\""),
            "\"path with \\\"quote\\\"\""
        );
    }

    #[test]
    fn tls_min_version_default_is_quoted_not_float() {
        // Regression guard: tls_min_version's default is the string
        // "1.2" which trivially parses as f64. The template must
        // render it as a quoted TOML string so the server's String-typed
        // ConfigFile mirror deserializes without complaint.
        let t = build_template();
        assert!(
            t.contains("#tls-min-version = \"1.2\""),
            "tls-min-version must render as a quoted string, got:\n{t}"
        );
        assert!(
            !t.contains("#tls-min-version = 1.2"),
            "tls-min-version must NOT render as a bare float"
        );
    }

    #[test]
    fn template_is_valid_toml_when_placeholders_kept() {
        // The generated template must parse as TOML even with the
        // REPLACE_ME placeholders still in place — otherwise operators
        // cannot validate "this file is syntactically correct" before
        // editing.
        let t = build_template();
        let _ = toml::from_str::<toml::Value>(&t).unwrap_or_else(|e| {
            panic!("generated template is not valid TOML: {e}\n{t}");
        });
    }

    #[test]
    fn template_parses_as_config_file_mirror_after_filling_required() {
        // Replace REPLACE_ME with a syntactically valid path and the
        // template should deserialize into `ConfigFile` cleanly (the
        // mirror uses `deny_unknown_fields`, so any typo'd key would
        // fail here).
        let t = build_template().replace("REPLACE_ME", "/tmp/placeholder");
        let parsed = toml::from_str::<toml::Value>(&t)
            .expect("filled template is not valid TOML — likely a rendering bug");
        // Round-trip through the ConfigFile mirror to exercise
        // deny_unknown_fields and rename_all = "kebab-case".
        let serialized = toml::to_string(&parsed).expect("re-serialize");
        let _cfg: crate::cli::ConfigFile = toml::from_str(&serialized)
            .expect("filled template failed to deserialize into ConfigFile mirror");
    }
}

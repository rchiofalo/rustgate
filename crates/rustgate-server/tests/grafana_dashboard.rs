// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration test for the golden Grafana dashboard at
//! `dashboards/rustgate-overview.json`.
//!
//! Two layers of pin:
//!
//! 1. The dashboard is valid JSON and contains the top-level keys a
//!    Grafana 10.x importer needs (`title`, `uid`, `schemaVersion`,
//!    `panels`, `templating`, `time`, `refresh`, `tags`).
//! 2. Every `rustgate_*` metric name referenced inside any panel's
//!    `targets[].expr` is also defined as a string literal in one of
//!    the workspace's `crates/*/src/metrics.rs` files. If a PR removes
//!    a metric without updating the dashboard the test fails fast at
//!    the panel that references the now-orphaned metric.
//!
//! Issue #771 — completes the issue together with the metrics
//! extension shipped via #1267.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Workspace root: `<crate>/tests/...` -> `<crate>` -> `crates/` ->
/// workspace root.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn dashboard_path() -> PathBuf {
    workspace_root()
        .join("dashboards")
        .join("rustgate-overview.json")
}

/// Read the dashboard JSON from disk and parse it.
fn load_dashboard() -> serde_json::Value {
    let path = dashboard_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse {} failed: {e}", path.display()))
}

/// Walk every panel (including panels nested in row-collapsed groups)
/// and call `f` once per `targets[].expr` string.
fn for_each_expr(dashboard: &serde_json::Value, mut f: impl FnMut(&str)) {
    fn visit(panels: &serde_json::Value, f: &mut dyn FnMut(&str)) {
        let arr = match panels.as_array() {
            Some(a) => a,
            None => return,
        };
        for panel in arr {
            if let Some(targets) = panel.get("targets").and_then(|t| t.as_array()) {
                for t in targets {
                    if let Some(expr) = t.get("expr").and_then(|e| e.as_str()) {
                        f(expr);
                    }
                }
            }
            if let Some(nested) = panel.get("panels") {
                visit(nested, f);
            }
        }
    }
    if let Some(panels) = dashboard.get("panels") {
        visit(panels, &mut f);
    }
}

/// Pull every `rustgate_*` token out of a PromQL expression. Strips the
/// histogram suffix `_bucket`, `_sum`, `_count` so a referenced
/// `rustgate_authz_evaluation_seconds_bucket` matches the
/// `rustgate_authz_evaluation_seconds` Histogram registered in code.
fn extract_metric_names(expr: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"rustgate_") {
            let start = i;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let mut name = expr[start..i].to_string();
            for suffix in ["_bucket", "_sum", "_count"] {
                if let Some(stripped) = name.strip_suffix(suffix) {
                    name = stripped.to_string();
                    break;
                }
            }
            let _ = out.insert(name);
        } else {
            i += 1;
        }
    }
    out
}

/// Read every `crates/*/src/metrics.rs` and collect the set of metric
/// names declared as `"rustgate_..."` string literals. The `Opts::new`
/// / `HistogramOpts::new` constructors and the `fallback_*` helpers all
/// take the metric name as the first string argument, so a literal scan
/// is sufficient and avoids depending on the prometheus crate's runtime
/// registry.
fn defined_metric_names() -> BTreeSet<String> {
    let crates_dir = workspace_root().join("crates");
    let crate_dirs = std::fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", crates_dir.display()))
        .filter_map(Result::ok);
    let mut out = BTreeSet::new();
    for entry in crate_dirs {
        let metrics_rs = entry.path().join("src").join("metrics.rs");
        if !metrics_rs.exists() {
            continue;
        }
        let raw = std::fs::read_to_string(&metrics_rs)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", metrics_rs.display()));
        for hit in raw.split("\"rustgate_").skip(1) {
            if let Some(end) = hit.find('"') {
                let name = format!("rustgate_{}", &hit[..end]);
                // Defensive: identifier characters only.
                if name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    let _ = out.insert(name);
                }
            }
        }
    }
    out
}

#[test]
fn dashboard_is_valid_json_with_required_top_level_keys() {
    let d = load_dashboard();
    assert!(d.is_object(), "dashboard root must be a JSON object");
    for key in [
        "title",
        "uid",
        "schemaVersion",
        "panels",
        "templating",
        "time",
        "refresh",
        "tags",
    ] {
        assert!(d.get(key).is_some(), "missing top-level key: {key}");
    }
    let title = d
        .get("title")
        .and_then(|v| v.as_str())
        .expect("title must be a string");
    assert!(
        title.to_ascii_lowercase().contains("rustgate"),
        "title should mention rustgate: got {title:?}"
    );
    let uid = d
        .get("uid")
        .and_then(|v| v.as_str())
        .expect("uid must be a string");
    assert!(!uid.is_empty(), "uid must be non-empty");
    let schema = d
        .get("schemaVersion")
        .and_then(|v| v.as_u64())
        .expect("schemaVersion must be a number");
    assert!(
        schema >= 30,
        "schemaVersion should target a modern Grafana (>= 30); got {schema}"
    );
}

#[test]
fn dashboard_has_a_meaningful_number_of_panels() {
    let d = load_dashboard();
    let panels = d
        .get("panels")
        .and_then(|p| p.as_array())
        .expect("panels must be an array");
    let mut total = 0usize;
    let mut non_row = 0usize;
    for p in panels {
        total += 1;
        if p.get("type").and_then(|t| t.as_str()) != Some("row") {
            non_row += 1;
        }
    }
    assert!(
        total >= 12,
        "expected at least a dozen top-level panels, got {total}"
    );
    assert!(
        non_row >= 10,
        "expected at least ten non-row panels, got {non_row}"
    );
}

#[test]
fn dashboard_templating_includes_datasource_and_peer_variables() {
    let d = load_dashboard();
    let list = d
        .get("templating")
        .and_then(|t| t.get("list"))
        .and_then(|l| l.as_array())
        .expect("templating.list must be an array");
    let names: BTreeSet<&str> = list
        .iter()
        .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        names.contains("DS_PROMETHEUS"),
        "templating must define DS_PROMETHEUS datasource variable; got {names:?}"
    );
    assert!(
        names.contains("peer"),
        "templating must define a federation `peer` variable; got {names:?}"
    );
}

#[test]
fn every_referenced_metric_exists_in_the_codebase() {
    let d = load_dashboard();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for_each_expr(&d, |expr| {
        for name in extract_metric_names(expr) {
            let _ = referenced.insert(name);
        }
    });
    assert!(
        !referenced.is_empty(),
        "expected the dashboard to reference some rustgate_* metrics"
    );
    let defined = defined_metric_names();
    assert!(
        !defined.is_empty(),
        "expected to find some rustgate_* metric definitions in crates/*/src/metrics.rs"
    );
    let missing: Vec<&String> = referenced.difference(&defined).collect();
    assert!(
        missing.is_empty(),
        "dashboard references metrics that are not defined anywhere in \
         crates/*/src/metrics.rs: {missing:?}\n\
         (referenced count: {ref_count}, defined count: {def_count})",
        ref_count = referenced.len(),
        def_count = defined.len(),
    );
}

#[test]
fn every_panel_target_expression_has_balanced_parens_and_quotes() {
    let d = load_dashboard();
    for_each_expr(&d, |expr| {
        let mut depth = 0i32;
        let mut in_dq = false;
        let mut in_sq = false;
        let mut prev = '\0';
        for c in expr.chars() {
            let escaped = prev == '\\';
            match c {
                '"' if !in_sq && !escaped => in_dq = !in_dq,
                '\'' if !in_dq && !escaped => in_sq = !in_sq,
                '(' if !in_dq && !in_sq => depth += 1,
                ')' if !in_dq && !in_sq => {
                    depth -= 1;
                    assert!(depth >= 0, "unbalanced ')' in expr: {expr}");
                }
                _ => {}
            }
            prev = c;
        }
        assert_eq!(depth, 0, "unbalanced parentheses in expr: {expr}");
        assert!(!in_dq, "unterminated double-quoted string in expr: {expr}");
        assert!(!in_sq, "unterminated single-quoted string in expr: {expr}");
    });
}

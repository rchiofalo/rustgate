#!/usr/bin/env python3
# Copyright (c) 2026 Roberto Chiofalo.
"""check-allow-justified.py — require `// justification:` on production `#[allow]`.

F-156 enforcement: every `#[allow(...)]` annotation in production Rust code
must be preceded by a `// justification: ...` comment explaining *why* the
lint is silenced at this specific site. This prevents the codebase from
accumulating unexplained suppressions that mask real bugs or style drift.

## What counts as "production" code

Scanned:
  * `crates/*/src/**/*.rs`

Not scanned (treated as tests or test support):
  * `crates/*/tests/**` — integration-test binaries
  * `crates/rustgate-test-utils/**` — test helper crate shared with dev-deps
  * `crates/*/benches/**` — microbenchmarks
  * `crates/*/examples/**` — example programs
  * `crates/*/build.rs` — build scripts (generated code paths)
  * Any `#[allow]` inside a `#[cfg(test)]`-gated block or `mod tests { ... }`
    module, or directly preceded by `#[cfg(test)]`.

## What counts as a "justification"

The line immediately preceding the `#[allow(...)]` — ignoring blank lines
and `#[cfg(...)]`-family attributes that may sit between — must be a line
comment (`//`) containing the literal token `justification:`. The comment
body can span multiple consecutive `//` lines; only the one touching the
`justification:` marker is required.

Good:
    // justification: seven args thread the full parser state through a
    // single dispatch site; packing them into a struct would only rename
    // the positional-argument risk.
    #[allow(clippy::too_many_arguments)]
    fn handle_open(...) { ... }

Bad (no justification comment):
    #[allow(clippy::too_many_arguments)]
    fn handle_open(...) { ... }

Bad (justification present but not immediately adjacent):
    // justification: ...
    ///
    /// doc comment broke the chain
    #[allow(clippy::too_many_arguments)]
    fn handle_open(...) { ... }

Usage: scripts/check-allow-justified.py [crates-root]
Exits 0 on success, 1 on any un-justified production `#[allow]`, 2 on
invocation error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# `#[allow(...)]` at any indentation. Captures the lint list for reporting.
ALLOW_RE = re.compile(r"^\s*#\[allow\(([^)]+)\)\]")

# `#[cfg(test)]` — exact-match guard above a `mod tests { ... }` module or
# an individual item. Either form flags the site below as test-only.
CFG_TEST_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")

# `mod tests {` / `mod test {` — opens a test module. We track the brace
# depth of these modules so we can skip `#[allow]` sites inside them.
MOD_TEST_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+tests?\s*\{")

# Excluded path prefixes (relative to the crates root).
EXCLUDED_PREFIXES = (
    "rustgate-test-utils/",
)


def is_production_path(rel: str) -> bool:
    """Return True if this relative path is production code to scan.

    The crates-root-relative path is expected — e.g. `rustgate-cot/src/delta.rs`.
    """
    # Only scan files under a crate's `src/` directory.
    parts = rel.split("/")
    if len(parts) < 3 or parts[1] != "src":
        return False
    # Excluded crates.
    for prefix in EXCLUDED_PREFIXES:
        if rel.startswith(prefix):
            return False
    return True


def iter_rust_sources(crates_root: Path):
    """Yield production `.rs` files under `crates_root`."""
    for path in sorted(crates_root.rglob("*.rs")):
        rel = path.relative_to(crates_root).as_posix()
        if is_production_path(rel):
            yield path


def find_unjustified_allows(path: Path) -> list[tuple[int, str]]:
    """Scan a single file and return [(lineno, lint_list)] for bad sites."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:  # pragma: no cover — surfaced to caller
        print(f"::error file={path}::cannot read: {exc}", file=sys.stderr)
        return []

    findings: list[tuple[int, str]] = []
    # Depth of `mod tests { ... }` blocks the cursor is inside. Any `#[allow]`
    # seen while depth > 0 is treated as test code.
    test_mod_depth = 0
    # Brace stack so we can decrement test_mod_depth correctly. We only track
    # braces inside test modules — outside, we don't care. This is an
    # approximation (ignores braces in strings / comments) but matches the
    # workspace style: `mod tests {` lives at column 0 and its contents
    # are well-formed Rust with matched braces.
    brace_open_count_inside_test_mod = 0

    for i, raw in enumerate(lines):
        line = raw  # preserve leading whitespace for regex

        # Track test-module entry/exit by counting braces while inside.
        if test_mod_depth > 0:
            # Strip string literals crudely before counting.
            stripped = re.sub(r'"[^"]*"', "", line)
            stripped = re.sub(r"'[^']*'", "", stripped)
            brace_open_count_inside_test_mod += stripped.count("{")
            brace_open_count_inside_test_mod -= stripped.count("}")
            if brace_open_count_inside_test_mod <= 0:
                test_mod_depth = 0
                brace_open_count_inside_test_mod = 0

        # Entering a `mod tests {` on this line?
        if MOD_TEST_RE.match(line):
            test_mod_depth = 1
            # The opening `{` is on this line — count it.
            brace_open_count_inside_test_mod = line.count("{") - line.count("}")
            continue

        m = ALLOW_RE.match(line)
        if not m:
            continue

        # Skip if inside a test module.
        if test_mod_depth > 0:
            continue

        lints = m.group(1).strip()

        # Walk backwards skipping blanks and non-justifying attributes to find
        # the comment (or not) immediately preceding this `#[allow]`.
        prev = i - 1
        # Skip `#[cfg(...)]`, `#[cfg_attr(...)]`, and similar attribute lines
        # that naturally sit between a comment and the `#[allow]`.
        attr_re = re.compile(r"^\s*#\[(cfg|cfg_attr|cfg_eval|derive|must_use|inline)\b")
        while prev >= 0:
            stripped = lines[prev].strip()
            if stripped == "":
                prev -= 1
                continue
            if attr_re.match(lines[prev]):
                # `#[cfg(test)]` directly above means this site IS a test guard
                # — drop the finding entirely.
                if CFG_TEST_RE.match(lines[prev]):
                    prev = None  # sentinel meaning "skip this site"
                    break
                prev -= 1
                continue
            break

        if prev is None:
            continue  # gated by #[cfg(test)] — not production

        if prev < 0:
            findings.append((i + 1, lints))
            continue

        # The preceding non-blank, non-attribute line must be a `//` comment
        # containing `justification:`.
        prev_line = lines[prev].lstrip()
        is_comment = prev_line.startswith("//") and not prev_line.startswith("///")
        if not is_comment:
            findings.append((i + 1, lints))
            continue

        # Walk upward through the `//` comment block to find a `justification:`
        # marker. This permits multi-line justification comments.
        found = False
        j = prev
        while j >= 0:
            cand = lines[j].lstrip()
            if not cand.startswith("//"):
                break
            if cand.startswith("///"):
                break
            if "justification:" in cand:
                found = True
                break
            j -= 1

        if not found:
            findings.append((i + 1, lints))

    return findings


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(f"usage: {argv[0]} [crates-root]", file=sys.stderr)
        return 2
    crates_root = Path(argv[1]) if len(argv) == 2 else Path("crates")
    if not crates_root.is_dir():
        print(f"::error::crates root not found: {crates_root}", file=sys.stderr)
        return 2

    total_files = 0
    total_findings = 0
    for path in iter_rust_sources(crates_root):
        total_files += 1
        findings = find_unjustified_allows(path)
        for lineno, lints in findings:
            total_findings += 1
            rel = path.as_posix()
            print(
                f"::error file={rel},line={lineno}::"
                f"missing `// justification:` comment above #[allow({lints})] — "
                f"see rules/shared-infrastructure.md 'Allow annotations' section "
                f"(F-156).",
                file=sys.stderr,
            )

    if total_findings > 0:
        print(
            f"\n{total_findings} un-justified #[allow] annotation(s) across "
            f"{total_files} scanned files. Add a `// justification: ...` comment "
            f"immediately above each, or move the code under `#[cfg(test)]`.",
            file=sys.stderr,
        )
        return 1

    print(f"scanned {total_files} production source files — all #[allow] sites justified.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

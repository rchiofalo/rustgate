#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Roberto Chiofalo
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract the [advisories].ignore list from deny.toml and emit `cargo audit
--ignore` flags.

The CI `audit` job runs `cargo deny check`, which honours the
in-config `ignore` array directly. The CI `audit-soft` job runs
`cargo audit`, which has its own CLI flag interface. This script keeps
the two in lockstep so the deny.toml `ignore` array is the single source
of truth for "advisories we knowingly accept" and prevents drift between
the two tools.

Output is a single line of CLI flags, e.g.

    --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2025-1234

If the ignore list is empty, output is also empty (no flags).

Usage:
    python3 scripts/extract-audit-ignores.py [DENY_TOML_PATH]

Defaults DENY_TOML_PATH to the deny.toml at the repository root.

Why a hand-rolled regex parser instead of `tomllib` / `tomli`:

- `tomllib` only ships with Python 3.11+. Older runners (and the
  minimum-Python contract documented elsewhere in CI) target 3.9, so
  reaching for `tomllib` would either force a Python upgrade or pull
  in `tomli` from PyPI for one tiny use-case. Neither is worth it.
- The format we parse is intentionally narrow: a single inline-string
  array under `[advisories]` named `ignore`. The parser below only
  accepts that exact shape and rejects anything more complex, so a
  future contributor who tries to add `{ id = "...", reason = "..." }`
  table-form entries will get a hard error pointing them at this
  script (which is the desired behaviour — table-form ignores would
  also need a different `cargo audit` invocation).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Pattern: line containing a quoted RUSTSEC ID, possibly preceded by
# whitespace and followed by a comma and/or comment. We intentionally
# pin the prefix `RUSTSEC-` so a stray quoted string elsewhere in the
# section (e.g. a future `reason = "..."` field) cannot sneak in.
RUSTSEC_LINE_RE = re.compile(r'"\s*(RUSTSEC-\d{4}-\d{4})\s*"')


def extract(deny_toml: Path) -> list[str]:
    """Return the ordered list of RUSTSEC IDs from deny.toml's
    [advisories].ignore array. Raises SystemExit on parse failure.
    """
    if not deny_toml.is_file():
        print(f"::error::{deny_toml} not found", file=sys.stderr)
        sys.exit(2)

    text = deny_toml.read_text(encoding="utf-8")

    # Find the [advisories] section by header, then the ignore = [ ... ]
    # block within it. We bound the scan to the next `[` header so a
    # later [bans] / [licenses] block with its own ignored item cannot
    # leak into the audit-side ignore list.
    advisories_match = re.search(
        r"^\[advisories\]\s*$",
        text,
        flags=re.MULTILINE,
    )
    if not advisories_match:
        # No [advisories] section at all is fine — nothing to ignore.
        return []

    section_start = advisories_match.end()
    next_section = re.search(
        r"^\s*\[",
        text[section_start:],
        flags=re.MULTILINE,
    )
    section_end = (
        section_start + next_section.start()
        if next_section
        else len(text)
    )
    section = text[section_start:section_end]

    ignore_match = re.search(
        r"ignore\s*=\s*\[(?P<body>.*?)\]",
        section,
        flags=re.DOTALL,
    )
    if not ignore_match:
        return []

    body = ignore_match.group("body")
    return RUSTSEC_LINE_RE.findall(body)


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(
            "usage: extract-audit-ignores.py [DENY_TOML_PATH]",
            file=sys.stderr,
        )
        return 2
    deny_toml = (
        Path(argv[1])
        if len(argv) == 2
        else Path(__file__).resolve().parents[1] / "deny.toml"
    )
    ids = extract(deny_toml)
    # Emit one `--ignore <ID>` per entry, joined with single spaces, on
    # a single line so the CI `run:` block can splice the result into
    # a `cargo audit` invocation directly.
    flags = " ".join(f"--ignore {advisory_id}" for advisory_id in ids)
    print(flags)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

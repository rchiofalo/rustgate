#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Roberto Chiofalo
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify a release binary's size has not regressed against the checked-in baseline.

Usage:
    check-binary-size.py <binary-id> <binary-path>

Arguments:
    binary-id    Key under `binaries` in ci/binary-size-baseline.json
                 (e.g. "rustgate-default"). Selects which baseline to compare.
    binary-path  Filesystem path to the built (and preferably stripped)
                 release binary to measure.

Behavior:
  * Reads ci/binary-size-baseline.json from the repo root.
  * Looks up the baseline under `binaries[<binary-id>].baseline_bytes`.
  * Measures the current binary size in bytes.
  * Emits a GitHub Actions summary row and a `::notice::` annotation
    with the absolute size and delta vs. baseline.
  * If baseline_bytes == 0 (unset): reports the observed size and exits 0
    with a `::notice::` telling the reviewer to commit the observed value.
  * If baseline_bytes > 0: compares current vs baseline. If the growth
    exceeds `_threshold_percent` (default 10%), emits `::error::`, writes
    to the step summary, and exits non-zero. Shrinkage and growth within
    threshold pass with a `::notice::`.

The intent is that a PR which legitimately grows the binary (new feature,
new dep) also bumps baseline_bytes in the same PR so the delta is visible
in code review.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO_ROOT / "ci" / "binary-size-baseline.json"
DEFAULT_THRESHOLD_PERCENT = 10.0


def load_baseline() -> dict:
    if not BASELINE_FILE.is_file():
        fail(f"baseline file not found: {BASELINE_FILE}")
    with BASELINE_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def fmt_bytes(n: int) -> str:
    """Human-readable size with one decimal (binary units)."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024.0 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} GiB"


def write_summary(lines: list[str]) -> None:
    """Append to the GitHub step summary if the env var is set."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    binary_id = sys.argv[1]
    binary_path = Path(sys.argv[2])

    if not binary_path.is_file():
        fail(f"binary not found: {binary_path}")

    current_bytes = binary_path.stat().st_size
    baseline = load_baseline()
    threshold_percent = float(baseline.get("_threshold_percent", DEFAULT_THRESHOLD_PERCENT))
    binaries = baseline.get("binaries", {})
    entry = binaries.get(binary_id)
    if entry is None:
        fail(
            f"binary id '{binary_id}' not present in {BASELINE_FILE.name}. "
            f"Add it under `binaries` with baseline_bytes=0 to establish the baseline."
        )

    baseline_bytes = int(entry.get("baseline_bytes", 0))
    features = entry.get("features", "(none)")

    # Always print absolute size so trends can be grepped from CI logs.
    print(f"Binary: {binary_id}")
    print(f"  path: {binary_path}")
    print(f"  features: {features}")
    print(f"  current size: {current_bytes} bytes ({fmt_bytes(current_bytes)})")

    if baseline_bytes <= 0:
        msg = (
            f"Baseline for '{binary_id}' is unset; observed size is "
            f"{current_bytes} bytes ({fmt_bytes(current_bytes)}). "
            f"Commit this value to ci/binary-size-baseline.json "
            f"to enable regression enforcement."
        )
        print(f"::notice::{msg}")
        write_summary(
            [
                f"### Binary size — `{binary_id}`",
                "",
                f"| | Size |",
                f"|---|---|",
                f"| Current | **{fmt_bytes(current_bytes)}** ({current_bytes:,} bytes) |",
                f"| Baseline | _(unset — record this size to enable gate)_ |",
                "",
                "> Baseline is 0. This run recorded the observed size only.",
                "> Edit `ci/binary-size-baseline.json` and set `baseline_bytes` "
                "> to enable the ±"
                f"{threshold_percent:.0f}% regression gate.",
            ]
        )
        return 0

    delta_bytes = current_bytes - baseline_bytes
    delta_percent = (delta_bytes / baseline_bytes) * 100.0
    sign = "+" if delta_bytes >= 0 else ""
    delta_str = f"{sign}{delta_bytes:,} bytes ({sign}{delta_percent:.2f}%)"

    print(f"  baseline:     {baseline_bytes} bytes ({fmt_bytes(baseline_bytes)})")
    print(f"  delta:        {delta_str}")

    summary_lines = [
        f"### Binary size — `{binary_id}`",
        "",
        f"| | Size |",
        f"|---|---|",
        f"| Baseline | {fmt_bytes(baseline_bytes)} ({baseline_bytes:,} bytes) |",
        f"| Current  | **{fmt_bytes(current_bytes)}** ({current_bytes:,} bytes) |",
        f"| Delta    | {delta_str} |",
        f"| Threshold | ±{threshold_percent:.2f}% |",
    ]

    if delta_percent > threshold_percent:
        summary_lines += [
            "",
            f"> :x: Growth exceeds +{threshold_percent:.0f}% threshold.",
            "> If this growth is intentional (new feature / dependency), bump "
            "`baseline_bytes` in `ci/binary-size-baseline.json` in the same PR "
            "so the delta is visible in review.",
        ]
        write_summary(summary_lines)
        print(
            f"::error::Binary '{binary_id}' grew by {delta_str}, "
            f"exceeding the +{threshold_percent:.0f}% threshold. "
            f"Bump baseline_bytes in ci/binary-size-baseline.json if intentional."
        )
        return 1

    if delta_percent < -threshold_percent:
        # Shrinkage is good but worth calling out so the baseline is updated.
        summary_lines += [
            "",
            f"> :white_check_mark: Binary shrank by {delta_str} — "
            f"please bump `baseline_bytes` down so future regressions "
            f"are measured against the tighter bound.",
        ]
        print(
            f"::notice::Binary '{binary_id}' shrank by {delta_str}. "
            f"Consider tightening the baseline."
        )
    else:
        summary_lines += [
            "",
            f"> :white_check_mark: Within ±{threshold_percent:.0f}% threshold.",
        ]
        print(f"::notice::Binary '{binary_id}' delta {delta_str} within threshold.")

    write_summary(summary_lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())

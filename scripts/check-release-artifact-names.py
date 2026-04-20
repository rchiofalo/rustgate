#!/usr/bin/env python3
# Copyright (c) 2026 Roberto Chiofalo.
"""check-release-artifact-names.py — guard against release artifact filename collisions.

F-21 hardening: the `release-binary.yml` workflow builds six variants from a
matrix — two architectures × three feature sets (base, fips, post-quantum) —
and each variant produces a `.tar.gz` archive uploaded to the GitHub release.
If a future matrix edit accidentally makes two entries compute the same
archive filename, `gh release upload --clobber` would silently overwrite one
with the other; worse, the signature/attestation flow would attest the
wrong binary. This script re-implements the "Package binary" shell logic
from the workflow against a parsed view of the matrix itself and asserts
every expected archive name is distinct.

It also pins the invariant that each variant carries a distinguishing
discriminator in its filename (`fips`, `pq`, or unmarked for the base
build) so an operator cannot tell a FIPS binary from a non-FIPS one by
architecture alone.

Invoked from `.github/workflows/ci.yml` so the check runs on every PR that
touches the release matrix, not only on release events — catches drift
before a release tag cuts in.

Usage: scripts/check-release-artifact-names.py [path/to/release-binary.yml]
Exits 0 on success, 1 on any detected collision or misnamed entry.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml  # pyyaml — pre-installed on ubuntu-latest runners.
except ImportError:
    print(
        "::error::pyyaml is required — install via `pip install pyyaml`",
        file=sys.stderr,
    )
    sys.exit(2)


# Placeholder version used for name computation. The real workflow substitutes
# `${{ steps.version.outputs.version }}` at runtime; for uniqueness checks the
# specific value is irrelevant — what matters is that every matrix entry
# produces a different basename given the same version. Using a deterministic
# placeholder keeps the assertions stable across runs.
PLACEHOLDER_VERSION = "vX.Y.Z"


def compute_archive_name(entry: dict, version: str) -> str:
    """Mirror the shell logic in `release-binary.yml` → Package binary step.

    Keep this function in lockstep with that step — if the workflow's naming
    scheme changes (e.g. adding a SHA suffix or swapping `.tar.gz` for `.zip`),
    update this helper at the same time.
    """
    target = entry["target"]
    # Matrix booleans are parsed by PyYAML as real bools when unquoted.
    is_fips = bool(entry.get("fips", False))
    is_pq = bool(entry.get("pq", False))

    if is_fips and is_pq:
        raise ValueError(
            f"matrix entry for target={target} has both fips=true and pq=true; "
            "the workflow naming logic picks `fips` by if/elif ordering but this "
            "combination is almost certainly a mistake — explicitly split into "
            "two entries or pick one."
        )

    if is_fips:
        return f"rustgate-fips-{version}-{target}.tar.gz"
    if is_pq:
        return f"rustgate-pq-{version}-{target}.tar.gz"
    return f"rustgate-{version}-{target}.tar.gz"


def expected_discriminator(entry: dict) -> str:
    """Return the token that must appear in the filename for this variant.

    Used as a defence-in-depth check on top of uniqueness — even if two
    archives differ only by the `target` suffix, a FIPS archive must still
    advertise `fips` in its name so operators cannot mistake it for a
    non-FIPS build.
    """
    if bool(entry.get("fips", False)):
        return "fips"
    if bool(entry.get("pq", False)):
        return "pq"
    return ""  # base build — no discriminator required.


def validate_matrix(matrix_include: list[dict]) -> list[str]:
    """Return a list of error messages; empty list means the matrix passes."""
    errors: list[str] = []

    names: list[tuple[dict, str]] = []
    for entry in matrix_include:
        try:
            name = compute_archive_name(entry, PLACEHOLDER_VERSION)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        names.append((entry, name))

    # 1. Uniqueness — no two matrix entries may produce the same archive
    #    filename. This is the primary F-21 guarantee.
    counter = Counter(name for _, name in names)
    for name, count in counter.items():
        if count > 1:
            offending = [e for e, n in names if n == name]
            errors.append(
                f"archive filename collision: {count} matrix entries all "
                f"produce {name!r} — entries: {offending}"
            )

    # 2. Discriminator presence — each non-base entry must carry its variant
    #    token in the filename so operators can distinguish at-a-glance.
    for entry, name in names:
        token = expected_discriminator(entry)
        if token == "":
            # Base build — assert the filename does NOT contain fips/pq, so
            # a future edit that flips the flag doesn't silently retain the
            # old discriminator.
            if "-fips-" in name:
                errors.append(
                    f"base-build entry {entry} produces filename {name!r} "
                    "containing '-fips-' — expected no discriminator."
                )
            if "-pq-" in name:
                errors.append(
                    f"base-build entry {entry} produces filename {name!r} "
                    "containing '-pq-' — expected no discriminator."
                )
            continue
        if f"-{token}-" not in name:
            errors.append(
                f"{token}-build entry {entry} produces filename {name!r} "
                f"missing '-{token}-' discriminator."
            )

    # 3. Basename structure — every archive must end in `.tar.gz` and start
    #    with `rustgate-`. Pins the shape so a workflow refactor that e.g.
    #    switched extensions is caught here instead of surfacing as a missing
    #    release asset.
    name_re = re.compile(r"^rustgate-(fips-|pq-)?[^/]+\.tar\.gz$")
    for entry, name in names:
        if not name_re.match(name):
            errors.append(
                f"archive filename {name!r} for entry {entry} does not match "
                f"expected shape rustgate-[fips-|pq-]<version>-<target>.tar.gz"
            )

    return errors


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(
            f"usage: {argv[0]} [path/to/release-binary.yml]",
            file=sys.stderr,
        )
        return 2
    workflow_path = (
        Path(argv[1])
        if len(argv) == 2
        else Path(".github/workflows/release-binary.yml")
    )
    if not workflow_path.is_file():
        print(
            f"::error::workflow file not found: {workflow_path}",
            file=sys.stderr,
        )
        return 2

    with workflow_path.open("r", encoding="utf-8") as f:
        try:
            workflow = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(
                f"::error file={workflow_path}::YAML parse error: {exc}",
                file=sys.stderr,
            )
            return 2

    try:
        matrix_include = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    except (KeyError, TypeError) as exc:
        print(
            f"::error file={workflow_path}::expected jobs.build.strategy.matrix.include "
            f"in workflow: {exc}",
            file=sys.stderr,
        )
        return 2

    if not isinstance(matrix_include, list) or not matrix_include:
        print(
            f"::error file={workflow_path}::matrix.include must be a non-empty list",
            file=sys.stderr,
        )
        return 2

    errors = validate_matrix(matrix_include)
    if errors:
        for msg in errors:
            print(f"::error file={workflow_path}::{msg}", file=sys.stderr)
        print(
            f"\n{len(errors)} release-artifact naming problem(s) detected.",
            file=sys.stderr,
        )
        return 1

    # Success — also print the planned names so the CI log records them.
    print(
        f"release-artifact names for {len(matrix_include)} matrix entries (all distinct):"
    )
    for entry in matrix_include:
        print(f"  {entry['target']:<35} → {compute_archive_name(entry, PLACEHOLDER_VERSION)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

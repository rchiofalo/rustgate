#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Roberto Chiofalo
# SPDX-License-Identifier: AGPL-3.0-only
# check-lock-pins.sh — fail fast when a hand-maintained Cargo.lock pin regresses.
#
# Usage: scripts/check-lock-pins.sh [path/to/Cargo.lock]   (default: Cargo.lock)
#
# Pins checked:
#   1. bindgen -> syn 2. bindgen 0.73 (a build dependency of aws-lc-fips-sys)
#      declares `syn >=2,<4`, but its prettyplease 0.2 dependency is built on
#      syn 2. Any re-resolve of the lockfile (`cargo update -p X`, a
#      Dependabot PR) moves bindgen to syn 3 once syn 3 is in the graph, and
#      the `--features fips` build then fails with the obscure
#      `syn::file::File: syn::parse_quote::ParseQuote` E0277. This check
#      catches it in seconds from the lockfile alone, with no Rust build.
#
# Skips cleanly when bindgen is absent from the lock, or when bindgen has
# moved off the 0.73 line (a newer bindgen may support syn 3; confirm and
# remove this guard).
#
# Emits GitHub Actions `::error file=…,line=…::` annotations on findings and
# exits non-zero when any check fails.

set -euo pipefail

LOCK="${1:-Cargo.lock}"

# bindgen versions known to accept syn 3 while their prettyplease needs syn 2.
GUARDED_BINDGEN='^0\.73\.'

if [[ ! -f "$LOCK" ]]; then
    echo "::error::check-lock-pins.sh: ${LOCK} not found (run from the repository root)." >&2
    exit 2
fi

# Flatten the lockfile into tab-separated records:
#   SYN     <version>
#   BINDGEN <version>
#   BDEP    <bindgen version> <line> <dependency name+version>
records="$(awk '
    /^\[\[package\]\]/ { name = ""; version = ""; in_deps = 0; next }
    /^name = "/        { name = $3; gsub(/"/, "", name); next }
    /^version = "/     {
        version = $3; gsub(/"/, "", version)
        if (name == "syn")     print "SYN\t" version
        if (name == "bindgen") print "BINDGEN\t" version
        next
    }
    /^dependencies = \[/ { in_deps = 1; next }
    in_deps && /^\]/     { in_deps = 0; next }
    in_deps && name == "bindgen" {
        dep = $0; gsub(/^ *"|",?$/, "", dep)
        print "BDEP\t" version "\t" NR "\t" dep
    }
' "$LOCK")"

syn_versions=()
while IFS=$'\t' read -r _ v; do
    syn_versions+=("$v")
done < <(grep '^SYN' <<<"$records" || true)

syn2=""
for v in "${syn_versions[@]+"${syn_versions[@]}"}"; do
    [[ "$v" == 2.* ]] && syn2="$v"
done

bindgen_versions="$(grep '^BINDGEN' <<<"$records" | cut -f2 || true)"
if [[ -z "$bindgen_versions" ]]; then
    echo "check-lock-pins: bindgen is not in ${LOCK}; the bindgen -> syn 2 pin no longer applies and this guard can be removed."
    exit 0
fi

fail=0
checked=0
for bv in $bindgen_versions; do
    if ! [[ "$bv" =~ $GUARDED_BINDGEN ]]; then
        echo "check-lock-pins: bindgen ${bv} is past the 0.73 line; skipping the syn 2 pin check."
        echo "  If bindgen ${bv} (and its prettyplease) build against syn 3, remove this guard and the pin comment above aws-lc-rs in Cargo.toml."
        continue
    fi
    checked=1

    while IFS=$'\t' read -r _ dep_bv line dep; do
        [[ "$dep_bv" == "$bv" ]] || continue
        case "$dep" in
            "syn "*) resolved="${dep#syn }" ;;
            # Cargo omits the version when the lock holds a single syn.
            "syn")   resolved="${syn_versions[0]:-}" ;;
            *)       continue ;;
        esac
        [[ "$resolved" == 3.* ]] || continue

        target="${syn2:-2.x}"
        echo "::error file=${LOCK},line=${line}::bindgen ${bv} depends on \"${dep}\" (syn ${resolved}); the --features fips build will fail. Pin it back to syn 2."
        echo "  bindgen 0.73 accepts syn >=2,<4, but its prettyplease 0.2 dependency needs syn 2."
        echo "  Fix: in ${LOCK} line ${line} (the [[package]] name = \"bindgen\" block), change"
        echo "         \"${dep}\","
        echo "       to"
        echo "         \"syn ${target}\","
        if [[ -z "$syn2" ]]; then
            echo "       (no syn 2.x package is left in the lock; restore one from git history first)"
        fi
        echo "  Then verify the edited lock is still consistent:"
        echo "         cargo metadata --locked --format-version 1 > /dev/null"
        fail=1
    done < <(grep '^BDEP' <<<"$records" || true)
done

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi

if [[ "$checked" -ne 0 ]]; then
    echo "check-lock-pins: OK (bindgen -> syn ${syn2:-2.x} pin intact)."
fi

#!/usr/bin/env bash
# check-playbook-drift.sh — enforce shared-infrastructure patterns mechanically.
#
# Run from the repository root. Emits GitHub Actions
# `::error file=…,line=…::` annotations on findings so CI highlights the
# offending line, and exits non-zero when any check fails.
#
# Checks:
#   1. duplicate-constants   — core constants (MAX_FRAME_SIZE, timeouts, …)
#                              must not be re-declared outside
#                              rustgate-core/src/constants.rs.
#   2. tcp-keepalive         — every file that uses `TcpListener` must also
#                              call `rustgate_core::net::configure_tcp_keepalive`
#                              (or the combined `configure_tactical_socket`
#                              helper, which also sets `TCP_NODELAY`) on
#                              accepted streams.
#   3. rejection-audit       — rejection-themed `tracing::warn!`/`warn!` must
#                              be followed within 10 lines by an `audit::*`
#                              call so the compliance trail stays intact.
#   4. credential-eq         — `==` must not compare password/token/secret
#                              values (use `subtle::ConstantTimeEq::ct_eq`).
#
# Opt-out marker: add `// playbook-drift-ok: <reason>` on the same line as a
# would-be finding to suppress that one match (intentional escape hatch for
# rare cases — reviewers should scrutinize every use).

set -euo pipefail

if [[ ! -f Cargo.toml || ! -d crates ]]; then
    echo "::error::check-playbook-drift.sh must run from the repository root." >&2
    exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
    echo "::error::ripgrep (rg) is required — install via apt/brew/cargo." >&2
    exit 2
fi

fail=0
report() {
    # $1 file, $2 line, $3 message
    local file="$1" line="$2" msg="$3"
    # Honour the opt-out marker on the offending line.
    if sed -n "${line}p" "$file" 2>/dev/null | grep -q 'playbook-drift-ok'; then
        return 0
    fi
    echo "::error file=${file},line=${line}::${msg}"
    fail=$((fail + 1))
}

# ---------------------------------------------------------------------------
# Check 1: duplicate core constants.
# ---------------------------------------------------------------------------
check_duplicate_constants() {
    echo "• duplicate core constants"
    local names=(
        MAX_FRAME_SIZE
        READ_TIMEOUT
        WRITE_TIMEOUT
        HANDSHAKE_TIMEOUT
        HTTP_CONNECTION_TIMEOUT
        FEDERATION_HEARTBEAT_INTERVAL
        FEDERATION_HEARTBEAT_TIMEOUT
        FEDERATION_MAX_RECONNECT_DELAY
        PLAINTEXT_GROUP
        ANONYMOUS_IDENTITY
        SOURCE_FEDERATION
    )
    local joined
    joined=$(
        IFS='|'
        echo "${names[*]}"
    )
    local pattern="\\b(const|static)\\s+(${joined})\\s*:"
    local hits
    # Skip all of rustgate-core — that is the canonical home of these
    # constants (constants.rs for most, message.rs for SOURCE_FEDERATION).
    # Any re-definition *outside* core counts as drift.
    hits=$(
        rg -n --type rust \
            --glob '!crates/rustgate-core/**' \
            -e "$pattern" crates/ || true
    )
    [[ -z "$hits" ]] && return 0
    while IFS= read -r row; do
        local file line
        file=${row%%:*}
        line=${row#*:}
        line=${line%%:*}
        report "$file" "$line" \
            "duplicate core constant — import from \`rustgate_core::constants\` instead (see .claude/rules/shared-infrastructure.md)."
    done <<<"$hits"
}

# ---------------------------------------------------------------------------
# Check 2: TcpListener without configure_tcp_keepalive.
# Every accepted TCP stream must pass through
# `rustgate_core::net::configure_tcp_keepalive` before TLS negotiation.
# Allow-listed files: core/net.rs defines the helper; test fixtures are
# exempt because they don't carry production traffic.
# ---------------------------------------------------------------------------
check_tcp_keepalive() {
    echo "• TcpListener keepalive coverage"
    local allow='^crates/rustgate-core/src/net\.rs$|^crates/rustgate-test-utils/'
    local file
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        [[ "$file" =~ $allow ]] && continue
        # Require an actual call site (`\(`) so a comment that merely
        # mentions the helper can't silence the check. `configure_tactical_socket`
        # is a strict superset (keepalive + `TCP_NODELAY`) and satisfies the
        # check — see `rustgate-core::net`.
        if ! rg -q 'configure_tcp_keepalive\(|configure_tactical_socket\(' "$file"; then
            local line
            line=$(rg -n 'TcpListener' "$file" | head -1 | cut -d: -f1)
            report "$file" "${line:-1}" \
                "TcpListener is used but neither \`configure_tcp_keepalive\` nor \`configure_tactical_socket\` is called — every accepted stream must go through one of these \`rustgate_core::net\` helpers."
        fi
    done < <(rg -l --type rust 'TcpListener' crates/*/src/ 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# Check 3: rejection-themed warn! without a nearby audit::* call.
# The warn log is the human-readable signal; the audit call is the
# tamper-evident compliance record. They must co-locate.
# ---------------------------------------------------------------------------
check_rejection_audit() {
    echo "• rejection → audit co-location"
    # Rejection keywords the warn message must contain.
    local keywords='reject|denied|refused|unauthorized|quota|limit exceeded|blocked|forbidden'
    # Match single-line `warn!(…rejected…)` / `tracing::warn!(…)` calls.
    # Multi-line warn! invocations (keyword on a later arg line) are out
    # of scope for this heuristic — tracking that statically triggers too
    # many false positives on descriptive messages like "may be rejected"
    # or backpressure "limit exceeded" that are not security events.
    local warn_pattern="(tracing::)?warn!\\([^)]*(${keywords})"
    local hits
    hits=$(
        rg -n --type rust \
            --glob '!**/tests.rs' \
            --glob '!**/*_test.rs' \
            --glob '!**/tests/**' \
            -e "$warn_pattern" crates/ || true
    )
    [[ -z "$hits" ]] && return 0
    while IFS= read -r row; do
        local file line
        file=${row%%:*}
        line=${row#*:}
        line=${line%%:*}
        # Look for an actual audit-module call within the 10 lines
        # following the warn. Require a `\(` or `!\(` so a comment that
        # merely mentions `audit::` cannot silence the check.
        local window_end=$((line + 10))
        if ! sed -n "${line},${window_end}p" "$file" |
            grep -qE 'audit::[a-z_]+\(|audit!\('; then
            report "$file" "$line" \
                "rejection-themed warn! without a companion \`audit::*\` call within 10 lines — see .claude/rules/shared-infrastructure.md (Audit System)."
        fi
    done <<<"$hits"
}

# ---------------------------------------------------------------------------
# Check 4: `==` comparisons on credential-named values.
# Password/token/secret comparisons leak length and prefix via timing when
# compared with `==`; use `subtle::ConstantTimeEq::ct_eq` instead.
# ---------------------------------------------------------------------------
check_credential_eq() {
    echo "• credential equality discipline"
    local names='password|token|secret|credential|api_key|bearer|hmac_key|passphrase'
    # Match an identifier (or `.as_bytes()` slice of one) on either side of `==`.
    # Narrow the match to rust files; exclude tests where fixtures legitimately
    # compare literals.
    local pattern="(\\b(${names})[a-zA-Z0-9_]*([[:space:]]*\\.[a-zA-Z_]+\\(\\))?[[:space:]]*==|==[[:space:]]*\\b(${names})[a-zA-Z0-9_]*)"
    local hits
    hits=$(
        rg -n --type rust \
            --glob '!**/tests.rs' \
            --glob '!**/*_test.rs' \
            --glob '!**/tests/**' \
            --glob '!crates/*/tests/**' \
            -e "$pattern" crates/ || true
    )
    [[ -z "$hits" ]] && return 0
    while IFS= read -r row; do
        local file line content
        file=${row%%:*}
        line=${row#*:}
        content=${line#*:}
        line=${line%%:*}
        # Allow-list: empty-string, None, or Option::Some/None pattern checks
        # — those leak no sensitive timing information.
        if [[ "$content" =~ ==[[:space:]]*\"\"[[:space:]]*\$ ]] ||
            [[ "$content" =~ ==[[:space:]]*None ]] ||
            [[ "$content" =~ ==[[:space:]]*Some ]]; then
            continue
        fi
        report "$file" "$line" \
            "possible non-constant-time credential comparison — use \`subtle::ConstantTimeEq::ct_eq\` (see .claude/rules/shared-infrastructure.md §Constant-Time Credential Comparison)."
    done <<<"$hits"
}

check_duplicate_constants
check_tcp_keepalive
check_rejection_audit
check_credential_eq

echo
if [[ "$fail" -gt 0 ]]; then
    echo "::error::check-playbook-drift.sh: ${fail} finding(s). Fix by reaching for the canonical helper listed in .claude/rules/shared-infrastructure.md — or add \`// playbook-drift-ok: <reason>\` to the offending line if the exception is genuinely warranted."
    exit 1
fi
echo "playbook drift check passed — no findings."

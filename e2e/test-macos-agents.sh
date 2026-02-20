#!/usr/bin/env bash
# test-macos-agents.sh - e2e smoke-tests halt with each macOS agent config.
#
# For each agent config we validate:
#   1. Filesystem (Seatbelt/SBPL):
#      - workspace write succeeds (true positive)
#      - workspace read succeeds (true positive)
#      - write outside allowed paths is denied (true negative)
#   2. Network proxy:
#      - blocked domain via HTTPS CONNECT is rejected (curl exit 56)
#      - strict mode exits 2 on blocked SOCKS5 domain CONNECT
#      - strict mode does NOT trip on an allowlisted SOCKS5 domain
#
# Requirements:
#   - macOS (sandbox-exec available)
#   - halt binary (HALT env var, default: ./target/release/halt)
#   - curl
#
# Usage:
#   e2e/test-macos-agents.sh
#   HALT=/usr/local/bin/halt e2e/test-macos-agents.sh
#
# Exit codes: 0 = all tests passed, 1 = at least one test failed.

set -euo pipefail

HALT=${HALT:-./target/release/halt}
CONFIGS_DIR=${CONFIGS_DIR:-configs}
PASS=0
FAIL=0
LAST_EXIT=0
WORKSPACE=$(mktemp -d)
trap 'rm -rf "$WORKSPACE"' EXIT

green() { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; }

pass() { green "$1"; PASS=$((PASS + 1)); }
fail() { red "$1"; FAIL=$((FAIL + 1)); }

run_halt() {
    local stderr_file="$1"
    shift
    set +e
    "$HALT" run --no-config "$@" 2>"$stderr_file"
    LAST_EXIT=$?
    set -e
    return 0
}

assert_exit() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    local stderr_file="$4"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label"
    else
        fail "$label (expected exit $expected, got $actual)"
        cat "$stderr_file" >&2 || true
    fi
}

strict_socks5_script() {
    cat <<'SOCKS5'
set -e
PROXY_PORT=$(echo "${HTTP_PROXY:-}" | grep -oE '[0-9]+$' || true)
[ -z "$PROXY_PORT" ] && exit 1
exec 3<>/dev/tcp/127.0.0.1/${PROXY_PORT}
printf '\x05\x01\x00' >&3
sleep 0.1
printf '%b' "${SOCKS5_PAYLOAD:?}" >&3
exec 3>&-
sleep 0.3
SOCKS5
}

blocked_socks5_payload() {
    # SOCKS5 CONNECT request for "blocked-domain.example" (len 0x16), port 80.
    echo '\x05\x01\x00\x03\x16blocked-domain.example\x00\x50'
}

allowed_socks5_payload_for() {
    case "$1" in
        # "api.anthropic.com" len 17 (0x11)
        claude) echo '\x05\x01\x00\x03\x11api.anthropic.com\x00\x50' ;;
        # "api.openai.com" len 14 (0x0e)
        codex) echo '\x05\x01\x00\x03\x0eapi.openai.com\x00\x50' ;;
        # "generativelanguage.googleapis.com" len 33 (0x21)
        gemini) echo '\x05\x01\x00\x03\x21generativelanguage.googleapis.com\x00\x50' ;;
        *) echo '\x05\x01\x00\x03\x0bexample.com\x00\x50' ;;
    esac
}

for AGENT in claude codex gemini; do
    CONFIG="${CONFIGS_DIR}/${AGENT}.toml"
    STDERR="/tmp/halt_stderr_${AGENT}_$$"
    SENTINEL="${WORKSPACE}/sentinel-${AGENT}.txt"
    BLOCKED_FILE="${HOME}/halt-test-blocked-${AGENT}.$$"
    ALLOWED_SOCKS5_PAYLOAD=$(allowed_socks5_payload_for "$AGENT")
    BLOCKED_SOCKS5_PAYLOAD=$(blocked_socks5_payload)

    echo ""
    echo "── ${AGENT} ─────────────────────────────────────────────────────────"

    run_halt "$STDERR" --config "$CONFIG" -- /bin/sh -c "echo ok > '${SENTINEL}'"
    code=$LAST_EXIT
    if [ "$code" -eq 0 ] && [ -f "$SENTINEL" ]; then
        pass "${AGENT}: workspace write succeeds"
    else
        fail "${AGENT}: workspace write failed (exit $code)"
        cat "$STDERR" >&2 || true
    fi

    run_halt "$STDERR" --config "$CONFIG" -- /bin/cat "$SENTINEL"
    assert_exit 0 "$LAST_EXIT" "${AGENT}: workspace read succeeds" "$STDERR"

    run_halt "$STDERR" --config "$CONFIG" \
        -- /bin/sh -c "echo x > '${BLOCKED_FILE}' 2>/dev/null; exit 0"
    if [ ! -f "$BLOCKED_FILE" ]; then
        pass "${AGENT}: write to \$HOME blocked by sandbox"
    else
        fail "${AGENT}: write to \$HOME was NOT blocked (SBPL not enforced)"
        rm -f "$BLOCKED_FILE"
    fi

    run_halt "$STDERR" --config "$CONFIG" \
        -- curl -sS --max-time 5 https://blocked-domain.invalid -o /dev/null
    assert_exit 56 "$LAST_EXIT" "${AGENT}: blocked domain rejected by proxy (curl exit 56)" "$STDERR"

    run_halt "$STDERR" --config "$CONFIG" --strict \
        -- /usr/bin/env SOCKS5_PAYLOAD="${BLOCKED_SOCKS5_PAYLOAD}" \
           /bin/bash -c "$(strict_socks5_script)"
    assert_exit 2 "$LAST_EXIT" "${AGENT}: strict mode exits 2 on blocked SOCKS5 CONNECT" "$STDERR"

    run_halt "$STDERR" --config "$CONFIG" --strict \
        -- /usr/bin/env SOCKS5_PAYLOAD="${ALLOWED_SOCKS5_PAYLOAD}" \
           /bin/bash -c "$(strict_socks5_script)"
    assert_exit 0 "$LAST_EXIT" "${AGENT}: strict mode allows allowlisted SOCKS5 CONNECT domain" "$STDERR"

    rm -f "$STDERR"
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]

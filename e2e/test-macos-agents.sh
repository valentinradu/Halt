#!/usr/bin/env bash
# test-macos-agents.sh — e2e smoke-tests halt with each macOS agent config.
#
# Tests two aspects for every agent:
#   1. Sandbox starts: halt can run a trivial command under the config.
#   2. Network filtering: a blocked domain gets NXDOMAIN through the proxy.
#
# Requirements:
#   - halt binary (set HALT env var or defaults to ./target/release/halt)
#   - curl
#   - macOS (uses sandbox-exec / SBPL under the hood)
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

green() { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; }

pass() { green "$1"; ((PASS++)); }
fail() { red   "$1"; ((FAIL++)); }

for AGENT in claude codex gemini; do
    CONFIG="${CONFIGS_DIR}/${AGENT}.toml"

    echo ""
    echo "── ${AGENT} ─────────────────────────────────────────────────────────"

    # 1. Config parses and halt starts a trivial sandboxed command.
    if "$HALT" run --no-config --config "$CONFIG" -- /bin/echo "ok-${AGENT}" \
           2>/tmp/halt_stderr_${AGENT}; then
        pass "${AGENT}: sandbox starts"
    else
        fail "${AGENT}: sandbox failed (exit $?)"
        cat /tmp/halt_stderr_${AGENT} >&2
    fi

    # 2. Blocked domain gets NXDOMAIN through the proxy (curl exit 6).
    CURL_EXIT=0
    "$HALT" run --no-config --config "$CONFIG" \
        -- curl -sS --max-time 5 https://blocked-domain.invalid \
           -o /dev/null 2>/dev/null || CURL_EXIT=$?
    if [ "$CURL_EXIT" -eq 6 ]; then
        pass "${AGENT}: blocked domain returns NXDOMAIN"
    else
        fail "${AGENT}: blocked domain not filtered (curl exit ${CURL_EXIT})"
    fi
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]

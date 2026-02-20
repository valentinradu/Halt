#!/usr/bin/env bash
# test-macos-agents.sh — e2e smoke-tests halt with each macOS agent config.
#
# Tests three aspects for every agent:
#   1. Sandbox starts:        halt runs a trivial command under the config.
#   2. Filesystem blocking:   a write to $HOME (outside allowed paths) is denied
#                             by sandbox-exec / SBPL; the file must not appear.
#   3. Network filtering:     a blocked domain is rejected by the HTTP CONNECT
#                             proxy with 403 Forbidden (curl exit 56).
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

pass() { green "$1"; PASS=$((PASS + 1)); }
fail() { red   "$1"; FAIL=$((FAIL + 1)); }

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

    # 2. Write outside allowed paths is blocked by sandbox-exec (SBPL).
    #    $HOME is not in system_defaults read_write, and none of the agent
    #    configs grant write access to arbitrary $HOME paths.  The shell exits
    #    0 explicitly so halt exit code is not affected; we check that the file
    #    was never created.
    BLOCKED_FILE="${HOME}/halt-test-blocked-${AGENT}.$$"
    "$HALT" run --no-config --config "$CONFIG" \
        -- /bin/sh -c "echo x > '${BLOCKED_FILE}' 2>/dev/null; exit 0" || true
    if [ ! -f "${BLOCKED_FILE}" ]; then
        pass "${AGENT}: write to \$HOME blocked by sandbox"
    else
        fail "${AGENT}: write to \$HOME was NOT blocked — SBPL not enforced"
        rm -f "${BLOCKED_FILE}"
    fi

    # 3. Blocked domain is rejected by the HTTP CONNECT proxy (curl exit 56).
    #    On macOS, halt injects HTTP_PROXY=http://127.0.0.1:PORT.  curl sends
    #    CONNECT blocked-domain.invalid:443 HTTP/1.1 and the proxy returns
    #    403 Forbidden — curl exits 56 (CURLE_RECV_ERROR).
    #    (Linux uses DNS interception in a network namespace and exits 6/NXDOMAIN.)
    CURL_EXIT=0
    "$HALT" run --no-config --config "$CONFIG" \
        -- curl -sS --max-time 5 https://blocked-domain.invalid \
           -o /dev/null 2>/dev/null || CURL_EXIT=$?
    if [ "$CURL_EXIT" -eq 56 ]; then
        pass "${AGENT}: blocked domain rejected by proxy (curl exit 56 / 403 Forbidden)"
    else
        fail "${AGENT}: blocked domain not filtered (curl exit ${CURL_EXIT}, expected 56)"
    fi
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]

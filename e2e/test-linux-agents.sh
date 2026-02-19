#!/usr/bin/env bash
# test-linux-agents.sh — e2e smoke-tests halt with each Linux agent config.
#
# Tests two sandbox dimensions for every agent:
#   1. Filesystem (Landlock): workspace is writable; paths outside it are blocked.
#   2. Network (proxy):       allowed domains resolve; blocked domains get NXDOMAIN.
#
# Requirements (already present in the halt-test Docker image):
#   - halt binary in PATH
#   - curl, bash
#   - NET_ADMIN capability (for halt's network namespace creation)
#
# Usage inside the halt-test container:
#   /halt/e2e/test-linux-agents.sh
#
# Exit codes: 0 = all tests passed, 1 = at least one test failed.

set -euo pipefail

HALT=${HALT:-halt}
CONFIGS_DIR=${CONFIGS_DIR:-/halt/configs/linux}
PASS=0
FAIL=0
WORKSPACE=$(mktemp -d)
trap 'rm -rf "$WORKSPACE"' EXIT

# ── Helpers ──────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; }

pass() { green "$1"; ((PASS++)); }
fail() { red   "$1"; ((FAIL++)); }

# run_halt CONFIG ARGS... -- CMD ARGS...
# Returns the exit code of halt (does not abort on failure).
run_halt() {
    local config="$1"; shift
    "$HALT" run --no-config --config "$config" "$@" 2>/tmp/halt_stderr || true
}

# assert_exit EXPECTED ACTUAL LABEL
assert_exit() {
    local expected="$1" actual="$2" label="$3"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label"
    else
        fail "$label (expected exit $expected, got $actual)"
        cat /tmp/halt_stderr >&2 || true
    fi
}

# ── Landlock filesystem tests ─────────────────────────────────────────────────
# These do not require NET_ADMIN because we use --network unrestricted to skip
# network namespace creation while still exercising Landlock.

test_filesystem() {
    local agent="$1"
    local config="$CONFIGS_DIR/${agent}.toml"

    echo ""
    echo "── $agent: filesystem (Landlock) ──────────────────────────────────"

    # 1. Basic execution: a simple command in the workspace must succeed.
    local sentinel="$WORKSPACE/sentinel-${agent}.txt"
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "echo ok > '$sentinel'" </dev/null
    local code=$?
    if [ "$code" -eq 0 ] && [ -f "$sentinel" ]; then
        pass "$agent: workspace write succeeds"
        ((PASS++))
    else
        fail "$agent: workspace write failed (exit $code)"
        ((FAIL++))
    fi

    # 2. Reading a file written inside the workspace must succeed.
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "cat '$sentinel'" </dev/null
    assert_exit 0 $? "$agent: workspace read succeeds"

    # 3. Writing outside the workspace (e.g. /etc/halt-test) must be denied.
    #    Landlock denies writes to paths not in the ruleset; bash exits non-zero.
    run_halt "$config" \
        --network unrestricted \
        -- bash -c "echo x > /etc/halt-test-${agent} 2>/dev/null; exit 0" </dev/null
    # The shell exits 0 because of the explicit `exit 0`, but the write itself
    # silently fails with EACCES — we verify the file was NOT created.
    if [ ! -f "/etc/halt-test-${agent}" ]; then
        pass "$agent: write to /etc blocked by Landlock"
        ((PASS++))
    else
        fail "$agent: write to /etc was NOT blocked — Landlock not enforced"
        ((FAIL++))
        rm -f "/etc/halt-test-${agent}"
    fi
}

# ── Network proxy tests ───────────────────────────────────────────────────────
# Require NET_ADMIN for halt's ProxyOnly network namespace setup.
# We test via curl using HTTP_PROXY injected by halt.

test_network() {
    local agent="$1"
    local config="$CONFIGS_DIR/${agent}.toml"
    # Determine the first domain in the allowlist for this agent.
    local allowed_domain blocked_domain="blocked-domain.invalid"

    case "$agent" in
        claude)  allowed_domain="api.anthropic.com" ;;
        codex)   allowed_domain="api.openai.com" ;;
        gemini)  allowed_domain="generativelanguage.googleapis.com" ;;
        *)       allowed_domain="github.com" ;;
    esac

    echo ""
    echo "── $agent: network (proxy) ─────────────────────────────────────────"

    # 4. Allowed domain: DNS query should resolve (proxy returns A record).
    #    We only check that curl can at least perform DNS resolution — a
    #    connection error is OK, but NXDOMAIN / proxy-blocked is not.
    #    curl exit codes: 6 = DNS fail, 7 = connect fail (host up), 22 = HTTP err
    run_halt "$config" \
        -- curl -sS --max-time 5 \
           "https://${allowed_domain}" \
           -o /dev/null 2>/tmp/halt_stderr </dev/null
    local code=$?
    # exit 7 (connection refused / timeout) means DNS resolved — that's fine.
    # exit 6 (DNS fail) means the proxy blocked or can't resolve — that's a fail.
    if [ "$code" -ne 6 ]; then
        pass "$agent: allowed domain '$allowed_domain' resolved through proxy (curl exit $code)"
        ((PASS++))
    else
        fail "$agent: allowed domain '$allowed_domain' NOT resolved (curl exit $code — DNS blocked?)"
        ((FAIL++))
        cat /tmp/halt_stderr >&2 || true
    fi

    # 5. Blocked domain: proxy must return NXDOMAIN (curl exit 6).
    run_halt "$config" \
        -- curl -sS --max-time 5 \
           "https://${blocked_domain}" \
           -o /dev/null 2>/tmp/halt_stderr </dev/null
    code=$?
    assert_exit 6 $code "$agent: blocked domain '$blocked_domain' gets NXDOMAIN (curl exit 6)"

    # 6. Strict mode: a SOCKS5 request for a blocked domain triggers violation → exit 2.
    #    We use bash /dev/tcp to speak raw SOCKS5 directly to the proxy port,
    #    mirroring the integration test already in the Rust test suite.
    local socks5_script
    socks5_script=$(cat <<'SOCKS5'
PROXY_PORT=$(echo "${HTTP_PROXY:-}" | grep -oE '[0-9]+$')
[ -z "$PROXY_PORT" ] && exit 0
exec 3<>/dev/tcp/127.0.0.1/${PROXY_PORT}
printf '\x05\x01\x00' >&3
sleep 0.1
printf '\x05\x01\x00\x03\x16blocked-domain.example\x00\x50' >&3
exec 3>&-
sleep 0.3
SOCKS5
    )
    run_halt "$config" \
        --strict \
        -- bash -c "$socks5_script" </dev/null
    code=$?
    assert_exit 2 $code "$agent: strict mode exits 2 on blocked SOCKS5 CONNECT"
}

# ── Run all tests for every agent ─────────────────────────────────────────────

for AGENT in claude codex gemini; do
    test_filesystem "$AGENT"
    test_network    "$AGENT"
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]

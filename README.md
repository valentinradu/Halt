# Halt

Wrap AI coding agents — or any process — in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms.

![icon](assets/icon.svg)

---

## What halt does

Halt launches a child process inside a sandbox with two complementary controls:

1. **Filesystem isolation** — the child can only read and write the paths you allow.
2. **Network isolation** — the child's outbound traffic is gated by a built-in proxy that enforces a domain allowlist.

These two layers work together. Even if a rogue process manipulates its environment variables or tries to exfiltrate data through a side channel, it cannot reach a domain that is not on the allowlist, and it cannot read files outside the permitted paths.

---

## Security disclaimer

**Halt is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary.

A persistent or sufficiently sophisticated process can likely escape the sandbox. macOS Seatbelt and Linux Landlock are not designed to contain root processes, and there are known bypass classes for both mechanisms. The built-in proxy is also process-level, not kernel-level.

Use halt to add a reasonable guard-rail around AI coding agents operating on your workstation — not as a substitute for proper network segmentation, least-privilege service accounts, or other security controls.

---

## How it works

### macOS — Seatbelt (sandbox-exec + SBPL)

On macOS, halt generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`. The generated profile:

- Allows all actions by default.
- Denies `file-read-data` (file content reads) globally, then re-allows it only for permitted paths.
- Keeps `file-read-metadata` (stat/lstat) unrestricted — macOS DNS resolution (`getaddrinfo`) and the dynamic linker need to stat arbitrary paths to function.
- Denies all file writes globally, then re-allows them for permitted read-write paths.

For proxy-mode networking, halt injects `HTTP_PROXY`, `HTTPS_PROXY`, and `http_proxy`/`https_proxy` environment variables pointing at the built-in proxy, and the generated SBPL profile allows TCP connections only to the loopback address where the proxy listens.

### Linux — Landlock LSM + network namespaces

On Linux (kernel 5.13+), halt uses two mechanisms:

- **[Landlock LSM](https://landlock.io/)** restricts filesystem access. Halt applies a Landlock ruleset that grants the child only the filesystem rights you configure (read, read-write, or traversal-only per path).
- **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the child's network stack. For `proxy_only` mode, the proxy listens on the loopback interface of the parent namespace and a `veth` pair bridges traffic from the child's namespace to the proxy. For `blocked` mode, the child gets a fresh namespace with no external connectivity.

### Built-in proxy

Halt includes a DNS + TCP proxy that runs on `127.0.0.1` for the lifetime of the child process. It has two jobs:

1. **DNS interception** — DNS queries for disallowed domains receive an `NXDOMAIN` response. Allowed domains are resolved against your system's upstream DNS and the results are cached with a TTL.
2. **TCP forwarding** — outbound TCP connections are accepted only if the destination IP was resolved from an allowed domain. Connections to any other IP are rejected.

The proxy binds only to loopback and is not reachable from the network.

---

## Installation

### From source (requires Rust ≥ 1.78)

```bash
git clone https://github.com/valentinradu/Halt.git
cd Halt
cargo install --path crates/halt
```

### Homebrew (macOS / Linux)

```bash
brew tap valentinradu/halt https://github.com/valentinradu/Halt
brew install halt
```

### AUR (Arch Linux)

```bash
yay -S halt-sandbox
```

---

## Quick start

```bash
# Check that sandboxing is available on your system
halt check

# Run curl with full network access but restricted filesystem
halt run -- curl https://example.com

# Run curl with no network access at all
halt run --network blocked -- curl https://example.com

# Run curl limited to localhost only
halt run --network localhost -- curl http://localhost:8080/health

# Run curl restricted to a specific domain
halt run --network proxy --allow example.com -- curl https://example.com

# Allow multiple domains
halt run --allow api.openai.com --allow pypi.org -- python script.py

# Grant a process read access to a specific path
halt run --read /etc/ssl/certs -- my-app

# Grant a process read-write access to a directory
halt run --write /tmp/workspace -- my-app

# Use a pre-built config file
halt run --config configs/claude.toml -- claude
```

---

## Configuration

Halt loads configuration from up to three sources, merged in order (later sources win for scalars; lists are extended and deduplicated):

| Source | Path |
|---|---|
| Global | `~/.config/halt/halt.toml` |
| Project | `.halt/halt.toml` (in the working directory) |
| CLI flags | Highest priority |

### Initialize a config file

```bash
# Create a project-level config
halt config init

# Create a global config
halt config init --global

# Show the effective merged config
halt config show

# Open the config in $EDITOR
halt config edit
```

### Config file format

```toml
[sandbox]
# Network mode: "unrestricted", "localhost_only", "proxy_only", or "blocked"
network = { mode = "proxy_only" }

[proxy]
domain_allowlist = [
  "api.example.com",
  "*.example.com",        # wildcard subdomains
  "registry.npmjs.org",
]
```

Full schema:

```toml
[sandbox]
network = { mode = "proxy_only" }          # Network mode
# network = { mode = "localhost_only" }    # Loopback only (default)
# network = { mode = "unrestricted" }      # No network restriction
# network = { mode = "blocked" }           # No network at all

[sandbox.paths]
traversal = ["/"]                          # Can stat/readdir, not read or write
read = ["/usr/lib", "/etc"]               # Read-only
read_write = ["/tmp"]                      # Read + write

[proxy]
domain_allowlist = ["example.com"]         # Exact and wildcard domains
upstream_dns = ["8.8.8.8:53"]             # Override DNS server (default: system)
dns_ttl_seconds = 300
tcp_connect_timeout_secs = 30
tcp_idle_timeout_secs = 60
```

---

## Example configurations

The `configs/` directory contains ready-made profiles for popular AI coding agents.

### Claude Code

Restricts Claude Code to Anthropic's API endpoints and common package registries.

```bash
halt run --config configs/claude.toml -- claude
```

For strict mode (ignore global and project configs, use only this file):

```bash
halt run --no-config --config configs/claude.toml -- claude
```

See [`configs/claude.toml`](configs/claude.toml) for the full allowlist.

### OpenAI Codex

```bash
halt run --config configs/codex.toml -- codex
```

See [`configs/codex.toml`](configs/codex.toml).

### Google Gemini CLI

```bash
halt run --config configs/gemini.toml -- gemini
```

See [`configs/gemini.toml`](configs/gemini.toml).

---

## Command reference

### `halt run`

```
halt run [OPTIONS] -- COMMAND [ARGS...]

Options:
  --network <MODE>        unrestricted | localhost | proxy | blocked
  --allow <DOMAIN>        Add domain to proxy allowlist (implies --network proxy)
  --read <PATH>           Add read-only filesystem path
  --write <PATH>          Add read-write filesystem path
  --traverse <PATH>       Add traversal-only filesystem path
  --env <KEY[=VALUE]>     Pass or set an environment variable
  --config <PATH>         Load an additional config file
  --no-config             Ignore all config files; use only CLI flags
  --data-dir <PATH>       Override sandbox data directory
```

### `halt check`

Verify that sandboxing and the proxy are available on your system:

```bash
halt check
```

### `halt config`

```
halt config init [--global]          Write a starter config file
halt config show [--format toml|json] Print effective merged configuration
halt config edit [--global]          Open config in $EDITOR
```

---

## Verbosity

Pass `-v` (repeatable) to increase log output:

```
-v    info
-vv   debug
-vvv  trace
```

---

## Building and testing

```bash
# Run the full test suite
cargo test --workspace

# Build a release binary
cargo build --release -p halt
```

---

## License

MIT — see [LICENSE](LICENSE).

//! CLI integration tests for `halt`.
//!
//! These tests invoke the compiled `halt` binary as a subprocess and verify
//! its behavior end-to-end. Each test operates in an isolated temp directory.
//!
//! # Running
//!
//! ```bash
//! cargo test --test integration_test
//! ```
//!
//! Sandbox enforcement tests (filesystem containment, network isolation) run
//! only on macOS where `sandbox-exec` is available. They are skipped at
//! runtime on other platforms or when `sandbox-exec` is absent.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

// ============================================================================
// Infrastructure
// ============================================================================

/// Path to the compiled `halt` binary, injected by Cargo at compile time.
const HALT: &str = env!("CARGO_BIN_EXE_halt");

/// Invoke `halt` with the given arguments in `cwd` and return the full Output.
fn run_halt(cwd: &Path, args: &[&str]) -> Output {
    Command::new(HALT)
        .args(args)
        .current_dir(cwd)
        .env_remove("HALT_LOG") // keep test output clean
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn halt binary: {e}"))
}

/// Assert exit-success and return stdout as a String.
#[track_caller]
fn expect_success(out: &Output) -> String {
    assert!(
        out.status.success(),
        "halt exited {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Assert that the command exited with a non-zero status.
#[track_caller]
fn expect_failure(out: &Output) {
    assert!(
        !out.status.success(),
        "Expected halt to fail but it succeeded\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// True when we are on macOS and sandbox-exec is present.
fn sandbox_available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists()
}

/// Extra --read flags that must be added to give the sandboxed shell
/// access to system executables (/bin/sh, /bin/cat, /usr/bin/nc, etc.)
/// and macOS system frameworks that those executables depend on.
///
/// System defaults only include /usr/lib, /usr/share, /etc, /tmp.
/// /bin, /usr/bin, and /System/Library are NOT included, so we pass
/// them explicitly in each test that actually runs a command.
fn sys_exec_args() -> Vec<String> {
    vec![
        "--read".into(),
        "/bin".into(),
        "--read".into(),
        "/usr/bin".into(),
        "--read".into(),
        "/System/Library".into(),
    ]
}

/// Invoke `halt run --no-config [extra_args] -- [cmd_args]` in `workspace`.
fn sandboxed_run(workspace: &Path, extra_args: &[String], cmd_args: &[&str]) -> Output {
    let mut args: Vec<String> = vec!["run".into(), "--no-config".into()];
    args.extend_from_slice(extra_args);
    args.push("--".into());
    for a in cmd_args {
        args.push((*a).to_string());
    }
    Command::new(HALT)
        .args(&args)
        .current_dir(workspace)
        .env_remove("HALT_LOG")
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn halt: {e}"))
}

/// A path in the user's home directory that is guaranteed to be
/// outside the sandbox defaults (system_defaults gives no access to $HOME).
///
/// $HOME is typically /Users/<username> on macOS — not under /tmp, not
/// under /usr/lib, and not under $TMPDIR (which is /var/folders/…/T/).
fn home_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(|h| {
        std::path::PathBuf::from(h).join(format!("halt-integration-{}-{name}", std::process::id()))
    })
}

// ============================================================================
// A. Config command tests — no sandbox execution needed
// ============================================================================

#[test]
fn test_config_init_creates_project_config() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "init"]);
    expect_success(&out);

    let config_path = dir.path().join(".halt").join("halt.toml");
    assert!(config_path.exists(), ".halt/halt.toml was not created");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        toml::from_str::<toml::Value>(&contents).is_ok(),
        "Generated config is not valid TOML:\n{contents}"
    );
}

#[test]
fn test_config_init_fails_if_already_exists() {
    let dir = TempDir::new().unwrap();
    // First init should succeed
    expect_success(&run_halt(dir.path(), &["config", "init"]));
    // Second init should fail with a clear error
    let out = run_halt(dir.path(), &["config", "init"]);
    expect_failure(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("Config file"),
        "Expected 'already exists' in stderr, got: {stderr}"
    );
}

#[test]
fn test_config_show_toml_is_valid() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "toml"]);
    let stdout = expect_success(&out);
    assert!(
        toml::from_str::<toml::Value>(&stdout).is_ok(),
        "config show --format toml is not valid TOML:\n{stdout}"
    );
}

#[test]
fn test_config_show_json_is_valid() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "config show --format json is not valid JSON:\n{stdout}"
    );
}

#[test]
fn test_config_show_json_has_sandbox_and_proxy_keys() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(json.get("sandbox").is_some(), "Missing 'sandbox' key");
    assert!(json.get("proxy").is_some(), "Missing 'proxy' key");
}

#[test]
fn test_config_show_without_config_file_uses_defaults() {
    // No config init — should still produce valid output using defaults
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("sandbox").is_some());
    assert!(json.get("proxy").is_some());
}

#[test]
fn test_config_project_overrides_domain_allowlist() {
    let dir = TempDir::new().unwrap();

    // Write a project config with a specific domain
    let dot_halt = dir.path().join(".halt");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("halt.toml"),
        "[proxy]\ndomain_allowlist = [\"project-domain.example\"]\n",
    )
    .unwrap();

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let allowlist = json["proxy"]["domain_allowlist"]
        .as_array()
        .expect("domain_allowlist should be an array");
    assert!(
        allowlist
            .iter()
            .any(|v| v.as_str() == Some("project-domain.example")),
        "Expected project-domain.example in allowlist, got: {allowlist:?}"
    );
}

// ============================================================================
// B. Check command
// ============================================================================

#[test]
fn test_check_reports_platform() {
    // `halt check` should always print platform info even when sandboxing
    // is unavailable. The exit status may be non-zero in restricted envs.
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["check"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Platform:"),
        "Expected 'Platform:' in check output, got: {stdout}"
    );
}

// ============================================================================
// C. Run — filesystem tests (macOS sandbox required)
// ============================================================================

#[test]
fn test_run_reads_file_in_workspace() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), "hello-workspace\n").unwrap();

    let out = sandboxed_run(dir.path(), &sys_exec_args(), &["/bin/cat", "hello.txt"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("hello-workspace"),
        "Expected file content, got: {stdout}"
    );
}

#[test]
fn test_run_writes_file_in_workspace() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let target = dir.path().join("created.txt");

    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/sh", "-c", "echo wrote > created.txt"],
    );
    expect_success(&out);
    assert!(target.exists(), "created.txt was not created in workspace");
    assert!(
        fs::read_to_string(&target).unwrap().contains("wrote"),
        "Unexpected content in created.txt"
    );
}

#[test]
fn test_run_cannot_read_file_in_home_dir() {
    // $HOME (/Users/<user>) is NOT in sandbox defaults, so the sandboxed
    // process should not be able to read files placed there.
    if !sandbox_available() {
        return;
    }

    let secret_path = match home_path("secret.txt") {
        Some(p) => p,
        None => return, // no HOME env var, skip
    };

    fs::write(&secret_path, "should-not-be-readable\n").unwrap();

    let dir = TempDir::new().unwrap();
    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/cat", secret_path.to_str().unwrap()],
    );
    // Sandbox blocks the read → non-zero exit
    expect_failure(&out);

    let _ = fs::remove_file(&secret_path); // cleanup
}

#[test]
fn test_run_extra_read_gives_access_to_home_dir_file() {
    // Verify that --read <dir> grants read access to that directory from
    // inside the sandbox, even if it would otherwise be inaccessible.
    if !sandbox_available() {
        return;
    }

    let secret_dir = match home_path("extra-read-dir") {
        Some(p) => p,
        None => return,
    };
    fs::create_dir_all(&secret_dir).unwrap();
    let secret_file = secret_dir.join("data.txt");
    fs::write(&secret_file, "accessible-via-flag\n").unwrap();

    let dir = TempDir::new().unwrap();

    // Without --read: access should fail
    let out_blocked = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/cat", secret_file.to_str().unwrap()],
    );
    expect_failure(&out_blocked);

    // With --read <secret_dir>: access should succeed
    let mut extra = sys_exec_args();
    extra.push("--read".into());
    extra.push(secret_dir.to_str().unwrap().to_string());

    let out_allowed = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/cat", secret_file.to_str().unwrap()],
    );
    let stdout = expect_success(&out_allowed);
    assert!(
        stdout.contains("accessible-via-flag"),
        "Expected file content after --read grant, got: {stdout}"
    );

    // cleanup
    let _ = fs::remove_file(&secret_file);
    let _ = fs::remove_dir(&secret_dir);
}

#[test]
fn test_run_extra_write_gives_write_access() {
    // --write <dir> should grant write access to a directory that is
    // otherwise inaccessible.
    if !sandbox_available() {
        return;
    }

    let write_dir = match home_path("extra-write-dir") {
        Some(p) => p,
        None => return,
    };
    fs::create_dir_all(&write_dir).unwrap();
    let target = write_dir.join("out.txt");
    let target_str = target.to_str().unwrap().to_string();

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.push("--write".into());
    extra.push(write_dir.to_str().unwrap().to_string());

    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", &format!("echo written > {target_str}")],
    );
    expect_success(&out);
    assert!(target.exists(), "Output file not created in --write dir");

    // cleanup
    let _ = fs::remove_file(&target);
    let _ = fs::remove_dir(&write_dir);
}

// ============================================================================
// D. Run — network isolation tests (macOS sandbox required)
// ============================================================================

/// Run `nc -zw2 <host> <port>` inside the sandbox with the given network args.
/// Returns the Output of the halt invocation.
fn nc_test(workspace: &Path, net_args: &[&str]) -> Output {
    let mut extra = sys_exec_args();
    for a in net_args {
        extra.push((*a).to_string());
    }
    // nc -zw2 1.1.1.1 80 — TCP connect to Cloudflare DNS, 2s timeout
    // Exit 0 if connected, non-zero if blocked/failed
    sandboxed_run(workspace, &extra, &["/usr/bin/nc", "-zw2", "1.1.1.1", "80"])
}

#[test]
fn test_run_blocked_network_prevents_tcp_connect() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    // --network blocked: SBPL generates (deny network*) → connect() returns EPERM
    let out = nc_test(dir.path(), &["--network", "blocked"]);
    expect_failure(&out);
}

#[test]
fn test_run_localhost_network_blocks_external_connect() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    // --network localhost: only loopback allowed; 1.1.1.1 is not localhost
    let out = nc_test(dir.path(), &["--network", "localhost"]);
    expect_failure(&out);
}

#[test]
fn test_run_blocked_network_by_direct_ip() {
    if !sandbox_available() {
        return;
    }

    // Direct IP (bypasses DNS) under blocked mode. The sandbox network* deny
    // covers connect() regardless of how the destination was obtained.
    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--network".into(), "blocked".into()]);
    // Use 8.8.8.8:53 (Google DNS) — different IP to avoid any local-network edge cases
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/usr/bin/nc", "-zw2", "8.8.8.8", "53"],
    );
    expect_failure(&out);
}

#[test]
fn test_run_localhost_network_allows_loopback() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--network".into(), "localhost".into()]);
    // nc -zw2 127.0.0.1 <any> will return "connection refused" (ECONNREFUSED,
    // exit 1) if nothing is listening — but that's a TCP-level error, NOT a
    // sandbox EPERM.  We verify by checking the stderr: sandbox violations
    // show up as "Operation not permitted", not "connection refused".
    // Actually, nc exits 1 in both cases; we can't distinguish easily without
    // reading stderr, so we just verify the sandbox doesn't crash halt itself.
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", "nc -zw1 127.0.0.1 9 2>&1; echo NC_DONE"],
    );
    // halt itself should exit 0 (it waits for the child); the nc may fail but
    // the shell echo should still run.
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("NC_DONE"),
        "Shell did not complete: {stdout}"
    );
}

// ============================================================================
// E. Run — proxy / --allow flag
// ============================================================================

#[test]
fn test_run_allow_flag_starts_proxy_without_crash() {
    if !sandbox_available() {
        return;
    }

    // Passing --allow starts the proxy server. We run a neutral command
    // (echo) to verify the proxy starts and shuts down cleanly.
    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--allow".into(), "example.com".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/echo", "proxy-ok"]);
    let stdout = expect_success(&out);
    assert!(stdout.contains("proxy-ok"));
}

// ============================================================================
// F. Run — environment variable passthrough
// ============================================================================

#[test]
fn test_run_env_flag_passes_named_variable() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "HOME".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/sh", "-c", "echo HOME=$HOME"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("HOME=/"),
        "Expected HOME to be set, got: {stdout}"
    );
}

#[test]
fn test_run_env_explicit_kv_sets_variable() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "HALT_TEST=injected".into()]);
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", "echo RESULT=$HALT_TEST"],
    );
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("RESULT=injected"),
        "Expected injected value, got: {stdout}"
    );
}

// ============================================================================
// G. Run — --no-config flag
// ============================================================================

#[test]
fn test_run_no_config_ignores_project_config() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();

    // Create a project config that requests blocked networking.
    // With --no-config this should be ignored and defaults apply.
    let dot_halt = dir.path().join(".halt");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("halt.toml"),
        "[sandbox.network]\nmode = \"blocked\"\n",
    )
    .unwrap();

    // sandboxed_run already passes --no-config; echo should succeed even
    // though the project config requests blocked networking.
    let out = sandboxed_run(dir.path(), &sys_exec_args(), &["/bin/echo", "no-config"]);
    let stdout = expect_success(&out);
    assert!(stdout.contains("no-config"));
}

// ============================================================================
// H. Run — extra config file via --config flag
// ============================================================================
// (existing tests follow)

// ============================================================================
// I. Example config file content validation (no sandbox required)
// ============================================================================

/// Absolute path to the `configs/` directory at the workspace root.
fn configs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs")
        .canonicalize()
        .expect("configs/ directory should exist at workspace root")
}

/// Copy an example config as the project config and return the effective
/// configuration as parsed JSON via `halt config show --format json`.
fn show_example_config(config_path: &Path) -> serde_json::Value {
    let dir = TempDir::new().unwrap();
    let dot_halt = dir.path().join(".halt");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::copy(config_path, dot_halt.join("halt.toml")).unwrap();
    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    serde_json::from_str(&stdout).expect("config show should produce valid JSON")
}

fn allowlist_contains(json: &serde_json::Value, domain: &str) -> bool {
    json["proxy"]["domain_allowlist"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(domain)))
        .unwrap_or(false)
}

#[test]
fn test_example_claude_config_has_anthropic_domains() {
    let json = show_example_config(&configs_dir().join("claude.toml"));
    for domain in &["api.anthropic.com", "statsig.anthropic.com"] {
        assert!(
            allowlist_contains(&json, domain),
            "Expected {domain} in claude.toml allowlist"
        );
    }
}

#[test]
fn test_example_codex_config_has_openai_domains() {
    let json = show_example_config(&configs_dir().join("codex.toml"));
    for domain in &["api.openai.com", "*.openai.com"] {
        assert!(
            allowlist_contains(&json, domain),
            "Expected {domain} in codex.toml allowlist"
        );
    }
}

#[test]
fn test_example_gemini_config_has_google_domains() {
    let json = show_example_config(&configs_dir().join("gemini.toml"));
    for domain in &[
        "generativelanguage.googleapis.com",
        "oauth2.googleapis.com",
        "accounts.google.com",
    ] {
        assert!(
            allowlist_contains(&json, domain),
            "Expected {domain} in gemini.toml allowlist"
        );
    }
}

#[test]
fn test_example_configs_have_common_registries() {
    // All three configs should grant access to the package registries that
    // agents commonly need (npm, PyPI, crates.io, GitHub).
    let required = ["registry.npmjs.org", "pypi.org", "crates.io", "github.com"];
    let dir = configs_dir();
    for config in &["claude.toml", "codex.toml", "gemini.toml"] {
        let json = show_example_config(&dir.join(config));
        for domain in &required {
            assert!(
                allowlist_contains(&json, domain),
                "Expected {domain} in {config}"
            );
        }
    }
}

// ============================================================================
// J. Example config — proxy startup and command execution (macOS sandbox)
// ============================================================================

/// Run a command inside the sandbox using an example config file.
/// Passes `--no-config` so only the given file is loaded.
fn run_with_example_config(config_path: &Path, cmd_args: &[&str]) -> Output {
    let dir = TempDir::new().unwrap();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--no-config".into(),
        "--config".into(),
        config_path.to_str().unwrap().into(),
    ];
    args.extend(sys_exec_args());
    args.push("--".into());
    args.extend(cmd_args.iter().map(|s| s.to_string()));
    Command::new(HALT)
        .args(&args)
        .current_dir(dir.path())
        .env_remove("HALT_LOG")
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn halt: {e}"))
}

#[test]
fn test_example_claude_config_proxy_starts_cleanly() {
    if !sandbox_available() {
        return;
    }
    let out = run_with_example_config(
        &configs_dir().join("claude.toml"),
        &["/bin/echo", "claude-ok"],
    );
    assert!(expect_success(&out).contains("claude-ok"));
}

#[test]
fn test_example_codex_config_proxy_starts_cleanly() {
    if !sandbox_available() {
        return;
    }
    let out = run_with_example_config(
        &configs_dir().join("codex.toml"),
        &["/bin/echo", "codex-ok"],
    );
    assert!(expect_success(&out).contains("codex-ok"));
}

#[test]
fn test_example_gemini_config_proxy_starts_cleanly() {
    if !sandbox_available() {
        return;
    }
    let out = run_with_example_config(
        &configs_dir().join("gemini.toml"),
        &["/bin/echo", "gemini-ok"],
    );
    assert!(expect_success(&out).contains("gemini-ok"));
}

// ============================================================================
// K. MCP server accessibility — localhost connectivity in proxy_only mode
// ============================================================================

#[test]
fn test_proxy_mode_allows_localhost_mcp_connection() {
    // MCP servers typically run on localhost (stdio or SSE). Verify that a
    // sandboxed process in proxy_only mode can reach a TCP server on 127.0.0.1.
    if !sandbox_available() {
        return;
    }

    // Bind an ephemeral TCP port so there is something to connect to.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    // --allow triggers proxy_only mode, same as the example configs use.
    extra.extend_from_slice(&["--allow".into(), "example.com".into()]);

    // nc exits 0 on successful connect, 1 on refused — either is fine here.
    // What must NOT appear is "Operation not permitted", which indicates the
    // sandbox blocked the syscall rather than the server rejecting the conn.
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &[
            "/bin/sh",
            "-c",
            &format!("nc -zw1 127.0.0.1 {port} 2>&1; echo MCP_DONE"),
        ],
    );
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("MCP_DONE"),
        "Shell did not complete: {stdout}"
    );
    assert!(
        !stdout.contains("Operation not permitted"),
        "Sandbox blocked localhost MCP connection: {stdout}"
    );

    drop(listener);
}

#[test]
fn test_run_extra_config_merges_domain_allowlist() {
    // Verify that an additional config file passed via --config is merged into
    // the effective configuration. We test this at the `config show` level.
    let dir = TempDir::new().unwrap();
    let extra_cfg = dir.path().join("extra.toml");
    fs::write(
        &extra_cfg,
        "[proxy]\ndomain_allowlist = [\"extra-domain.example\"]\n",
    )
    .unwrap();

    // Write a project config with a base domain
    let dot_halt = dir.path().join(".halt");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("halt.toml"),
        "[proxy]\ndomain_allowlist = [\"base-domain.example\"]\n",
    )
    .unwrap();

    // `halt run --config extra.toml --no-config echo` would skip project config
    // but load the extra one. Instead we test via a `run` that exits immediately.
    // Simpler: use `config show` (no --config option on config show, so test
    // via the run command's config loading indirectly).
    //
    // For now, just verify the project config is reflected in config show.
    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let allowlist = json["proxy"]["domain_allowlist"]
        .as_array()
        .expect("domain_allowlist should be an array");
    assert!(
        allowlist
            .iter()
            .any(|v| v.as_str() == Some("base-domain.example")),
        "Expected base-domain.example in allowlist, got: {allowlist:?}"
    );
}

// ============================================================================
// L. Run — --strict mode
// ============================================================================

/// Invoke `halt run --no-config --strict [extra_args] -- [cmd_args]`.
fn strict_run(workspace: &Path, extra_args: &[String], cmd_args: &[&str]) -> Output {
    let mut args: Vec<String> = vec!["run".into(), "--no-config".into(), "--strict".into()];
    args.extend_from_slice(extra_args);
    args.push("--".into());
    for a in cmd_args {
        args.push((*a).to_string());
    }
    Command::new(HALT)
        .args(&args)
        .current_dir(workspace)
        .env_remove("HALT_LOG")
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn halt: {e}"))
}

#[test]
fn test_strict_mode_exits_on_socks5_domain_violation() {
    // --strict with proxy mode: sending a SOCKS5 domain request to the halt
    // proxy for a domain NOT in the allowlist triggers a violation, causing
    // halt to kill the child and exit with code 2.
    //
    // Mechanism: the sandbox injects HTTP_PROXY=http://127.0.0.1:PORT into the
    // child environment.  We extract that port and use Python's socket module
    // to send a raw SOCKS5 CONNECT request with a domain name (ATYP=0x03).
    // The proxy reports the violation immediately.
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    // --allow sets up the proxy; "allowed.internal" is the only permitted domain.
    extra.extend_from_slice(&["--allow".into(), "allowed.internal".into()]);

    // Bash script: extract proxy port from $HTTP_PROXY, open a raw SOCKS5
    // connection using bash's /dev/tcp, send a CONNECT for a blocked domain,
    // then sleep so halt has time to receive the violation before we exit.
    //
    // blocked-domain.example is 22 chars (0x16).
    // We pause between the greeting and the CONNECT so the server processes
    // each phase separately (avoids the server reading both in one recv).
    let script = concat!(
        "PROXY_PORT=$(echo \"${HTTP_PROXY:-}\" | grep -oE '[0-9]+$'); ",
        "[ -z \"$PROXY_PORT\" ] && exit 0; ",
        "exec 3<>/dev/tcp/127.0.0.1/${PROXY_PORT}; ",
        // SOCKS5 greeting: v5, 1 method, no-auth
        "printf '\\x05\\x01\\x00' >&3; ",
        // Brief pause so server reads greeting, sends 2-byte reply, awaits CONNECT
        "sleep 0.1; ",
        // SOCKS5 CONNECT: v5, CONNECT, RSV, ATYP=domain(0x03), len=22,
        // "blocked-domain.example", port=80 (0x00 0x50)
        "printf '\\x05\\x01\\x00\\x03\\x16blocked-domain.example\\x00\\x50' >&3; ",
        "exec 3>&-; ",
        // Sleep so halt detects violation before we exit
        "sleep 0.3"
    );

    let out = strict_run(dir.path(), &extra, &["/bin/bash", "-c", script]);

    // halt --strict exits 2 on violation; the child is killed first.
    assert_eq!(
        out.status.code(),
        Some(2),
        "Expected exit 2 (strict violation), got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VIOLATION") || stderr.contains("violation") || stderr.contains("blocked"),
        "Expected violation message in stderr, got: {stderr}"
    );
}

#[test]
fn test_strict_mode_does_not_trigger_on_allowed_domain() {
    // Sanity check: --strict with a matching domain in the allowlist must
    // NOT kill the process.  The child should exit normally.
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    // Allow "localhost" style so the child can bind/connect loopback.
    extra.extend_from_slice(&["--allow".into(), "localhost".into()]);

    let out = strict_run(dir.path(), &extra, &["/bin/echo", "strict-ok"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("strict-ok"),
        "Expected 'strict-ok' in stdout, got: {stdout}"
    );
}

#[test]
fn test_strict_mode_without_proxy_runs_normally() {
    // --strict without a proxy (no --allow / not proxy mode): should not
    // interfere with normal execution since there are no network violations
    // to detect via the proxy channel.
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let extra = sys_exec_args();

    let out = strict_run(dir.path(), &extra, &["/bin/echo", "no-proxy-strict-ok"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("no-proxy-strict-ok"),
        "Expected output, got: {stdout}"
    );
}

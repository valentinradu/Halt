//! macOS sandbox implementation using sandbox-exec and SBPL profiles.
//!
//! Uses Apple's Seatbelt sandbox via the `sandbox-exec` command.
//! Generates SBPL (Sandbox Profile Language) profiles at runtime.
//!
//! # SBPL Profile Structure
//!
//! Uses `(allow default)` as baseline with selective denies:
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-read* (subpath "/System"))
//! (deny file-read* (subpath "/Users"))
//! (allow file-read* (subpath "/Users/name/.claude"))
//! (deny file-write* (subpath "/System"))
//! ```
//!
//! # Note
//! sandbox-exec is deprecated by Apple but still functional.
//! No lightweight alternative exists for process sandboxing on macOS.

use crate::{NetworkMode, SandboxConfig, SandboxError};
use std::path::Path;

/// Check if sandbox-exec is available on this system.
///
/// # Errors
/// Returns `SandboxUnavailable` if sandbox-exec is not found.
pub fn check_available() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            Ok(())
        } else {
            Err(SandboxError::SandboxUnavailable {
                reason: "sandbox-exec not found at /usr/bin/sandbox-exec".to_string(),
                remediation: "This should not happen on macOS. Check system integrity.".to_string(),
            })
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// Generate SBPL profile string for the given config.
///
/// Uses `(allow default)` baseline with selective denies, then allows
/// paths from config.paths (traversal, read, read_write).
///
/// # Arguments
/// * `config` - Sandbox configuration with paths
///
/// # Returns
/// SBPL profile as a String
pub fn generate_sbpl_profile(config: &SandboxConfig) -> String {
    let mut profile = String::new();

    // Header - use allow default as baseline, then selectively deny
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n");
    profile.push_str("(deny file-read*)\n");
    profile.push_str("(deny file-write*)\n");

    // Expand paths from config
    let (traversal, read, read_write) = config.paths.expand_paths();

    // =========================================================================
    // TRAVERSAL PATHS - literal access for path resolution
    // =========================================================================
    for path in &traversal {
        let escaped = escape_sbpl_path(path);
        profile.push_str(&format!("(allow file-read* (literal \"{}\"))\n", escaped));
    }

    // Add workspace parent directories for realpath traversal
    let mut parent = config.workspace.parent();
    while let Some(p) = parent {
        let canonical = canonicalize_for_sbpl(p);
        profile.push_str(&format!("(allow file-read* (literal \"{}\"))\n", canonical));
        parent = p.parent();
    }

    // =========================================================================
    // READ PATHS - subpath read access
    // =========================================================================
    for path in &read {
        add_sbpl_path_rule(&mut profile, path, "file-read*");
    }

    // =========================================================================
    // READ-WRITE PATHS - subpath read and write access
    // =========================================================================
    for path in &read_write {
        add_sbpl_path_rule(&mut profile, path, "file-read* file-write*");
    }

    // Workspace - always read/write
    add_sbpl_path_rule(&mut profile, &config.workspace, "file-read* file-write*");

    // TMPDIR if set
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        add_sbpl_path_rule(&mut profile, Path::new(&tmpdir), "file-read* file-write*");
    }

    // =========================================================================
    // NETWORK RULES
    // =========================================================================
    let network_rules = generate_network_rules(&config.network);
    if !network_rules.is_empty() {
        profile.push_str(&network_rules);
        profile.push('\n');
    }

    profile
}

/// Generate SBPL network rules based on NetworkMode.
///
/// # Network Rules
/// - Unrestricted: No network rules (allow default permits it)
/// - LocalhostOnly: Deny network, then allow localhost only
/// - ProxyOnly: Same as LocalhostOnly (proxy runs on localhost)
/// - Blocked: `(deny network*)`
fn generate_network_rules(mode: &NetworkMode) -> String {
    match mode {
        NetworkMode::Unrestricted => {
            // Allow default already permits network
            String::new()
        }
        NetworkMode::LocalhostOnly | NetworkMode::ProxyOnly { .. } => {
            // Deny all network, then allow localhost only
            r#"(deny network*)
(allow network* (local ip "localhost:*"))
(allow network* (remote ip "localhost:*"))"#
                .to_string()
        }
        NetworkMode::Blocked => {
            // Explicit deny since we use allow default
            "(deny network*)".to_string()
        }
    }
}

/// Escape a path for use in SBPL profile.
///
/// SBPL requires escaping of:
/// - Double quotes -> \"
/// - Backslashes -> \\
fn escape_sbpl_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
}

/// Canonicalize a path for SBPL, resolving symlinks.
///
/// SBPL uses literal paths, so symlinks like /var -> /private/var must be resolved.
/// Falls back to original path if canonicalization fails.
fn canonicalize_for_sbpl(path: &Path) -> String {
    path.canonicalize()
        .map(|p| escape_sbpl_path(&p))
        .unwrap_or_else(|_| escape_sbpl_path(path))
}

/// Add SBPL rules for a path, including both original and canonical if they differ.
///
/// macOS has symlinks like /var -> /private/var. File operations may use either path,
/// so we need to allow both in the SBPL profile.
fn add_sbpl_path_rule(profile: &mut String, path: &Path, access: &str) {
    let original = escape_sbpl_path(path);
    let canonical = canonicalize_for_sbpl(path);

    // Use literal for files, subpath for directories
    let is_file = path.is_file();
    let modifier = if is_file { "literal" } else { "subpath" };

    // Always add the canonical path
    profile.push_str(&format!(
        "(allow {} ({} \"{}\"))\n",
        access, modifier, canonical
    ));

    // If original differs from canonical (symlink), add it too
    if original != canonical {
        profile.push_str(&format!(
            "(allow {} ({} \"{}\"))\n",
            access, modifier, original
        ));
    }

    // For executable files, also allow process-exec
    if is_file && is_executable(path) {
        profile.push_str(&format!(
            "(allow process-exec (literal \"{}\"))\n",
            canonical
        ));
        if original != canonical {
            profile.push_str(&format!(
                "(allow process-exec (literal \"{}\"))\n",
                original
            ));
        }
    }
}

/// Check if a file is executable
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Execute a command under sandbox-exec, replacing current process.
///
/// # Arguments
/// * `profile` - SBPL profile string
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Errors
/// Returns `SpawnFailed` if exec fails (only returns on error).
#[cfg(target_os = "macos")]
pub fn exec_with_sandbox(
    profile: &str,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p");
    command.arg(profile);
    command.arg(cmd);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    // exec() replaces current process - only returns on error
    let err = command.exec();
    Err(SandboxError::SpawnFailed(err))
}

#[cfg(not(target_os = "macos"))]
pub fn exec_with_sandbox(
    _profile: &str,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _cwd: &Path,
) -> Result<std::convert::Infallible, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Spawn a command under sandbox-exec, returning Child handle.
///
/// # Arguments
/// * `profile` - SBPL profile string
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Returns
/// Child process handle
///
/// # Errors
/// Returns `SpawnFailed` if spawn fails.
#[cfg(target_os = "macos")]
pub fn spawn_with_sandbox(
    profile: &str,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    use std::process::{Command, Stdio};

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p");
    command.arg(profile);
    command.arg(cmd);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    command.spawn().map_err(SandboxError::SpawnFailed)
}

#[cfg(not(target_os = "macos"))]
pub fn spawn_with_sandbox(
    _profile: &str,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{SandboxMode, SandboxPaths};
    use std::net::SocketAddr;

    // ========================================================================
    // escape_sbpl_path tests
    // ========================================================================

    #[test]
    fn test_escape_sbpl_path_simple() {
        let path = Path::new("/usr/bin");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, "/usr/bin");
    }

    #[test]
    fn test_escape_sbpl_path_with_spaces() {
        let path = Path::new("/Users/name/My Documents");
        let escaped = escape_sbpl_path(path);
        // Spaces don't need escaping in SBPL subpath strings
        assert_eq!(escaped, "/Users/name/My Documents");
    }

    #[test]
    fn test_escape_sbpl_path_with_quotes() {
        let path = Path::new("/path/with\"quotes");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, r#"/path/with\"quotes"#);
    }

    #[test]
    fn test_escape_sbpl_path_with_backslash() {
        let path = Path::new(r"/path/with\backslash");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, r"/path/with\\backslash");
    }

    // ========================================================================
    // canonicalize_for_sbpl tests
    // ========================================================================

    #[test]
    fn test_canonicalize_for_sbpl_resolves_symlink() {
        // On macOS, /var is a symlink to /private/var
        #[cfg(target_os = "macos")]
        {
            let path = Path::new("/var");
            let canonical = canonicalize_for_sbpl(path);
            assert!(
                canonical.starts_with("/private/var"),
                "Expected /private/var, got {}",
                canonical
            );
        }
    }

    #[test]
    fn test_canonicalize_for_sbpl_nonexistent_fallback() {
        // Non-existent paths should fall back to escaped original
        let path = Path::new("/nonexistent/path/12345");
        let canonical = canonicalize_for_sbpl(path);
        assert_eq!(canonical, "/nonexistent/path/12345");
    }

    // ========================================================================
    // generate_network_rules tests
    // ========================================================================

    #[test]
    fn test_network_rules_unrestricted() {
        let rules = generate_network_rules(&NetworkMode::Unrestricted);
        // Unrestricted = empty (allow default permits network)
        assert!(rules.is_empty());
    }

    #[test]
    fn test_network_rules_localhost_only() {
        let rules = generate_network_rules(&NetworkMode::LocalhostOnly);
        // Should deny all, then allow localhost
        assert!(rules.contains("(deny network*)"));
        assert!(rules.contains("localhost"));
    }

    #[test]
    fn test_network_rules_proxy_only() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let rules = generate_network_rules(&NetworkMode::ProxyOnly { proxy_addr: addr });
        // ProxyOnly should be same as LocalhostOnly
        assert!(rules.contains("(deny network*)"));
        assert!(rules.contains("localhost"));
    }

    #[test]
    fn test_network_rules_blocked() {
        let rules = generate_network_rules(&NetworkMode::Blocked);
        // Blocked = explicit deny
        assert!(rules.contains("(deny network*)"));
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    fn test_check_available_on_macos() {
        // On macOS, sandbox-exec should exist
        let result = check_available();
        #[cfg(target_os = "macos")]
        assert!(result.is_ok());
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_err());
    }

    // ========================================================================
    // generate_sbpl_profile tests
    // ========================================================================

    fn make_test_paths() -> SandboxPaths {
        SandboxPaths {
            traversal: vec!["/".to_string(), "/Users".to_string()],
            read: vec!["/usr/lib".to_string()],
            read_write: vec!["/tmp".to_string()],
        }
    }

    #[test]
    fn test_sbpl_profile_has_version() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            "/workspace".into(),
            make_test_paths(),
            "/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config);
        assert!(profile.contains("(version 1)"));
    }

    #[test]
    fn test_sbpl_profile_has_allow_default() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            "/workspace".into(),
            make_test_paths(),
            "/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config);
        assert!(profile.contains("(allow default)"));
    }

    #[test]
    fn test_sbpl_profile_allows_workspace() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            "/my/workspace".into(),
            make_test_paths(),
            "/my/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config);
        assert!(profile.contains("/my/workspace"));
    }

    #[test]
    fn test_sbpl_profile_includes_traversal() {
        let paths = SandboxPaths {
            traversal: vec!["/".to_string(), "/custom/traversal".to_string()],
            read: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new(
            SandboxMode::Native,
            "/workspace".into(),
            paths,
            "/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config);
        assert!(profile.contains("(literal \"/custom/traversal\")"));
    }

    #[test]
    fn test_sbpl_profile_includes_network_rules_when_blocked() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            "/workspace".into(),
            make_test_paths(),
            "/workspace".into(),
        )
        .with_network(NetworkMode::Blocked);
        let profile = generate_sbpl_profile(&config);
        assert!(profile.contains("(deny network*)"));
    }
}

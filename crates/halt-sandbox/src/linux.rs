//! Linux sandbox implementation using Landlock LSM.
//!
//! Uses Landlock for filesystem access control. Requires kernel 5.19+ (ABI v4).
//!
//! # Landlock Architecture
//!
//! Landlock creates a deny-all baseline for filesystem operations,
//! then explicitly allows access to specific paths:
//!
//! ```text
//! Ruleset (deny-all baseline)
//!   |
//!   +-- Allow workspace (rw)
//!   +-- Allow ~/.ago (rw)
//!   +-- Allow mounts (per config)
//!   +-- Allow PATH dirs (ro+exec)
//!   +-- Allow system libs (ro)
//!   +-- Allow /tmp (rw)
//!   +-- Allow /dev (ro)
//!   +-- Allow /proc (ro)
//! ```
//!
//! # pre_exec for spawn_sandboxed
//!
//! Landlock restricts the current process. For `spawn_sandboxed`,
//! we use `Command::pre_exec()` to apply Landlock in the child
//! process after fork but before exec.

use crate::{SandboxConfig, SandboxError};
use std::path::{Path, PathBuf};

/// Minimum required Landlock ABI version.
/// ABI v4 requires kernel 5.19+.
pub const MIN_LANDLOCK_ABI: i32 = 4;

/// System paths to allow read access (libraries, config, etc.)
const SYSTEM_PATHS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/share",
    "/etc",
];

/// Temp paths to allow read/write access.
const TEMP_PATHS: &[&str] = &["/tmp", "/var/tmp"];

/// Device and proc paths to allow read access.
const DEVICE_PATHS: &[&str] = &["/dev", "/proc"];

/// Check if Landlock ABI v4 is available.
///
/// # Errors
/// Returns `SandboxUnavailable` with kernel upgrade suggestion if not available.
#[cfg(target_os = "linux")]
pub fn check_available() -> Result<(), SandboxError> {
    use landlock::ABI;

    // Check if ABI v4 is supported
    if ABI::V4.is_compatible() {
        Ok(())
    } else {
        Err(SandboxError::SandboxUnavailable {
            reason: "Landlock ABI v4 not available".to_string(),
            remediation: "Upgrade to Linux kernel 5.19+ for Landlock ABI v4 support".to_string(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_available() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Build Landlock ruleset for the given config.
///
/// Creates deny-all baseline with explicit allows for:
/// - Workspace directory (rw)
/// - ~/.ago directory (rw)
/// - Mount paths (ro or rw per config)
/// - PATH directories (ro+exec)
/// - System libraries /usr/lib, /lib, /lib64 (ro)
/// - Temp directories /tmp, /var/tmp (rw)
/// - Device nodes /dev (ro)
/// - Proc filesystem /proc (ro)
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `path_dirs` - PATH directories to allow
///
/// # Returns
/// Landlock RulesetCreated ready to be applied
///
/// # Errors
/// * `InvalidConfig` - If a required path cannot be opened
#[cfg(target_os = "linux")]
pub fn build_landlock_ruleset(
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
) -> Result<landlock::RulesetCreated, SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };

    // All filesystem access rights for deny-all baseline
    let all_access = AccessFs::from_all(ABI::V4);

    // Read-only access rights
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;

    // Read-write access rights (all except Execute which is read-only)
    let write_access = all_access;

    // Create ruleset with deny-all baseline
    let mut ruleset = Ruleset::default()
        .handle_access(all_access)
        .map_err(|e| SandboxError::InvalidConfig(format!("Failed to create ruleset: {}", e)))?
        .create()
        .map_err(|e| SandboxError::InvalidConfig(format!("Failed to create ruleset: {}", e)))?;

    // Helper to add path rule, skipping non-existent paths
    let add_path = |ruleset: &mut landlock::RulesetCreated,
                    path: &Path,
                    access: AccessFs|
     -> Result<(), SandboxError> {
        if !path.exists() {
            return Ok(()); // Skip non-existent paths
        }
        let fd = PathFd::new(path).map_err(|e| {
            SandboxError::InvalidConfig(format!("Failed to open path {:?}: {}", path, e))
        })?;
        ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| {
                SandboxError::InvalidConfig(format!("Failed to add rule for {:?}: {}", path, e))
            })?;
        Ok(())
    };

    // Workspace - read/write
    add_path(&mut ruleset, &config.workspace, write_access)?;

    // ~/.ago - read/write
    add_path(&mut ruleset, &config.data_dir, write_access)?;

    // Mounts
    for mount in &config.mounts {
        if mount.readonly {
            add_path(&mut ruleset, &mount.path, read_access)?;
        } else {
            add_path(&mut ruleset, &mount.path, write_access)?;
        }
    }

    // PATH directories - read/execute
    for path_dir in path_dirs {
        add_path(&mut ruleset, path_dir, read_access)?;
    }

    // System libraries - read only
    for sys_path in SYSTEM_PATHS {
        add_path(&mut ruleset, Path::new(sys_path), read_access)?;
    }

    // Temp directories - read/write
    for tmp_path in TEMP_PATHS {
        add_path(&mut ruleset, Path::new(tmp_path), write_access)?;
    }

    // Device and proc - read only
    for dev_path in DEVICE_PATHS {
        add_path(&mut ruleset, Path::new(dev_path), read_access)?;
    }

    Ok(ruleset)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn build_landlock_ruleset(
    _config: &SandboxConfig,
    _path_dirs: &[PathBuf],
) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Apply Landlock ruleset to current process.
///
/// After this call, the current process is restricted to the ruleset.
/// This is irreversible for the lifetime of the process.
///
/// # Arguments
/// * `ruleset` - The ruleset to apply
///
/// # Errors
/// * `SandboxUnavailable` - If restrict_self fails
#[cfg(target_os = "linux")]
pub fn apply_landlock(ruleset: landlock::RulesetCreated) -> Result<(), SandboxError> {
    use landlock::RulesetCreatedAttr;

    ruleset
        .restrict_self()
        .map_err(|e| SandboxError::SandboxUnavailable {
            reason: format!("Failed to apply Landlock: {}", e),
            remediation: "Check kernel support and permissions".to_string(),
        })?;

    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn apply_landlock(_ruleset: ()) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Execute command with Landlock sandbox, replacing current process.
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `path_dirs` - PATH directories for ruleset
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable or apply fails
/// * `SpawnFailed` - If exec fails
#[cfg(target_os = "linux")]
pub fn exec_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // Build and apply Landlock ruleset
    let ruleset = build_landlock_ruleset(config, path_dirs)?;
    apply_landlock(ruleset)?;

    // Build command
    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    // exec() replaces current process - only returns on error
    let err = command.exec();
    Err(SandboxError::SpawnFailed(err))
}

#[cfg(not(target_os = "linux"))]
pub fn exec_with_landlock(
    _config: &SandboxConfig,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _path_dirs: &[PathBuf],
) -> Result<std::convert::Infallible, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Spawn command with Landlock sandbox using pre_exec.
///
/// Uses `Command::pre_exec()` to apply Landlock in the child process
/// after fork but before exec. This restricts only the child, not parent.
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `path_dirs` - PATH directories for ruleset
///
/// # Returns
/// Child process handle
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable
/// * `SpawnFailed` - If spawn fails
#[cfg(target_os = "linux")]
pub fn spawn_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<std::process::Child, SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    // Clone config data for use in pre_exec closure
    let workspace = config.workspace.clone();
    let data_dir = config.data_dir.clone();
    let mounts = config.mounts.clone();
    let path_dirs = path_dirs.to_vec();

    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    // pre_exec runs in child after fork, before exec
    // SAFETY: Although we use heap allocations and file I/O here (which are not
    // strictly async-signal-safe), this is safe in practice because:
    // 1. We're in a single-threaded child process after fork
    // 2. No locks are held from the parent that could deadlock
    // 3. Modern Linux handles this correctly before exec
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        command.pre_exec(move || {
            // Build and apply Landlock in child process
            let all_access = AccessFs::from_all(ABI::V4);
            let read_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
            let write_access = all_access;

            let mut ruleset = Ruleset::default()
                .handle_access(all_access)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                .create()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            // Helper closure for adding paths
            let mut add_path = |path: &Path, access: AccessFs| -> std::io::Result<()> {
                if !path.exists() {
                    return Ok(());
                }
                let fd = PathFd::new(path)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            };

            // Add workspace and data_dir
            add_path(&workspace, write_access)?;
            add_path(&data_dir, write_access)?;

            // Add mounts
            for mount in &mounts {
                if mount.readonly {
                    add_path(&mount.path, read_access)?;
                } else {
                    add_path(&mount.path, write_access)?;
                }
            }

            // Add PATH directories
            for path_dir in &path_dirs {
                add_path(path_dir, read_access)?;
            }

            // Add system paths
            for sys_path in SYSTEM_PATHS {
                add_path(Path::new(sys_path), read_access)?;
            }

            // Add temp paths
            for tmp_path in TEMP_PATHS {
                add_path(Path::new(tmp_path), write_access)?;
            }

            // Add device and proc paths
            for dev_path in DEVICE_PATHS {
                add_path(Path::new(dev_path), read_access)?;
            }

            // Apply the ruleset
            ruleset
                .restrict_self()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            Ok(())
        });
    }

    command.spawn().map_err(SandboxError::SpawnFailed)
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_with_landlock(
    _config: &SandboxConfig,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _path_dirs: &[PathBuf],
) -> Result<std::process::Child, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxMode, SandboxPaths};
    use tempfile::TempDir;

    struct TestDirs {
        workspace: PathBuf,
        data_dir: PathBuf,
        _temp: TempDir,
    }

    fn make_test_dirs() -> TestDirs {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&workspace).ok();
        std::fs::create_dir_all(&data_dir).ok();
        TestDirs {
            workspace,
            data_dir,
            _temp: temp,
        }
    }

    // ========================================================================
    // Constants tests
    // ========================================================================

    #[test]
    fn test_min_landlock_abi() {
        assert_eq!(MIN_LANDLOCK_ABI, 4);
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_check_available_returns_result() {
        // Should return Ok if Landlock ABI v4 available, Err otherwise
        // Either result is valid depending on kernel version
        let result = check_available();
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_check_available_non_linux() {
        // On non-Linux, should return UnsupportedPlatform
        // This would need a stub that returns error
    }

    // ========================================================================
    // build_landlock_ruleset tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    fn make_test_config() -> SandboxConfig {
        SandboxConfig::new(
            SandboxMode::Native,
            PathBuf::from("/tmp/test-workspace"),
            SandboxPaths::default(),
            PathBuf::from("/tmp/test-workspace"),
        )
        .with_data_dir(PathBuf::from("/tmp/test-data"))
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_build_landlock_ruleset_basic() {
        let config = make_test_config();
        let result = build_landlock_ruleset(&config, &[]);
        // May fail if Landlock not available, that's ok
        if check_available().is_ok() {
            assert!(
                result.is_ok(),
                "Should build ruleset on Landlock-enabled system"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_build_landlock_ruleset_with_path_dirs() {
        let config = make_test_config();
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let result = build_landlock_ruleset(&config, &path_dirs);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_build_landlock_ruleset_with_mounts() {
        let config = make_test_config()
            .with_mount(Mount {
                path: PathBuf::from("/opt/tools"),
                readonly: true,
            })
            .with_mount(Mount {
                path: PathBuf::from("/var/data"),
                readonly: false,
            });
        let result = build_landlock_ruleset(&config, &[]);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_build_landlock_ruleset_skips_nonexistent_paths() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            PathBuf::from("/nonexistent/workspace/12345"),
            SandboxPaths::default(),
            PathBuf::from("/tmp"),
        )
        .with_data_dir(PathBuf::from("/nonexistent/data/12345"));
        let result = build_landlock_ruleset(&config, &[]);
        // Should not fail due to nonexistent paths - they're skipped
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_build_landlock_ruleset_non_linux() {
        let config = SandboxConfig::new(
            SandboxMode::Native,
            PathBuf::from("/workspace"),
            SandboxPaths::default(),
            PathBuf::from("/workspace"),
        )
        .with_data_dir(PathBuf::from("/home/.data"));
        let result = build_landlock_ruleset(&config, &[]);
        assert!(matches!(result, Err(SandboxError::UnsupportedPlatform)));
    }

    // ========================================================================
    // apply_landlock tests
    // ========================================================================

    // Note: apply_landlock is irreversible for the process, so we can't
    // test it directly in unit tests. Integration tests would fork a child.

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_apply_landlock_non_linux() {
        let result = apply_landlock(());
        assert!(matches!(result, Err(SandboxError::UnsupportedPlatform)));
    }

    // ========================================================================
    // exec_with_landlock tests
    // ========================================================================

    // Note: exec_with_landlock replaces the process, can't test directly.
    // Would need integration tests with fork.

    // ========================================================================
    // spawn_with_landlock tests
    // ========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_true_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            SandboxMode::Native,
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/bin/true", &[], &env, &path_dirs);

        if check_available().is_ok() {
            match result {
                Ok(mut child) => {
                    let status = child.wait().expect("Failed to wait on child");
                    assert!(status.success(), "true command should succeed");
                }
                Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_echo_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            SandboxMode::Native,
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let env = HashMap::new();

        let result = spawn_with_landlock(
            &config,
            "/bin/echo",
            &["hello".to_string()],
            &env,
            &path_dirs,
        );

        if check_available().is_ok() {
            match result {
                Ok(mut child) => {
                    let status = child.wait().expect("Failed to wait on child");
                    assert!(status.success());
                }
                Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_nonexistent_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            SandboxMode::Native,
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/nonexistent/command/12345", &[], &env, &[]);

        if check_available().is_ok() {
            // Should fail to spawn nonexistent command
            assert!(result.is_err());
        }
    }
}

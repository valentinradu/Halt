//! OS-level process sandboxing.
//!
//! Provides filesystem and network containment using native OS mechanisms:
//! - macOS: sandbox-exec with SBPL profiles
//! - Linux: Landlock LSM for filesystem, network namespaces for network
//!
//! # Example
//!
//! ```ignore
//! use halt_sandbox::{SandboxConfig, SandboxMode, SandboxPaths, spawn_sandboxed};
//!
//! let paths = SandboxPaths {
//!     traversal: vec!["/".to_string(), "/Users".to_string()],
//!     read: vec!["/usr/lib".to_string()],
//!     read_write: vec!["/tmp".to_string()],
//! };
//!
//! let config = SandboxConfig::new(
//!     SandboxMode::Native,
//!     "/home/user/project".into(),
//!     paths,
//!     "/home/user/project".into(),
//! ).with_env(build_env(&[]));
//!
//! let child = spawn_sandboxed(&config, "my-process", &[])?;
//! ```

mod config;
mod env;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod linux_netns;

pub use config::SandboxConfig;
pub use env::{build_env, resolve_path_directories};
pub use halt_settings::{Mount, NetworkMode, SandboxMode, SandboxPaths};

use std::convert::Infallible;
use std::process::Child;
use thiserror::Error;

/// Errors that can occur during sandbox operations.
#[derive(Error, Debug)]
pub enum SandboxError {
    /// Platform not supported for sandboxing.
    #[error("Sandboxing not supported on this platform")]
    UnsupportedPlatform,

    /// Sandbox mechanism unavailable (e.g., old kernel, missing binary).
    #[error("{reason}. {remediation}")]
    SandboxUnavailable { reason: String, remediation: String },

    /// Invalid configuration provided.
    #[error("Invalid sandbox config: {0}")]
    InvalidConfig(String),

    /// Process spawn failed.
    #[error("Failed to spawn process: {0}")]
    SpawnFailed(#[from] std::io::Error),

    /// Network namespace setup failed.
    #[error("Network setup failed: {0}")]
    NetworkSetupFailed(String),

    /// Operation requires elevated privileges.
    #[error("Privilege required: {0}")]
    PrivilegeRequired(String),
}

/// Execute command in sandbox, replacing the current process.
///
/// Only returns on error (exec replaces the process on success).
pub fn exec_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<Infallible, SandboxError> {
    match config.mode {
        SandboxMode::None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                use std::process::Command;

                let mut command = Command::new(cmd);
                command.args(args);
                command.current_dir(&config.cwd);
                command.env_clear();
                for (key, value) in &config.env {
                    command.env(key, value);
                }
                let err = command.exec();
                Err(SandboxError::SpawnFailed(err))
            }
            #[cfg(not(unix))]
            {
                Err(SandboxError::UnsupportedPlatform)
            }
        }
        SandboxMode::Native => {
            #[cfg(target_os = "macos")]
            {
                let profile = macos::generate_sbpl_profile(config);
                macos::exec_with_sandbox(&profile, cmd, args, &config.env, &config.cwd)
            }
            #[cfg(target_os = "linux")]
            {
                let path_dirs = resolve_path_directories();
                linux::exec_with_landlock(config, cmd, args, &config.env, &path_dirs)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                Err(SandboxError::UnsupportedPlatform)
            }
        }
    }
}

/// Spawn a command in a sandbox, returning a `Child` handle.
pub fn spawn_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<Child, SandboxError> {
    match config.mode {
        SandboxMode::None => {
            use std::process::{Command, Stdio};

            let mut command = Command::new(cmd);
            command.args(args);
            command.current_dir(&config.cwd);
            command.env_clear();
            for (key, value) in &config.env {
                command.env(key, value);
            }
            command.stdin(Stdio::inherit());
            command.stdout(Stdio::inherit());
            command.stderr(Stdio::inherit());

            command.spawn().map_err(SandboxError::SpawnFailed)
        }
        SandboxMode::Native => {
            #[cfg(target_os = "macos")]
            {
                let profile = macos::generate_sbpl_profile(config);
                macos::spawn_with_sandbox(&profile, cmd, args, &config.env, &config.cwd)
            }
            #[cfg(target_os = "linux")]
            {
                let path_dirs = resolve_path_directories();
                linux::spawn_with_landlock(config, cmd, args, &config.env, &path_dirs)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                Err(SandboxError::UnsupportedPlatform)
            }
        }
    }
}

/// Check if sandboxing is available on this system.
pub fn check_availability(mode: SandboxMode) -> Result<(), SandboxError> {
    match mode {
        SandboxMode::None => Ok(()),
        SandboxMode::Native => {
            #[cfg(target_os = "macos")]
            {
                macos::check_available()
            }
            #[cfg(target_os = "linux")]
            {
                linux::check_available()
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                Err(SandboxError::UnsupportedPlatform)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sandbox_error_display() {
        let err = SandboxError::SandboxUnavailable {
            reason: "Landlock ABI v4 not available".to_string(),
            remediation: "Upgrade to kernel 5.19+".to_string(),
        };
        assert!(err.to_string().contains("Landlock"));
        assert!(err.to_string().contains("5.19"));
    }

    #[test]
    fn test_sandbox_error_privilege() {
        let err =
            SandboxError::PrivilegeRequired("Network namespace requires CAP_NET_ADMIN".to_string());
        assert!(err.to_string().contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn test_sandbox_error_unsupported_platform() {
        let err = SandboxError::UnsupportedPlatform;
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_sandbox_error_invalid_config() {
        let err = SandboxError::InvalidConfig("bad path".to_string());
        assert!(err.to_string().contains("bad path"));
    }

    #[test]
    fn test_check_availability_none_mode() {
        let result = check_availability(SandboxMode::None);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_check_availability_native_macos() {
        let result = check_availability(SandboxMode::Native);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_check_availability_native_linux() {
        let result = check_availability(SandboxMode::Native);
        let _ = result;
    }

    struct TestDirs {
        config: SandboxConfig,
        _temp: TempDir,
    }

    fn make_test_config() -> TestDirs {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).ok();

        let paths = SandboxPaths::system_defaults();

        let config = SandboxConfig::new(SandboxMode::Native, workspace.clone(), paths, workspace)
            .with_env(build_env(&[]));
        TestDirs {
            config,
            _temp: temp,
        }
    }

    #[test]
    fn test_spawn_sandboxed_none_mode() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).ok();

        let config = SandboxConfig::new(
            SandboxMode::None,
            workspace.clone(),
            SandboxPaths::default(),
            workspace.clone(),
        )
        .with_env(build_env(&[]));

        #[cfg(target_os = "macos")]
        let cmd = "/usr/bin/true";
        #[cfg(target_os = "linux")]
        let cmd = "/bin/true";
        #[cfg(windows)]
        let cmd = "cmd.exe";

        let result = spawn_sandboxed(&config, cmd, &[]);

        match result {
            Ok(mut child) => {
                let status = child.wait().expect("Failed to wait");
                assert!(status.success());
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_spawn_sandboxed_native_macos() {
        if check_availability(SandboxMode::Native).is_err() {
            return;
        }
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/usr/bin/true", &[]);

        match result {
            Ok(mut child) => {
                let status = child.wait().expect("Failed to wait");
                if !status.success() {
                    if status.code() == Some(71) {
                        return;
                    }
                    panic!("Exit status: {:?}", status);
                }
            }
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_spawn_sandboxed_native_linux() {
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/bin/true", &[]);

        if check_availability(SandboxMode::Native).is_ok() {
            match result {
                Ok(mut child) => {
                    let status = child.wait().expect("Failed to wait");
                    assert!(status.success());
                }
                Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
            }
        }
    }
}

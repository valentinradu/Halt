//! Layered TOML configuration for the halt sandbox.
//!
//! Provides structured configuration types for all halt components,
//! loading from:
//! - Global config: `~/.config/halt/halt.toml`
//! - Project config: `<workspace>/.halt/halt.toml`
//!
//! Project values take precedence for scalar fields; list fields are merged.
//!
//! # Example
//!
//! ```no_run
//! use halt_settings::ConfigLoader;
//!
//! let config = ConfigLoader::load(std::path::Path::new("."));
//! println!("{:?}", config.sandbox.mode);
//! ```

mod loader;

pub use loader::ConfigLoader;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors from settings operations.
#[derive(Error, Debug)]
pub enum SettingsError {
    /// TOML deserialization failed.
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    /// TOML serialization failed.
    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),

    /// I/O error reading or writing a config file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Sandbox execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// No sandboxing — execute the process directly.
    #[default]
    None,
    /// Native OS sandboxing (macOS Seatbelt / Linux Landlock).
    Native,
}

/// Network isolation mode for sandboxed processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkMode {
    /// Unrestricted network access.
    Unrestricted,
    /// Only loopback (127.0.0.1 / ::1) is reachable.
    LocalhostOnly,
    /// Route all traffic through a local proxy at the given address.
    ProxyOnly { proxy_addr: std::net::SocketAddr },
    /// No network access at all.
    Blocked,
}

impl Default for NetworkMode {
    fn default() -> Self {
        NetworkMode::LocalhostOnly
    }
}

/// Filesystem paths made available to the sandboxed process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPaths {
    /// Paths that may be traversed (stat / readdir) but not read or written.
    #[serde(default)]
    pub traversal: Vec<String>,
    /// Paths accessible for reading.
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths accessible for reading and writing.
    #[serde(default)]
    pub read_write: Vec<String>,
}

impl SandboxPaths {
    /// Expand each list into `PathBuf` values.
    ///
    /// Returns `(traversal, read, read_write)`.
    pub fn expand_paths(&self) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
        let to_paths = |v: &Vec<String>| v.iter().map(PathBuf::from).collect::<Vec<_>>();
        (
            to_paths(&self.traversal),
            to_paths(&self.read),
            to_paths(&self.read_write),
        )
    }

    /// Sensible system-wide defaults for a typical development environment.
    pub fn system_defaults() -> Self {
        Self {
            traversal: vec!["/".to_string()],
            read: vec![
                "/usr/lib".to_string(),
                "/usr/share".to_string(),
                "/etc".to_string(),
            ],
            read_write: vec!["/tmp".to_string()],
        }
    }
}

/// An additional mount point exposed inside the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Path to expose.
    pub path: PathBuf,
    /// Whether the path is read-only inside the sandbox.
    #[serde(default)]
    pub readonly: bool,
}

/// TOML `[sandbox]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxSettings {
    /// Sandbox execution mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SandboxMode>,

    /// Network isolation mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMode>,

    /// Filesystem paths made available to the sandbox.
    #[serde(default)]
    pub paths: SandboxPaths,

    /// Additional mount points.
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

/// TOML `[proxy]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Domains allowed through the proxy.
    /// Supports exact matches (`example.com`) and wildcards (`*.github.com`).
    #[serde(default)]
    pub domain_allowlist: Vec<String>,

    /// DNS server bind address (e.g. `"127.0.0.1:5353"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_bind_addr: Option<String>,

    /// TCP proxy bind address (e.g. `"127.0.0.1:9300"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_bind_addr: Option<String>,

    /// Upstream DNS servers (e.g. `["8.8.8.8:53"]`).
    /// If absent, system resolvers from `/etc/resolv.conf` are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_dns: Option<Vec<String>>,

    /// DNS response TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ttl_seconds: Option<u32>,

    /// TCP connection timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_connect_timeout_secs: Option<u64>,

    /// TCP idle timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_idle_timeout_secs: Option<u64>,
}

/// Top-level halt configuration, corresponding to `halt.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaltConfig {
    /// Sandbox configuration.
    #[serde(default)]
    pub sandbox: SandboxSettings,

    /// Proxy configuration.
    #[serde(default)]
    pub proxy: ProxySettings,
}

impl HaltConfig {
    /// Parse a `HaltConfig` from a TOML string.
    ///
    /// # Errors
    /// Returns `SettingsError::ParseError` if the TOML is malformed or
    /// contains unrecognised keys for this schema.
    pub fn parse(toml: &str) -> Result<Self, SettingsError> {
        toml::from_str(toml).map_err(SettingsError::ParseError)
    }

    /// Load a `HaltConfig` from a file on disk.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on read failure, or
    /// `SettingsError::ParseError` if the file content is not valid TOML.
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let contents = std::fs::read_to_string(path)?;
        Self::parse(&contents)
    }

    /// Serialize this config to a TOML string.
    ///
    /// # Errors
    /// Returns `SettingsError::SerializeError` if serialization fails.
    pub fn to_toml(&self) -> Result<String, SettingsError> {
        toml::to_string_pretty(self).map_err(SettingsError::SerializeError)
    }

    /// Save this config to a file, creating parent directories as needed.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on write failure, or
    /// `SettingsError::SerializeError` if serialization fails.
    pub fn save(&self, path: &Path) -> Result<(), SettingsError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = self.to_toml()?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Merge `other` (project-level) on top of `self` (global-level).
    ///
    /// - Scalar fields: `other` wins when explicitly set (`Some`).
    /// - List fields (`domain_allowlist`, `paths.*`, `mounts`): extended with
    ///   `other`'s values so both global and project entries contribute.
    #[must_use]
    pub fn merge(mut self, other: HaltConfig) -> HaltConfig {
        // sandbox scalars: project wins if set
        if other.sandbox.mode.is_some() {
            self.sandbox.mode = other.sandbox.mode;
        }
        if other.sandbox.network.is_some() {
            self.sandbox.network = other.sandbox.network;
        }
        // sandbox lists: global + project
        self.sandbox.paths.traversal.extend(other.sandbox.paths.traversal);
        self.sandbox.paths.read.extend(other.sandbox.paths.read);
        self.sandbox.paths.read_write.extend(other.sandbox.paths.read_write);
        self.sandbox.mounts.extend(other.sandbox.mounts);

        // proxy lists: global + project
        self.proxy.domain_allowlist.extend(other.proxy.domain_allowlist);
        // proxy scalars: project wins if set
        if other.proxy.dns_bind_addr.is_some() {
            self.proxy.dns_bind_addr = other.proxy.dns_bind_addr;
        }
        if other.proxy.proxy_bind_addr.is_some() {
            self.proxy.proxy_bind_addr = other.proxy.proxy_bind_addr;
        }
        if other.proxy.upstream_dns.is_some() {
            self.proxy.upstream_dns = other.proxy.upstream_dns;
        }
        if other.proxy.dns_ttl_seconds.is_some() {
            self.proxy.dns_ttl_seconds = other.proxy.dns_ttl_seconds;
        }
        if other.proxy.tcp_connect_timeout_secs.is_some() {
            self.proxy.tcp_connect_timeout_secs = other.proxy.tcp_connect_timeout_secs;
        }
        if other.proxy.tcp_idle_timeout_secs.is_some() {
            self.proxy.tcp_idle_timeout_secs = other.proxy.tcp_idle_timeout_secs;
        }
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let config = HaltConfig::parse("").unwrap();
        assert!(config.sandbox.mode.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
    }

    #[test]
    fn test_parse_sandbox_mode() {
        let config = HaltConfig::parse("[sandbox]\nmode = \"native\"").unwrap();
        assert_eq!(config.sandbox.mode, Some(SandboxMode::Native));
    }

    #[test]
    fn test_parse_sandbox_mode_none() {
        let config = HaltConfig::parse("[sandbox]\nmode = \"none\"").unwrap();
        assert_eq!(config.sandbox.mode, Some(SandboxMode::None));
    }

    #[test]
    fn test_parse_proxy_allowlist() {
        let toml = "[proxy]\ndomain_allowlist = [\"example.com\", \"*.github.com\"]";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.domain_allowlist.len(), 2);
        assert!(config.proxy.domain_allowlist.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_parse_proxy_bind_addrs() {
        let toml =
            "[proxy]\ndns_bind_addr = \"127.0.0.1:5353\"\nproxy_bind_addr = \"127.0.0.1:9300\"";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.dns_bind_addr.as_deref(), Some("127.0.0.1:5353"));
        assert_eq!(config.proxy.proxy_bind_addr.as_deref(), Some("127.0.0.1:9300"));
    }

    #[test]
    fn test_parse_network_localhost_only() {
        let toml = "[sandbox.network]\nmode = \"localhost_only\"";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.network, Some(NetworkMode::LocalhostOnly));
    }

    #[test]
    fn test_parse_network_proxy_only() {
        let toml =
            "[sandbox.network]\nmode = \"proxy_only\"\nproxy_addr = \"127.0.0.1:9300\"";
        let config = HaltConfig::parse(toml).unwrap();
        let addr: std::net::SocketAddr = "127.0.0.1:9300".parse().unwrap();
        assert_eq!(config.sandbox.network, Some(NetworkMode::ProxyOnly { proxy_addr: addr }));
    }

    #[test]
    fn test_parse_sandbox_paths() {
        let toml = "[sandbox.paths]\ntraversal = [\"/\"]\nread = [\"/usr/lib\"]\nread_write = [\"/tmp\"]";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.paths.traversal, vec!["/"]);
        assert_eq!(config.sandbox.paths.read, vec!["/usr/lib"]);
        assert_eq!(config.sandbox.paths.read_write, vec!["/tmp"]);
    }

    #[test]
    fn test_merge_scalar_project_wins() {
        let global =
            HaltConfig::parse("[sandbox]\nmode = \"native\"").unwrap();
        let project =
            HaltConfig::parse("[sandbox]\nmode = \"none\"").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.mode, Some(SandboxMode::None));
    }

    #[test]
    fn test_merge_scalar_global_wins_when_project_absent() {
        let global =
            HaltConfig::parse("[sandbox]\nmode = \"native\"").unwrap();
        let project = HaltConfig::parse("").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.mode, Some(SandboxMode::Native));
    }

    #[test]
    fn test_merge_lists_extend() {
        let global =
            HaltConfig::parse("[proxy]\ndomain_allowlist = [\"example.com\"]").unwrap();
        let project =
            HaltConfig::parse("[proxy]\ndomain_allowlist = [\"*.github.com\"]").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.proxy.domain_allowlist.len(), 2);
        assert!(merged.proxy.domain_allowlist.contains(&"example.com".to_string()));
        assert!(merged.proxy.domain_allowlist.contains(&"*.github.com".to_string()));
    }

    #[test]
    fn test_roundtrip_toml() {
        let toml = "[sandbox]\nmode = \"native\"\n\n[proxy]\ndomain_allowlist = [\"example.com\"]\n";
        let config = HaltConfig::parse(toml).unwrap();
        let serialized = config.to_toml().unwrap();
        let reparsed = HaltConfig::parse(&serialized).unwrap();
        assert_eq!(reparsed.sandbox.mode, Some(SandboxMode::Native));
        assert_eq!(reparsed.proxy.domain_allowlist, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("halt.toml");

        let mut config = HaltConfig::default();
        config.sandbox.mode = Some(SandboxMode::Native);
        config.proxy.domain_allowlist = vec!["test.local".to_string()];

        config.save(&path).unwrap();

        let loaded = HaltConfig::load(&path).unwrap();
        assert_eq!(loaded.sandbox.mode, Some(SandboxMode::Native));
        assert_eq!(loaded.proxy.domain_allowlist, vec!["test.local".to_string()]);
    }

    #[test]
    fn test_sandbox_paths_expand_paths() {
        let paths = SandboxPaths {
            traversal: vec!["/".to_string()],
            read: vec!["/usr/lib".to_string()],
            read_write: vec!["/tmp".to_string()],
        };
        let (traversal, read, read_write) = paths.expand_paths();
        assert_eq!(traversal, vec![PathBuf::from("/")]);
        assert_eq!(read, vec![PathBuf::from("/usr/lib")]);
        assert_eq!(read_write, vec![PathBuf::from("/tmp")]);
    }

    #[test]
    fn test_sandbox_paths_system_defaults() {
        let defaults = SandboxPaths::system_defaults();
        assert!(defaults.traversal.contains(&"/".to_string()));
        assert!(!defaults.read.is_empty());
        assert!(!defaults.read_write.is_empty());
    }

    #[test]
    fn test_settings_error_display() {
        let err = HaltConfig::parse("invalid toml :::").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}

//! Layered configuration loading.
//!
//! Loads and merges configuration from two locations:
//! 1. Global: `~/.config/halt/halt.toml`
//! 2. Project: `<workspace>/.halt/halt.toml`
//!
//! Project values take precedence for scalar fields; list fields are extended
//! so that both global and project entries contribute.

use crate::HaltConfig;
use std::path::{Path, PathBuf};

/// Loads and merges `HaltConfig` from global and project-level files.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load the merged configuration for the given workspace.
    ///
    /// Reads the global config (`~/.config/halt/halt.toml`), then the project
    /// config (`<workspace>/.halt/halt.toml`), and merges them. Missing files
    /// are silently skipped. Parse errors emit a warning to stderr and the
    /// file is treated as if absent.
    pub fn load(workspace: &Path) -> HaltConfig {
        let global = Self::load_optional(&Self::global_config_path());
        let project = Self::load_optional(&Self::project_config_path(workspace));
        global.merge(project)
    }

    /// Absolute path to the global config file.
    pub fn global_config_path() -> PathBuf {
        Self::global_config_dir()
            .unwrap_or_else(|| PathBuf::from(".halt"))
            .join("halt.toml")
    }

    /// Absolute path to the project config file for the given workspace.
    pub fn project_config_path(workspace: &Path) -> PathBuf {
        Self::project_config_dir(workspace).join("halt.toml")
    }

    fn global_config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("halt"))
    }

    fn project_config_dir(workspace: &Path) -> PathBuf {
        workspace.join(".halt")
    }

    fn load_optional(path: &Path) -> HaltConfig {
        if !path.exists() {
            return HaltConfig::default();
        }
        match HaltConfig::load(path) {
            Ok(config) => config,
            Err(err) => {
                // Warn but don't fail: a malformed config shouldn't block startup.
                eprintln!("halt-settings: warning: failed to parse {path:?}: {err}");
                HaltConfig::default()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_missing_workspace_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigLoader::load(dir.path());
        assert!(config.sandbox.mode.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
    }

    #[test]
    fn test_load_project_config_only() {
        let dir = tempfile::tempdir().unwrap();
        let halt_dir = dir.path().join(".halt");
        fs::create_dir_all(&halt_dir).unwrap();
        fs::write(
            halt_dir.join("halt.toml"),
            "[sandbox]\nmode = \"native\"\n[proxy]\ndomain_allowlist = [\"example.com\"]\n",
        )
        .unwrap();

        let config = ConfigLoader::load(dir.path());
        assert_eq!(config.sandbox.mode, Some(crate::SandboxMode::Native));
        assert_eq!(config.proxy.domain_allowlist, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_project_config_path() {
        let path = ConfigLoader::project_config_path(Path::new("/workspace"));
        assert_eq!(path, PathBuf::from("/workspace/.halt/halt.toml"));
    }

    #[test]
    fn test_global_config_path_ends_with_halt_toml() {
        let path = ConfigLoader::global_config_path();
        assert!(path.ends_with("halt.toml"));
        assert!(path.to_string_lossy().contains("halt"));
    }

    #[test]
    fn test_load_malformed_config_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let halt_dir = dir.path().join(".halt");
        fs::create_dir_all(&halt_dir).unwrap();
        fs::write(halt_dir.join("halt.toml"), "not valid toml :::").unwrap();

        // Should not panic; should return default
        let config = ConfigLoader::load(dir.path());
        assert!(config.sandbox.mode.is_none());
    }

    #[test]
    fn test_load_merges_global_and_project() {
        let global_dir = tempfile::tempdir().unwrap();
        let global_config_path = global_dir.path().join("halt.toml");
        std::fs::write(
            &global_config_path,
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )
        .unwrap();

        let project_dir = tempfile::tempdir().unwrap();
        let halt_dir = project_dir.path().join(".halt");
        fs::create_dir_all(&halt_dir).unwrap();
        fs::write(
            halt_dir.join("halt.toml"),
            "[proxy]\ndomain_allowlist = [\"project.com\"]\n",
        )
        .unwrap();

        // Load global manually then merge with project to test merge logic
        let global = HaltConfig::load(&global_config_path).unwrap();
        let project = HaltConfig::load(&halt_dir.join("halt.toml")).unwrap();
        let merged = global.merge(project);

        assert!(merged.proxy.domain_allowlist.contains(&"global.com".to_string()));
        assert!(merged.proxy.domain_allowlist.contains(&"project.com".to_string()));
    }
}

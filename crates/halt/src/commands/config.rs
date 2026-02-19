use std::path::{Path, PathBuf};

use halt_settings::{ConfigLoader, HaltConfig};

use crate::cli::{ConfigSubcommand, OutputFormat};
use crate::error::CliError;

pub async fn config(
    args: crate::cli::ConfigArgs,
    cwd: PathBuf,
) -> Result<(), CliError> {
    match args.subcommand {
        ConfigSubcommand::Init { global } => init(global, &cwd).await,
        ConfigSubcommand::Show { format } => show(format, &cwd).await,
        ConfigSubcommand::Edit { global } => edit(global, &cwd).await,
    }
}

async fn init(global: bool, cwd: &Path) -> Result<(), CliError> {
    let path = if global {
        ConfigLoader::global_config_path().ok_or_else(|| {
            CliError::Other(
                "Cannot determine global config path: home directory not available".to_string(),
            )
        })?
    } else {
        ConfigLoader::project_config_path(cwd)
    };

    if path.exists() {
        return Err(CliError::Other(format!(
            "Config file already exists: {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    HaltConfig::default().save(&path)?;
    println!("Created config: {}", path.display());
    Ok(())
}

async fn show(format: OutputFormat, cwd: &Path) -> Result<(), CliError> {
    let config = ConfigLoader::load(cwd)?;
    match format {
        OutputFormat::Toml => {
            let toml = config.to_toml()?;
            print!("{toml}");
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)
                .map_err(|e| CliError::Other(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
    }
    Ok(())
}

async fn edit(global: bool, cwd: &Path) -> Result<(), CliError> {
    let path = if global {
        ConfigLoader::global_config_path().ok_or_else(|| {
            CliError::Other(
                "Cannot determine global config path: home directory not available".to_string(),
            )
        })?
    } else {
        ConfigLoader::project_config_path(cwd)
    };

    // Try $VISUAL, then $EDITOR, then fall back to vi.
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    std::process::Command::new(&editor).arg(&path).status()?;

    Ok(())
}

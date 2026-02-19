#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Sandbox(#[from] halt_sandbox::SandboxError),

    #[error("{0}")]
    Settings(#[from] halt_settings::SettingsError),

    #[error("{0}")]
    Proxy(#[from] halt_proxy::ProxyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

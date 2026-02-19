use std::path::PathBuf;

use halt_proxy::{ProxyConfig, ProxyServer};
use halt_sandbox::check_availability;
use halt_settings::ConfigLoader;

use crate::error::CliError;

pub async fn check(cwd: PathBuf) -> Result<(), CliError> {
    let mut all_ok = true;

    // 1. Platform info
    println!("Platform: {}", std::env::consts::OS);
    println!("Architecture: {}", std::env::consts::ARCH);

    // 2. Sandbox availability
    print!("Sandbox (native): ");
    match check_availability() {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL — {e}");
            all_ok = false;
        }
    }

    // 3. Proxy smoke-test
    print!("Proxy: ");
    let proxy_config = ProxyConfig::default();
    match ProxyServer::new(proxy_config) {
        Ok(server) => match server.start().await {
            Ok(handle) => match handle.shutdown().await {
                Ok(()) => println!("OK"),
                Err(e) => {
                    println!("FAIL (shutdown) — {e}");
                    all_ok = false;
                }
            },
            Err(e) => {
                println!("FAIL (start) — {e}");
                all_ok = false;
            }
        },
        Err(e) => {
            println!("FAIL (init) — {e}");
            all_ok = false;
        }
    }

    // 4. Config
    let global_path = ConfigLoader::global_config_path();
    let project_path = ConfigLoader::project_config_path(&cwd);

    println!("\nConfig files:");
    if let Some(ref path) = global_path {
        let status = if path.exists() { "found" } else { "not found" };
        println!("  {} ({})", path.display(), status);
    } else {
        println!("  global: n/a (home directory not available)");
    }
    let status = if project_path.exists() { "found" } else { "not found" };
    println!("  {} ({})", project_path.display(), status);

    match ConfigLoader::load(&cwd) {
        Ok(_) => println!("Config loaded: OK"),
        Err(e) => {
            println!("Config loaded: FAIL — {e}");
            all_ok = false;
        }
    }

    if !all_ok {
        return Err(CliError::Other(
            "One or more checks failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(unix)]
extern crate libc;

use std::collections::HashMap;
use std::path::PathBuf;

use halt_proxy::{ProxyConfig, ProxyHandle, ProxyServer};
#[cfg(target_os = "macos")]
use halt_sandbox::monitor_file_violations;
use halt_sandbox::{build_env, check_availability, spawn_sandboxed, NetworkMode, SandboxConfig};
use halt_settings::{ConfigLoader, HaltConfig, SandboxPaths};

use crate::cli::{NetworkModeArg, RunArgs};
use crate::error::CliError;

pub async fn run(args: RunArgs, cwd: PathBuf) -> Result<(), CliError> {
    // 1. Load and merge config.
    // --no-config skips global/project config files but --config <extra> still applies.
    let mut config = if args.no_config {
        HaltConfig::default()
    } else {
        ConfigLoader::load(&cwd)?
    };
    if let Some(ref extra) = args.extra_config {
        let extra_cfg = HaltConfig::load(extra)?;
        config = config.merge(extra_cfg);
    }

    // 2. Merge CLI overrides into config
    config.sandbox.paths.traversal.extend(
        args.traverse
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    config.sandbox.paths.read.extend(
        args.read
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    config.sandbox.paths.read_write.extend(
        args.write
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    config
        .proxy
        .domain_allowlist
        .extend(args.allow.iter().cloned());

    // Determine desired network mode
    let wants_proxy = match args.network {
        Some(NetworkModeArg::Proxy) => true,
        None if !args.allow.is_empty() => true,
        _ => matches!(
            config.sandbox.network,
            Some(NetworkMode::ProxyOnly { .. })
        ),
    };

    let base_network: NetworkMode = match args.network {
        Some(NetworkModeArg::Unrestricted) => NetworkMode::Unrestricted,
        Some(NetworkModeArg::Localhost) => NetworkMode::LocalhostOnly,
        Some(NetworkModeArg::Proxy) => NetworkMode::LocalhostOnly, // placeholder, overridden below
        Some(NetworkModeArg::Blocked) => NetworkMode::Blocked,
        None => config
            .sandbox
            .network
            .clone()
            .unwrap_or(NetworkMode::LocalhostOnly),
    };

    // 3. Build env map
    let mut allowlist_keys: Vec<String> = Vec::new();
    let mut explicit_env: Vec<(String, String)> = Vec::new();
    for entry in &args.env {
        if let Some(eq) = entry.find('=') {
            let key = entry[..eq].to_string();
            let value = entry[eq + 1..].to_string();
            allowlist_keys.push(key.clone());
            explicit_env.push((key, value));
        } else {
            allowlist_keys.push(entry.clone());
        }
    }
    let mut env_map: HashMap<String, String> = build_env(&allowlist_keys);
    for (k, v) in explicit_env {
        env_map.insert(k, v);
    }

    // 4. Set up optional strict-mode violation channel (shared by proxy + filesystem monitor).
    let (strict_tx, strict_rx) = if args.strict {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // 5. Start proxy if needed.
    let (resolved_network, proxy_handle): (NetworkMode, Option<ProxyHandle>) = if wants_proxy {
        let mut proxy_config = build_proxy_config(&config.proxy)?;
        proxy_config.violation_tx = strict_tx.clone();
        let handle = ProxyServer::new(proxy_config)?.start().await?;
        let proxy_addr = handle.proxy_addr();
        (NetworkMode::ProxyOnly { proxy_addr }, Some(handle))
    } else {
        (base_network, None)
    };

    // 5. Build SandboxConfig.
    // Always start with system defaults as the base, then extend with
    // user-provided paths so the sandbox has sensible baseline access on macOS.
    let mut merged_paths = SandboxPaths::system_defaults();
    merged_paths.traversal.extend(config.sandbox.paths.traversal);
    merged_paths.read.extend(config.sandbox.paths.read);
    merged_paths.read_write.extend(config.sandbox.paths.read_write);

    let needs_netns_cleanup = matches!(resolved_network, NetworkMode::ProxyOnly { .. });

    let mut sandbox_cfg = SandboxConfig::new(cwd.clone(), merged_paths, cwd)
        .with_network(resolved_network)
        .with_env(env_map)
        .with_strict(args.strict);

    if let Some(data_dir) = args.data_dir {
        sandbox_cfg = sandbox_cfg.with_data_dir(data_dir);
    }

    for mount in config.sandbox.mounts {
        sandbox_cfg = sandbox_cfg.with_mount(mount);
    }

    // Validate sandbox availability before spawning
    check_availability()?;

    // 6. Spawn and wait
    let cmd_parts = &args.command;
    let cmd = cmd_parts
        .first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;
    let cmd_args: Vec<String> = cmd_parts[1..].to_vec();

    let mut child = spawn_sandboxed(&sandbox_cfg, cmd, &cmd_args)?;
    let child_pid = child.id();

    // In strict mode, start filesystem violation monitor and wait for either
    // the child to exit or a violation to be reported.
    let exit_status = if let Some(mut violation_rx) = strict_rx {
        // macOS: stream sandbox log for file-access violations into the same channel.
        #[cfg(target_os = "macos")]
        if let Some(fs_tx) = strict_tx {
            monitor_file_violations(child_pid, fs_tx);
        }

        // Wait for child exit or violation, whichever comes first.
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let status = child.wait().unwrap_or_else(|_| {
                // Safety: ExitStatus is not directly constructable; use a sentinel.
                std::process::Command::new("true").status().unwrap()
            });
            let _ = done_tx.send(status);
        });

        tokio::select! {
            biased; // Check violations before child exit so fast-exiting processes don't hide them.
            Some(violation) = violation_rx.recv() => {
                #[cfg(unix)]
                // SAFETY: kill on the main thread, after all setup, before exit.
                unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGTERM); }
                print_violation(&violation);
                std::process::exit(2);
            }
            Ok(status) = &mut done_rx => {
                // Child exited — yield once so any in-flight violation sends can land.
                tokio::task::yield_now().await;
                if let Ok(violation) = violation_rx.try_recv() {
                    print_violation(&violation);
                    std::process::exit(2);
                }
                status
            }
        }
    } else {
        child.wait()?
    };

    // Clean up the named network namespace that was created for ProxyOnly mode.
    if needs_netns_cleanup {
        if let Err(e) = halt_sandbox::delete_sandbox_netns(std::process::id()) {
            tracing::warn!(error = %e, "Failed to delete network namespace; it will be reaped on process exit");
        }
    }

    if let Some(handle) = proxy_handle {
        handle.shutdown().await?;
    }

    // On Unix, if the sandboxed process was killed by a signal, re-raise that
    // signal so the parent shell / CI system sees the correct termination reason.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = exit_status.signal() {
            // SAFETY: raise() sends the signal to the calling process.
            // We are on the main thread, past all cleanup, about to exit.
            unsafe { libc::raise(signal) };
        }
    }

    std::process::exit(exit_status.code().unwrap_or(1));
}

fn print_violation(violation: &str) {
    eprintln!();
    eprintln!("halt: [VIOLATION] {violation}");
    let fix = if violation.starts_with("network: DNS query for") {
        // Extract domain from: network: DNS query for "domain" blocked ...
        if let Some(start) = violation.find('"') {
            if let Some(end) = violation[start + 1..].find('"') {
                let domain = &violation[start + 1..start + 1 + end];
                format!(
                    "add \"{domain}\" to [proxy.domain_allowlist] in your halt config"
                )
            } else {
                "add the domain to [proxy.domain_allowlist] in your halt config".to_string()
            }
        } else {
            "add the domain to [proxy.domain_allowlist] in your halt config".to_string()
        }
    } else if violation.starts_with("network:") {
        "verify the process uses DNS resolution and the target domain is in [proxy.domain_allowlist]".to_string()
    } else if violation.starts_with("filesystem:") {
        // Extract path from: filesystem: "proc" was denied "op" access to "/path"
        if let Some(path_start) = violation.rfind('"') {
            if path_start + 1 < violation.len() {
                let after = &violation[..path_start];
                if let Some(path_open) = after.rfind('"') {
                    let path = &violation[path_open + 1..path_start];
                    format!(
                        "add \"{path}\" to [sandbox.paths.read] or [sandbox.paths.read_write] in your halt config"
                    )
                } else {
                    "add the path to [sandbox.paths.read] or [sandbox.paths.read_write] in your halt config".to_string()
                }
            } else {
                "add the path to [sandbox.paths.read] or [sandbox.paths.read_write] in your halt config".to_string()
            }
        } else {
            "add the path to [sandbox.paths.read] or [sandbox.paths.read_write] in your halt config".to_string()
        }
    } else {
        "review your halt config".to_string()
    };
    eprintln!("halt: fix: {fix}");
    eprintln!("halt: sandboxed process killed (exit 2).");
}

fn build_proxy_config(
    settings: &halt_settings::ProxySettings,
) -> Result<ProxyConfig, CliError> {
    let mut config = ProxyConfig {
        domain_allowlist: settings.domain_allowlist.clone(),
        ..Default::default()
    };

    if let Some(ttl) = settings.dns_ttl_seconds {
        config.dns_ttl = std::time::Duration::from_secs(u64::from(ttl));
    }
    if let Some(connect_timeout) = settings.tcp_connect_timeout_secs {
        config.tcp_connect_timeout = std::time::Duration::from_secs(connect_timeout);
    }
    if let Some(idle_timeout) = settings.tcp_idle_timeout_secs {
        config.tcp_idle_timeout = std::time::Duration::from_secs(idle_timeout);
    }
    if let Some(upstream_dns) = &settings.upstream_dns {
        let addrs: Result<Vec<_>, _> = upstream_dns
            .iter()
            .map(|s| s.parse::<std::net::SocketAddr>())
            .collect();
        config.upstream_dns = Some(
            addrs.map_err(|e| CliError::Other(format!("Invalid upstream_dns entry: {e}")))?,
        );
    }

    Ok(config)
}

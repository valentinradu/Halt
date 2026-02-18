//! Domain-filtered proxy for sandbox network isolation.
//!
//! `halt-proxy` provides DNS + TCP proxying with domain allowlist enforcement.
//! Sandboxed processes can only reach the internet through this proxy,
//! which enforces domain-level access control.
//!
//! # Architecture
//!
//! ```text
//! Sandboxed Process
//!       |
//!       | (only allowed outbound)
//!       v
//! halt-proxy (127.0.0.1:PROXY_PORT)
//!       |
//!       +-- DNS Server (intercepts queries)
//!       |      |
//!       |      +-- allowed domain? --> resolve via upstream
//!       |      +-- blocked domain? --> return NXDOMAIN
//!       |
//!       +-- TCP Proxy (forwards connections)
//!              |
//!              +-- destination in resolved set? --> forward
//!              +-- unknown destination? --> reject
//! ```
//!
//! # Components
//!
//! - [`DnsServer`]: Intercepts DNS queries, resolves only allowed domains
//! - [`TcpProxy`]: Forwards TCP connections to resolved (allowed) destinations
//! - [`DomainFilter`]: Matches domains against allowlist (supports wildcards)
//! - [`ProxyServer`]: Combined DNS + TCP proxy server
//!
//! # Usage
//!
//! ```ignore
//! use halt_proxy::{ProxyServer, ProxyConfig};
//!
//! let config = ProxyConfig {
//!     bind_addr: "127.0.0.1:9300".parse()?,
//!     dns_port: 5353,
//!     domain_allowlist: vec![
//!         "api.anthropic.com".to_string(),
//!         "*.github.com".to_string(),
//!     ],
//! };
//!
//! let server = ProxyServer::new(config)?;
//! server.run().await?;
//! ```
//!
//! # Security Model
//!
//! - Binds to `127.0.0.1` only (not reachable from network)
//! - Sandboxed processes forced to use this proxy via network namespace (Linux)
//!   or sandbox-exec localhost-only rule (macOS)
//! - No authentication needed (localhost-only binding is the security boundary)
//!


mod dns;
mod filter;
mod proxy;
mod server;

pub use dns::{DnsServer, DnsServerConfig};
pub use filter::{DomainFilter, DomainMatch};
pub use proxy::{TcpProxy, TcpProxyConfig};
pub use server::{ProxyConfig, ProxyHandle, ProxyServer};

use std::net::SocketAddr;

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, ProxyError>;

/// Errors that can occur in proxy operations.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to bind to address.
    #[error("Failed to bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// DNS resolution failed.
    #[error("DNS resolution failed for {domain}: {message}")]
    DnsResolution { domain: String, message: String },

    /// Domain blocked by allowlist.
    #[error("Domain blocked: {domain}")]
    DomainBlocked { domain: String },

    /// TCP connection failed.
    #[error("TCP connection to {addr} failed: {source}")]
    TcpConnection {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Server shutdown error.
    #[error("Server shutdown error: {0}")]
    Shutdown(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Resolved address with associated domain.
///
/// Tracks which domain a resolved IP belongs to,
/// allowing the TCP proxy to verify connections are to allowed destinations.
#[derive(Debug, Clone)]
pub struct ResolvedAddress {
    /// The domain that was resolved.
    pub domain: String,

    /// The resolved IP addresses.
    pub addresses: Vec<std::net::IpAddr>,

    /// When this resolution expires (TTL-based).
    pub expires_at: std::time::Instant,
}

/// Cache of resolved domains.
///
/// Maps IP addresses back to domains for TCP proxy validation.
/// Entries expire based on DNS TTL.
pub struct ResolutionCache {
    /// Map from IP address to resolved domain info.
    entries: std::sync::RwLock<std::collections::HashMap<std::net::IpAddr, ResolvedAddress>>,
}

impl ResolutionCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Insert a resolved address into the cache.
    ///
    /// # Arguments
    /// * `resolved` - The resolved address to cache
    pub fn insert(&self, resolved: ResolvedAddress) {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        for addr in &resolved.addresses {
            entries.insert(*addr, resolved.clone());
        }
    }

    /// Look up a domain for an IP address.
    ///
    /// Returns `Some(domain)` if the IP was resolved from an allowed domain
    /// and the cache entry hasn't expired.
    ///
    /// # Arguments
    /// * `addr` - The IP address to look up
    pub fn lookup(&self, addr: &std::net::IpAddr) -> Option<String> {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.get(addr).and_then(|resolved| {
            if resolved.expires_at > std::time::Instant::now() {
                Some(resolved.domain.clone())
            } else {
                None
            }
        })
    }

    /// Remove expired entries from the cache.
    pub fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, resolved| resolved.expires_at > now);
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        self.entries.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ResolutionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state between DNS server and TCP proxy.
///
/// Contains the domain filter and resolution cache.
/// The filter is wrapped in RwLock to support runtime domain additions.
pub struct SharedState {
    /// Domain filter for allowlist matching (wrapped for mutation).
    filter: std::sync::RwLock<DomainFilter>,

    /// Cache of resolved addresses.
    pub cache: ResolutionCache,
}

impl SharedState {
    /// Create new shared state with the given domain allowlist.
    ///
    /// # Arguments
    /// * `allowlist` - List of allowed domains (supports wildcards like `*.github.com`)
    pub fn new(allowlist: Vec<String>) -> Self {
        Self {
            filter: std::sync::RwLock::new(DomainFilter::new(allowlist)),
            cache: ResolutionCache::new(),
        }
    }

    /// Check if a domain is allowed by the filter.
    pub fn is_allowed(&self, domain: &str) -> bool {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        self.filter
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_allowed(domain)
    }

    /// Add a domain to the allowlist.
    ///
    /// Creates a new filter with the added domain and replaces the current one.
    pub fn add_domain(&self, domain: String) {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        let mut filter = self.filter.write().unwrap_or_else(|e| e.into_inner());
        *filter = filter.with_domain(domain);
    }

    /// Get the current allowlist patterns.
    pub fn allowlist(&self) -> Vec<String> {
        // Use unwrap_or_else to recover from poisoned lock - the data is still valid
        self.filter
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .patterns()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ResolutionCache Tests
    // ========================================================================

    #[test]
    fn test_resolution_cache_new_is_empty() {
        let cache = ResolutionCache::new();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_resolution_cache_insert_single() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_insert_multiple_ips_same_domain() {
        let cache = ResolutionCache::new();
        let ip1: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: std::net::IpAddr = "5.6.7.8".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip1, ip2],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip1), Some("example.com".to_string()));
        assert_eq!(cache.lookup(&ip2), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_lookup_missing() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_resolution_cache_lookup_expired() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() - std::time::Duration::from_secs(1),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_resolution_cache_lookup_not_expired() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_cleanup_removes_expired() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() - std::time::Duration::from_secs(1),
        };
        cache.insert(resolved);
        assert_eq!(cache.len(), 1);
        cache.cleanup_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_resolution_cache_cleanup_keeps_valid() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        cache.cleanup_expired();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_resolution_cache_overwrite_same_ip() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved1 = ResolvedAddress {
            domain: "first.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved1);
        let resolved2 = ResolvedAddress {
            domain: "second.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved2);
        assert_eq!(cache.lookup(&ip), Some("second.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ResolutionCache::new());
        let mut handles = vec![];

        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                let ip: std::net::IpAddr = format!("1.2.3.{}", i).parse().unwrap();
                let resolved = ResolvedAddress {
                    domain: format!("domain{}.com", i),
                    addresses: vec![ip],
                    expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
                };
                cache.insert(resolved);
                cache.lookup(&ip);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_resolution_cache_ipv4_and_ipv6() {
        let cache = ResolutionCache::new();
        let ipv4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let ipv6: std::net::IpAddr = "::1".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ipv4, ipv6],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ipv4), Some("example.com".to_string()));
        assert_eq!(cache.lookup(&ipv6), Some("example.com".to_string()));
    }

    // ========================================================================
    // SharedState Tests
    // ========================================================================

    #[test]
    fn test_shared_state_new_with_empty_allowlist() {
        let state = SharedState::new(vec![]);
        assert!(!state.is_allowed("any.com"));
        assert!(state.cache.is_empty());
    }

    #[test]
    fn test_shared_state_new_with_domains() {
        let state = SharedState::new(vec!["example.com".to_string(), "*.github.com".to_string()]);
        assert!(state.is_allowed("example.com"));
        assert!(state.is_allowed("api.github.com"));
        assert!(!state.is_allowed("other.com"));
    }

    #[test]
    fn test_shared_state_filter_and_cache_connected() {
        let state = SharedState::new(vec!["example.com".to_string()]);
        assert!(state.is_allowed("example.com"));
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
    }

    // ========================================================================
    // ProxyError Tests
    // ========================================================================

    #[test]
    fn test_proxy_error_display_bind() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let err = ProxyError::Bind {
            addr,
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        };
        assert!(err.to_string().contains("127.0.0.1:8080"));
    }

    #[test]
    fn test_proxy_error_display_domain_blocked() {
        let err = ProxyError::DomainBlocked {
            domain: "evil.com".to_string(),
        };
        assert!(err.to_string().contains("evil.com"));
    }

    #[test]
    fn test_proxy_error_display_dns_resolution() {
        let err = ProxyError::DnsResolution {
            domain: "test.com".to_string(),
            message: "NXDOMAIN".to_string(),
        };
        assert!(err.to_string().contains("test.com"));
        assert!(err.to_string().contains("NXDOMAIN"));
    }

    // ========================================================================
    // RwLock Poisoning Consistency Tests
    // ========================================================================

    /// This test verifies that SharedState handles RwLock poisoning consistently.
    /// Both `cache` and `filter` now use `unwrap_or_else(|e| e.into_inner())` to
    /// recover from poisoned locks, so operations continue to work even after
    /// a thread panics while holding a lock.
    #[test]
    fn test_shared_state_filter_handles_poisoning() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));

        // Poison the filter's RwLock by panicking while holding a write lock
        let state_clone = Arc::clone(&state);
        let handle = thread::spawn(move || {
            // Get write lock on filter and panic
            let _guard = state_clone.filter.write().unwrap();
            panic!("Intentionally poisoning the filter RwLock");
        });

        // Wait for the thread to panic (poisoning the lock)
        let _ = handle.join();

        // Now try to use the filter - should NOT panic because is_allowed uses
        // unwrap_or_else to recover from poisoned lock
        let result = state.is_allowed("example.com");

        // The filter should still work correctly
        assert!(
            result,
            "Filter should still allow example.com after poisoning"
        );

        // add_domain should also work
        state.add_domain("test.com".to_string());

        // allowlist should work too
        let patterns = state.allowlist();
        assert!(patterns.len() >= 2, "Should have at least 2 patterns");
    }

    /// Verify that cache handles poisoning gracefully (control test).
    #[test]
    fn test_resolution_cache_handles_poisoning() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ResolutionCache::new());

        // Poison the RwLock
        let cache_clone = Arc::clone(&cache);
        let handle = thread::spawn(move || {
            let _guard = cache_clone.entries.write().unwrap();
            panic!("Intentionally poisoning the cache RwLock");
        });

        let _ = handle.join();

        // Cache should still work (won't panic) because it uses unwrap_or_else
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let result = cache.lookup(&ip); // Should NOT panic
        assert_eq!(result, None);

        // is_empty should also work
        let empty = cache.is_empty(); // Should NOT panic
        assert!(empty);
    }
}

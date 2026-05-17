#![forbid(unsafe_code)]
//! DNS resolution wrapper around `hickory-resolver` (F-NODE.7).
//!
//! Wraps [`TokioResolver`] with a small, opinionated surface that the rest of
//! `bibeam-node` needs:
//!
//! * `resolve_a` / `resolve_aaaa` for single-family lookups;
//! * `resolve_any` for concurrent dual-stack lookups (A + AAAA fired in
//!   parallel, results merged in deterministic v4-then-v6 order);
//! * an explicit fallback chain — the constructor first attempts the
//!   system resolver configuration (`/etc/resolv.conf` on Unix, registry on
//!   Windows), and if that fails (file missing, parse error, empty
//!   nameservers list), falls back to Cloudflare's public DNS at
//!   `1.1.1.1` / `1.0.0.1` via plain UDP + TCP.
//!
//! The fallback path is not silent: it emits a `tracing::warn!` event with
//! the upstream error, and callers can introspect via
//! [`DnsResolver::using_fallback`] for audit-log emission or config gating.
//! Operators that want to refuse the fallback (e.g. high-assurance exit
//! deployments) can construct the resolver, check `using_fallback()`, and
//! refuse to bring the daemon up.
//!
//! Errors from the upstream resolver are folded into [`CoreError::Transport`]
//! — DNS is part of the transport surface from the daemon's point of view, and
//! callers should not need to depend on the `hickory_resolver` crate to
//! pattern-match on failures.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bibeam_core::Error as CoreError;
use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use tracing::warn;

/// Fallback public DNS resolvers used when the system configuration is
/// unavailable. Matches the spec'd Cloudflare addresses (`1.1.1.1`,
/// `1.0.0.1`); IPv6 endpoints from [`CLOUDFLARE`] are included too so a v6-only
/// fallback path stays reachable.
const FALLBACK_GROUP: &hickory_resolver::config::ServerGroup<'static> = &CLOUDFLARE;

/// Wrapper around [`TokioResolver`] with a deterministic fallback to public DNS.
///
/// Cloning is cheap — the inner resolver is internally reference-counted, so
/// `DnsResolver` is `Clone`able and can be handed to multiple tasks without
/// any external locking.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    inner: TokioResolver,
    cache_ttl_secs: u64,
    using_fallback: bool,
}

impl DnsResolver {
    /// Build a resolver bound to the current Tokio runtime.
    ///
    /// The `cache_ttl_secs` value caps the maximum TTL (in seconds) that
    /// hickory's built-in positive response cache will honour. `0` disables
    /// the cap (hickory falls back to its own default of `MAX_TTL`).
    ///
    /// If `/etc/resolv.conf` (or the Windows registry equivalent) is missing,
    /// unparsable, or has no nameserver entries, this falls back to
    /// Cloudflare's `1.1.1.1` / `1.0.0.1`. The fallback is logged via
    /// `tracing::warn!`; introspect with [`Self::using_fallback`].
    pub fn new(cache_ttl_secs: u64) -> Result<Self, CoreError> {
        let (mut builder, using_fallback) = Self::system_or_fallback_builder();
        Self::tune_options(&mut builder, cache_ttl_secs);
        let inner = builder
            .build()
            .map_err(|e| CoreError::Transport(format!("dns: build resolver: {e}")))?;
        Ok(Self {
            inner,
            cache_ttl_secs,
            using_fallback,
        })
    }

    /// Returns the configured positive-response cache TTL cap, in seconds.
    #[must_use]
    pub const fn cache_ttl_secs(&self) -> u64 {
        self.cache_ttl_secs
    }

    /// Returns `true` when the resolver was built from the public-DNS
    /// fallback (system configuration was unavailable). Operators that
    /// treat DNS provider choice as policy can refuse to start in this
    /// state.
    #[must_use]
    pub const fn using_fallback(&self) -> bool {
        self.using_fallback
    }

    /// Resolve `host` to its IPv4 (A record) addresses.
    pub async fn resolve_a(&self, host: &str) -> Result<Vec<Ipv4Addr>, CoreError> {
        let lookup = self
            .inner
            .ipv4_lookup(host)
            .await
            .map_err(|e| CoreError::Transport(format!("dns: A lookup for {host:?}: {e}")))?;
        Ok(extract_v4(&lookup))
    }

    /// Resolve `host` to its IPv6 (AAAA record) addresses.
    pub async fn resolve_aaaa(&self, host: &str) -> Result<Vec<Ipv6Addr>, CoreError> {
        let lookup = self
            .inner
            .ipv6_lookup(host)
            .await
            .map_err(|e| CoreError::Transport(format!("dns: AAAA lookup for {host:?}: {e}")))?;
        Ok(extract_v6(&lookup))
    }

    /// Resolve `host` to both IPv4 and IPv6 addresses concurrently.
    ///
    /// A and AAAA queries are fired in parallel via [`tokio::join`]. The
    /// merge policy is forgiving: if exactly one family fails, the other's
    /// results are still returned; the function only errors when *both*
    /// families fail. Returned addresses are ordered v4-first, then v6 —
    /// callers that need a different ordering (e.g. RFC 8305 Happy Eyeballs)
    /// can sort after the fact.
    pub async fn resolve_any(&self, host: &str) -> Result<Vec<IpAddr>, CoreError> {
        let (v4_res, v6_res) = tokio::join!(self.resolve_a(host), self.resolve_aaaa(host));
        merge_any(host, v4_res, v6_res)
    }

    /// Try the system resolver config first; fall back to Cloudflare public
    /// DNS if reading the system config fails (file missing, parse failure,
    /// or empty nameservers list — all three surface as `Err` from
    /// [`TokioResolver::builder_tokio`]). The bool in the return is `true`
    /// when the fallback path was taken.
    fn system_or_fallback_builder()
    -> (hickory_resolver::ResolverBuilder<TokioRuntimeProvider>, bool) {
        match TokioResolver::builder_tokio() {
            Ok(builder) => (builder, false),
            Err(err) => {
                warn!(
                    error = %err,
                    fallback = "1.1.1.1, 1.0.0.1",
                    "dns: system resolver config unavailable, falling back to public DNS"
                );
                let config = ResolverConfig::udp_and_tcp(FALLBACK_GROUP);
                (Resolver::builder_with_config(config, TokioRuntimeProvider::default()), true)
            },
        }
    }

    /// Apply the resolver tuning that applies regardless of which config
    /// source we ended up with: cap the positive-response TTL, and ensure
    /// the system `hosts` file is consulted (matters for the fallback path,
    /// where the system config wasn't loaded).
    fn tune_options(
        builder: &mut hickory_resolver::ResolverBuilder<TokioRuntimeProvider>,
        cache_ttl_secs: u64,
    ) {
        let opts = builder.options_mut();
        if cache_ttl_secs > 0 {
            opts.positive_max_ttl = Some(Duration::from_secs(cache_ttl_secs));
        }
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Auto;
    }
}

/// Pull only IPv4 addresses out of a [`Lookup`], skipping anything that
/// isn't an `A` record (CNAME chains can interleave other record types).
///
/// `Record::data` is the documented public field accessor on hickory 0.26 —
/// there is no `data()` method; the field itself is `pub`.
fn extract_v4(lookup: &Lookup) -> Vec<Ipv4Addr> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(addr) => Some(addr.0),
            _ => None,
        })
        .collect()
}

/// Pull only IPv6 addresses out of a [`Lookup`], skipping anything that
/// isn't an `AAAA` record.
fn extract_v6(lookup: &Lookup) -> Vec<Ipv6Addr> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::AAAA(addr) => Some(addr.0),
            _ => None,
        })
        .collect()
}

/// Combine the per-family results from [`DnsResolver::resolve_any`] into a
/// single ordered vector. Errors are tolerated as long as at least one
/// family succeeded; if both failed the v4 error is surfaced (it tends to
/// be the more informative of the two on dual-stack networks).
fn merge_any(
    host: &str,
    v4_result: Result<Vec<Ipv4Addr>, CoreError>,
    v6_result: Result<Vec<Ipv6Addr>, CoreError>,
) -> Result<Vec<IpAddr>, CoreError> {
    match (v4_result, v6_result) {
        (Ok(v4_addrs), Ok(v6_addrs)) => {
            let mut out: Vec<IpAddr> = v4_addrs.into_iter().map(IpAddr::V4).collect();
            out.extend(v6_addrs.into_iter().map(IpAddr::V6));
            Ok(out)
        },
        (Ok(v4_addrs), Err(_)) => Ok(v4_addrs.into_iter().map(IpAddr::V4).collect()),
        (Err(_), Ok(v6_addrs)) => Ok(v6_addrs.into_iter().map(IpAddr::V6).collect()),
        (Err(err), Err(_)) => {
            Err(CoreError::Transport(format!("dns: both A and AAAA failed for {host:?}: {err}")))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `localhost` is in `/etc/hosts` on every supported target — hickory's
    /// default `ResolveHosts::Auto` policy consults that file before going
    /// to the wire, so this test is deterministic without network access.
    #[tokio::test]
    async fn resolve_a_returns_loopback_for_localhost() {
        let resolver = DnsResolver::new(60).expect("build resolver");
        let addrs = resolver.resolve_a("localhost").await.expect("A lookup");
        assert!(
            addrs.iter().any(|ip| ip == &Ipv4Addr::LOCALHOST),
            "expected 127.0.0.1 in {addrs:?}"
        );
    }

    #[tokio::test]
    async fn resolve_aaaa_returns_loopback_for_localhost() {
        let resolver = DnsResolver::new(60).expect("build resolver");
        let addrs = resolver.resolve_aaaa("localhost").await.expect("AAAA lookup");
        assert!(addrs.iter().any(|ip| ip == &Ipv6Addr::LOCALHOST), "expected ::1 in {addrs:?}");
    }

    #[tokio::test]
    async fn resolve_any_returns_both_families() {
        let resolver = DnsResolver::new(60).expect("build resolver");
        let addrs = resolver.resolve_any("localhost").await.expect("ANY lookup");
        let has_v4 = addrs
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(addr) if addr == &Ipv4Addr::LOCALHOST));
        let has_v6 = addrs
            .iter()
            .any(|ip| matches!(ip, IpAddr::V6(addr) if addr == &Ipv6Addr::LOCALHOST));
        assert!(has_v4 && has_v6, "expected both v4 and v6 loopback in {addrs:?}");
    }

    /// `.invalid` is reserved by RFC 6761 §6.4 and MUST NOT resolve; the
    /// resolver will surface either NXDOMAIN (with network) or an IO/timeout
    /// error (sandboxed). Either way we get `Err`.
    #[tokio::test]
    async fn resolve_a_returns_error_for_nonexistent() {
        let resolver = DnsResolver::new(60).expect("build resolver");
        let result = resolver.resolve_a("nxdomain-bibeam-fnode7.invalid").await;
        assert!(result.is_err(), "expected Err for reserved .invalid TLD, got {result:?}");
    }

    #[test]
    fn merge_any_keeps_v4_when_v6_fails() {
        let v4_result = Ok(vec![Ipv4Addr::LOCALHOST]);
        let v6_result = Err(CoreError::Transport("boom".into()));
        let merged = merge_any("h", v4_result, v6_result).expect("merged");
        assert_eq!(merged, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn merge_any_keeps_v6_when_v4_fails() {
        let v4_result = Err(CoreError::Transport("boom".into()));
        let v6_result = Ok(vec![Ipv6Addr::LOCALHOST]);
        let merged = merge_any("h", v4_result, v6_result).expect("merged");
        assert_eq!(merged, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[test]
    fn merge_any_errors_when_both_fail() {
        let v4_result: Result<Vec<Ipv4Addr>, CoreError> = Err(CoreError::Transport("v4".into()));
        let v6_result: Result<Vec<Ipv6Addr>, CoreError> = Err(CoreError::Transport("v6".into()));
        assert!(merge_any("h", v4_result, v6_result).is_err());
    }

    #[test]
    fn cache_ttl_secs_round_trips() {
        let resolver = DnsResolver::new(42).expect("build resolver");
        assert_eq!(resolver.cache_ttl_secs(), 42);
    }

    /// On systems where `/etc/resolv.conf` exists and parses, the resolver
    /// must not silently route to public DNS.
    #[tokio::test]
    async fn using_fallback_is_false_with_valid_system_config() {
        let resolver = DnsResolver::new(60).expect("build resolver");
        if std::path::Path::new("/etc/resolv.conf").exists() {
            assert!(
                !resolver.using_fallback(),
                "system /etc/resolv.conf present; resolver must not fall back"
            );
        }
    }
}

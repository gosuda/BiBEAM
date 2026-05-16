#![forbid(unsafe_code)]
//! `rustls` configuration for `BiBEAM`'s own coordinator-bound HTTPS.
//!
//! Per D-1, **user-application TLS is end-to-end and `BiBEAM`-transparent**:
//! when a user runs `curl https://example.com` over the tunnel, the
//! TLS handshake terminates on `example.com`, not inside `BiBEAM`.
//! That means this crate does *not* hold a TLS server config or any
//! kind of TLS interceptor. It owns exactly one thing in the TLS
//! domain: the [`coordinator_client_config`] helper that builds a
//! [`rustls::ClientConfig`] for the small set of HTTPS calls
//! `bibeam-cli` and `bibeam-node` issue against the `BiBEAM`
//! coordinator (`reqwest` / `tokio-tungstenite` wired up in
//! `bibeam-discovery`).
//!
//! ## Why `webpki-roots` and not `rustls-native-certs`
//!
//! The [`webpki_roots`] crate embeds Mozilla's curated root-CA bundle into the
//! binary at compile time. That gives us three properties we explicitly
//! want for the coordinator client:
//!
//! 1. **Reproducible builds.** The trust anchors travel with the
//!    binary and do not depend on the host's `/etc/ssl` layout, which
//!    varies wildly across the Linux distros, macOS, and Windows we
//!    ship to.
//! 2. **No FFI surface.** `rustls-native-certs` pulls in
//!    `security-framework` on macOS and `schannel` on Windows. Those
//!    are stable but add transitive `unsafe` we do not need for the
//!    `BiBEAM`-coordinator path, which only ever speaks to operator-
//!    controlled endpoints with public-CA-issued certs.
//! 3. **Smaller threat surface.** A compromised system trust store is
//!    not an avenue to MITM the `BiBEAM` control plane when the trust
//!    anchors are baked into the binary.
//!
//! The trade-off is that `BiBEAM` will need a rebuild when Mozilla
//! ships a root-store update. That is acceptable for the coordinator
//! path; user-application TLS termination still happens on the
//! end-server with whatever roots the user's libcurl / browser already
//! trusts, so this choice does not affect user-visible behaviour.
//!
//! ## Why no ECH wiring
//!
//! Per D-1, ECH (Encrypted Client Hello) lands as a follow-up PR once
//! `rustls`'s ECH support stabilises. The MVP coordinator-bound HTTPS
//! uses standard TLS 1.3 with SNI in cleartext; observers can see
//! that a connection is heading to the `BiBEAM` coordinator. That is
//! acceptable because the coordinator's hostname is already public.

use std::sync::Arc;

use rustls::ClientConfig;
use thiserror::Error;

/// Errors emitted by [`coordinator_client_config`].
///
/// The only non-success path today is `rustls`'s
/// [`with_safe_default_protocol_versions`](rustls::ConfigBuilder)
/// rejecting the protocol set — that is a static invariant of `ring`
/// with TLS 1.2 and 1.3, and so this enum exists for forward
/// compatibility rather than to gate a likely runtime failure.
///
/// The `rustls::Error` payload is boxed so the enum stays under the
/// workspace's `large-error-threshold = 64` budget.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// `rustls`'s safe-default protocol-version negotiation rejected
    /// the configuration. In practice this means the embedded provider
    /// can offer neither TLS 1.2 nor TLS 1.3 — a build-time
    /// configuration error, not a runtime one.
    #[error("rustls rejected the safe-default protocol versions: {0}")]
    Versions(#[source] Box<rustls::Error>),
}

/// Build a [`rustls::ClientConfig`] suitable for `BiBEAM`'s own
/// coordinator-bound HTTPS calls.
///
/// The returned config:
///
/// - uses the `ring` crypto provider via `rustls::crypto::ring::default_provider`
///   (consistent with the `quinn`-replacing data-plane choice in D-4
///   and with the rest of the workspace's `rustls-ring` features),
/// - trusts Mozilla's root CAs via `webpki_roots::TLS_SERVER_ROOTS`,
/// - asks for both TLS 1.2 and TLS 1.3 (the `rustls` safe default),
///   and
/// - does **not** advertise a client certificate — the coordinator
///   speaks in-band PASETO over TLS, not mTLS, per F-CRYPTO.4.
///
/// The config is wrapped in an [`Arc`] for cheap sharing across the
/// many `reqwest::Client` / `tokio-tungstenite::connect` call-sites in
/// `bibeam-discovery`.
///
/// # Errors
///
/// Returns [`TlsConfigError::Versions`] if `rustls` cannot accept
/// safe-default protocol versions for the embedded `ring` provider.
/// That is a build-time invariant under the workspace feature set, so
/// in practice this fn does not fail.
pub fn coordinator_client_config() -> Result<Arc<ClientConfig>, TlsConfigError> {
    let bundle = build_coordinator_client_config_with_store()?;
    Ok(Arc::new(bundle.config))
}

/// Construct a [`rustls::RootCertStore`] preloaded with Mozilla's
/// trust anchors from [`webpki_roots`].
fn mozilla_root_store() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    for trust_anchor in webpki_roots::TLS_SERVER_ROOTS.iter().cloned() {
        root_store.roots.push(trust_anchor);
    }
    root_store
}

/// Wire `root_store` and the ring crypto provider into a finished
/// [`ClientConfig`] using safe-default protocol versions and no
/// client-cert auth.
fn build_client_config(root_store: rustls::RootCertStore) -> Result<ClientConfig, TlsConfigError> {
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsConfigError::Versions(Box::new(err)))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

/// Test-visible (within-crate) bundle pairing the finished
/// [`ClientConfig`] with the root store that fed its verifier.
///
/// `Debug` on a finished `ClientConfig` doesn't expose verifier
/// internals, so we surface the store separately for tests that need
/// to assert "the same anchor set actually reached the builder". The
/// public [`coordinator_client_config`] keeps the
/// `Arc<ClientConfig>`-only signature.
#[derive(Debug)]
struct CoordinatorClientConfigBundle {
    config: ClientConfig,
    /// Read only in `#[cfg(test)]` paths — it exists to give tests a
    /// concrete handle on the anchor set the builder consumed. Marked
    /// `dead_code`-suppressing for the non-test build so the field
    /// can live on a struct that is otherwise only read in tests
    /// without poisoning every clippy run with a warning.
    #[cfg_attr(not(test), allow(dead_code, reason = "test-only inspection field"))]
    root_store: rustls::RootCertStore,
}

fn build_coordinator_client_config_with_store()
-> Result<CoordinatorClientConfigBundle, TlsConfigError> {
    let root_store = mozilla_root_store();
    // Clone so the bundle can retain the same anchor set that fed the
    // builder; `RootCertStore` is cheap to clone (it's a `Vec` of
    // borrowed-`Bytes`-flavoured anchors).
    let config = build_client_config(root_store.clone())?;
    Ok(CoordinatorClientConfigBundle { config, root_store })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mozilla_root_store_carries_the_compiled_in_bundle() {
        // Direct check that the helper actually moves every
        // webpki-roots anchor into the resulting store. This catches
        // an accidental switch to an empty / native store regression
        // by inspecting the store the public fn actually consumes,
        // not by recounting webpki-roots.
        let store = mozilla_root_store();
        assert_eq!(
            store.roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "mozilla_root_store must transfer every webpki-roots anchor",
        );
        assert!(!store.roots.is_empty(), "store must not be empty");
    }

    #[test]
    fn coordinator_config_builds_with_a_populated_root_store() {
        // build_coordinator_client_config_with_store retains a clone
        // of the root store that fed the builder, so the assertion
        // here inspects the *exact* anchor set the builder consumed
        // (not a separately re-read webpki_roots count). A regression
        // that routed the builder through an empty store would fail
        // this assert.
        let bundle = build_coordinator_client_config_with_store().expect("bundle must build");
        assert_eq!(
            bundle.root_store.roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "the store consumed by the builder must hold every webpki-roots anchor",
        );
        assert!(
            !bundle.root_store.roots.is_empty(),
            "the store consumed by the builder must be non-empty",
        );
        // ALPN should be empty: the coordinator-client config is
        // protocol-neutral and `reqwest` / `tokio-tungstenite` set
        // their own ALPN values when they wrap us.
        assert!(
            bundle.config.alpn_protocols.is_empty(),
            "coordinator client config must not preempt ALPN selection",
        );
    }

    #[test]
    fn public_helper_returns_an_arc_wrapped_config() {
        // Smoke check that the public, externally consumed API path
        // really succeeds end-to-end. The deeper assertion (that the
        // store actually reached the builder) lives in the bundle
        // test above.
        let config = coordinator_client_config().expect("public helper must build");
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn config_is_shareable_across_threads() {
        // The fn returns Arc<ClientConfig>; this is what reqwest /
        // tokio-tungstenite need to fan a single config across many
        // concurrent connections. Compile-time check that the Arc is
        // Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<ClientConfig>>();
        let config = coordinator_client_config().expect("build");
        let clone = Arc::clone(&config);
        assert!(Arc::strong_count(&config) >= 2);
        drop(clone);
    }
}

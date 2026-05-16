#![forbid(unsafe_code)]
//! [`WgPeerConfig`] — `WireGuard` peer-section assembly + canonical
//! `wg-quick`-parseable rendering.
//!
//! Per D-4 the data plane is `boringtun`-driven `WireGuard`. The
//! coordinator mints peer configs and `bibeam-cli` renders them out so
//! a user can either (a) hand the file to `wg-quick(8)` to drive
//! kernel `WireGuard`, or (b) feed the same fields into our own
//! `WgTunnel` (F-TRANS.1) directly. The wire shape this module emits
//! is the same shape `wg showconf(8)` prints.
//!
//! ## Canonical `[Peer]` field order
//!
//! `wg-quick` and `wg setconf` accept fields in any order, but
//! `wg showconf` emits them in a fixed order. We match that emit
//! order so output is byte-identical to what an operator would see if
//! they ran `wg showconf <ifname>` on a kernel peer they had loaded
//! from this file:
//!
//! 1. `[Peer]`
//! 2. `PublicKey` (always present)
//! 3. `PresharedKey` (omitted if absent)
//! 4. `AllowedIPs` (omitted if empty; entries joined with `", "`)
//! 5. `Endpoint` (omitted if absent; IPv6 rendered with `[…]`-brackets)
//! 6. `PersistentKeepalive` (omitted if absent)
//!
//! Every value line uses a single space on each side of `=`. Lines
//! terminate with LF. The block does NOT end with a blank line —
//! callers that combine multiple peers should add their own separator.
//!
//! The format is documented in `showconf.c` upstream
//! (<https://git.zx2c4.com/wireguard-tools/tree/src/showconf.c>).

use std::net::SocketAddr;

use ipnet::IpNet;

use bibeam_crypto::{WgPsk, WgPublicKey};

/// One `[Peer]` section of a `wg-quick(8)` config.
///
/// Built from F-CRYPTO.1's X25519 public key and F-CRYPTO.5's
/// per-rotation `WgPsk`. The `endpoint` is what F-TRANS.4's STUN
/// client (and F-TRANS.6's relay fallback) populate; it may be
/// [`None`] for a peer whose address has not yet been discovered.
#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    /// Peer's long-term X25519 public key — the value `wg setconf`
    /// expects after `PublicKey = `.
    pub public_key: WgPublicKey,
    /// Per-rotation `WireGuard` pre-shared key. `None` falls back to
    /// bare X25519.
    pub preshared_key: Option<WgPsk>,
    /// UDP endpoint to send WG packets to. `None` for a peer that
    /// only accepts inbound connections (the kernel learns its
    /// endpoint from the first authenticated packet).
    pub endpoint: Option<SocketAddr>,
    /// CIDR blocks routed through this peer. Empty means "no
    /// `AllowedIPs` line emitted" — kernel `WireGuard` rejects packets
    /// with no `AllowedIPs` match, so callers usually want at least one.
    pub allowed_ips: Vec<IpNet>,
    /// Keepalive interval in seconds. `Some(25)` is the standard NAT-
    /// punching keepalive. `None` omits the line entirely.
    pub persistent_keepalive: Option<u16>,
}

impl WgPeerConfig {
    /// Render this peer as a `wg-quick(8)`-parseable `[Peer]` section.
    ///
    /// Output is canonical per [the module-level field-order
    /// documentation](self): fields are emitted in `wg showconf`'s
    /// order, separators and whitespace match `showconf.c` exactly,
    /// and absent optionals are omitted entirely (no blank trailing
    /// `=` lines).
    #[must_use]
    pub fn to_wg_quick(&self) -> String {
        let mut output = String::with_capacity(256);
        output.push_str("[Peer]\n");
        output.push_str("PublicKey = ");
        output.push_str(&self.public_key.to_wg_base64());
        output.push('\n');
        if let Some(psk) = &self.preshared_key {
            output.push_str("PresharedKey = ");
            output.push_str(&encode_psk_base64(psk));
            output.push('\n');
        }
        if !self.allowed_ips.is_empty() {
            output.push_str("AllowedIPs = ");
            append_allowed_ips(&mut output, &self.allowed_ips);
            output.push('\n');
        }
        if let Some(endpoint) = self.endpoint {
            output.push_str("Endpoint = ");
            output.push_str(&format_endpoint(endpoint));
            output.push('\n');
        }
        if let Some(keepalive) = self.persistent_keepalive {
            output.push_str("PersistentKeepalive = ");
            output.push_str(&keepalive.to_string());
            output.push('\n');
        }
        output
    }
}

/// Encode a [`WgPsk`] in `WireGuard`'s wire-form base64 — standard
/// base64 (with padding) of the 32 raw bytes, matching `wg`'s output.
fn encode_psk_base64(psk: &WgPsk) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(psk.as_bytes())
}

/// Append a comma-space-joined list of `IpNet` entries to `output`.
///
/// `wg-quick` and `wg showconf` use the exact separator string
/// `", "` (a comma followed by one space). We match that byte-for-byte.
fn append_allowed_ips(output: &mut String, allowed_ips: &[IpNet]) {
    let mut iterator = allowed_ips.iter();
    if let Some(head) = iterator.next() {
        output.push_str(&head.to_string());
    }
    for entry in iterator {
        output.push_str(", ");
        output.push_str(&entry.to_string());
    }
}

/// Format a [`SocketAddr`] in `wg(8)`'s `Endpoint = …` shape.
///
/// IPv4 endpoints are `addr:port`. IPv6 endpoints are `[addr]:port`
/// (the brackets disambiguate the colon-laden v6 address from the
/// `:port` separator). [`SocketAddr`]'s own `Display` impl already
/// produces both shapes correctly, so we delegate.
fn format_endpoint(endpoint: SocketAddr) -> String {
    endpoint.to_string()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use base64::Engine as _;

    use bibeam_crypto::{WgPsk, WgPublicKey};

    use super::*;

    /// The expected byte-identical rendering, captured as a fixture
    /// matching what `wg showconf` upstream would emit for the same
    /// input. Lives at `tests/fixtures/wg_quick_peer.conf` and is
    /// re-loaded here so a regression that drifts either the
    /// renderer or the fixture file is caught on the next test run.
    const FIXTURE_PATH: &str = "tests/fixtures/wg_quick_peer.conf";

    fn fixture_public_key() -> WgPublicKey {
        WgPublicKey::from_wg_base64("2L8m2KuY3iJ60vJ0nNYwDt+EFENlSjAJslU9OMaIw3o=")
            .expect("fixture public key parses")
    }

    fn fixture_preshared_key() -> WgPsk {
        let raw = base64::engine::general_purpose::STANDARD
            .decode("QmlCRUFNIHRlc3QgUFNLIDMyIGJ5dGVzIHBheWxvYWQ=")
            .expect("fixture psk base64 decodes");
        let bytes: [u8; 32] = raw.as_slice().try_into().expect("fixture psk is 32 bytes");
        WgPsk::new(bytes)
    }

    fn fixture_config() -> WgPeerConfig {
        WgPeerConfig {
            public_key: fixture_public_key(),
            preshared_key: Some(fixture_preshared_key()),
            endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 51_820)),
            allowed_ips: vec![
                "10.0.0.0/24".parse().expect("ipv4 cidr"),
                "fd00::/64".parse().expect("ipv6 cidr"),
            ],
            persistent_keepalive: Some(25),
        }
    }

    #[test]
    fn renders_byte_identical_to_captured_fixture() {
        let expected = std::fs::read_to_string(FIXTURE_PATH).expect("fixture readable");
        let rendered = fixture_config().to_wg_quick();
        assert_eq!(
            rendered, expected,
            "WgPeerConfig::to_wg_quick must be byte-identical to wg-showconf fixture",
        );
    }

    #[test]
    fn omits_absent_optionals() {
        let minimal = WgPeerConfig {
            public_key: fixture_public_key(),
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
        };
        let rendered = minimal.to_wg_quick();
        let expected = format!("[Peer]\nPublicKey = {}\n", fixture_public_key().to_wg_base64());
        assert_eq!(rendered, expected, "no optional fields should leak through");
    }

    #[test]
    fn ipv6_endpoint_uses_bracketed_form() {
        let config = WgPeerConfig {
            public_key: fixture_public_key(),
            preshared_key: None,
            endpoint: Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                51_820,
            )),
            allowed_ips: vec![],
            persistent_keepalive: None,
        };
        let rendered = config.to_wg_quick();
        assert!(
            rendered.contains("Endpoint = [fd00::1]:51820\n"),
            "IPv6 endpoint must use the [addr]:port bracketed form; got:\n{rendered}",
        );
    }

    #[test]
    fn allowed_ips_joined_with_comma_space() {
        // Use a three-element list so we catch a separator regression
        // that only manifests on the second-or-later join boundary.
        let config = WgPeerConfig {
            public_key: fixture_public_key(),
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec![
                "10.0.0.0/24".parse().expect("cidr"),
                "10.1.0.0/24".parse().expect("cidr"),
                "fd00::/64".parse().expect("cidr"),
            ],
            persistent_keepalive: None,
        };
        let rendered = config.to_wg_quick();
        assert!(
            rendered.contains("AllowedIPs = 10.0.0.0/24, 10.1.0.0/24, fd00::/64\n"),
            "AllowedIPs must be joined with `, `; got:\n{rendered}",
        );
    }

    #[test]
    fn single_allowed_ip_has_no_trailing_separator() {
        let config = WgPeerConfig {
            public_key: fixture_public_key(),
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.0.0.0/24".parse().expect("cidr")],
            persistent_keepalive: None,
        };
        let rendered = config.to_wg_quick();
        assert!(rendered.contains("AllowedIPs = 10.0.0.0/24\n"));
        assert!(
            !rendered.contains("AllowedIPs = 10.0.0.0/24,"),
            "single-entry AllowedIPs must not emit a trailing separator",
        );
    }
}

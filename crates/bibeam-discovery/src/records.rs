#![forbid(unsafe_code)]
//! Rendezvous record types exchanged over the discovery plane.
//!
//! - [`PeerRecord`] — a single peer's discovery snapshot
//!   (advertised socket, exit-capable bit, capacity hint, last-seen
//!   wall-clock).
//!
//! Sibling relay- and exit-shaped records land in the F-DISC.5
//! commit; this commit (F-DISC.4) introduces only the [`PeerRecord`]
//! shape the pkarr-on-Mainline-DHT fallback needs to assemble.
//!
//! ## Wire form
//!
//! Every record (de)serialises through both
//! [`serde_json`] (HTTP REST control plane) and [`postcard`] (binary
//! pkarr/DHT TXT records). The field order and tags below are the
//! canonical form; any change is a wire-breaking event.

use std::net::SocketAddr;

use bibeam_core::{PeerId, Timestamp};
use serde::{Deserialize, Serialize};

/// One peer's discovery snapshot.
///
/// Published by the coordinator (in the HTTP control plane) and, in
/// the F-DISC.4 fallback path, by the peer itself as a pkarr-signed
/// DNS TXT record under its identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Identifier of the peer described by this record.
    pub peer_id: PeerId,
    /// Address the peer advertises for inbound connections.
    pub addr_hint: SocketAddr,
    /// Whether the peer is willing to serve as an exit node.
    pub can_exit: bool,
    /// Peer-supplied capacity score; opaque to the coordinator and
    /// to peers consuming the record.
    pub capacity_hint: u32,
    /// When this snapshot was captured.
    pub last_seen: Timestamp,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn sample_record() -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: true,
            capacity_hint: 42,
            last_seen: Timestamp::now(),
        }
    }

    #[test]
    fn peer_record_json_round_trips() {
        let original = sample_record();
        let encoded = serde_json::to_string(&original).expect("encode");
        let decoded: PeerRecord = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn peer_record_postcard_round_trips() {
        let original = sample_record();
        let encoded = postcard::to_allocvec(&original).expect("encode");
        let decoded: PeerRecord = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }
}

#![forbid(unsafe_code)]
//! Layer-3 IP packet parser.
//!
//! [`parse`] takes a slice that starts at the IPv4 or IPv6 header and
//! returns a [`ParsedPacket`] — a non-owning view containing the source
//! and destination addresses, the IP protocol number, optional transport
//! ports, and a borrow of the transport payload.
//!
//! The parser delegates the byte-level work to
//! [`etherparse::PacketHeaders::from_ip_slice`], which dispatches between
//! IPv4 and IPv6 internally based on the first nibble of the slice. That
//! means callers do not need to know the IP version ahead of time —
//! [`ParsedPacket::src`] and [`ParsedPacket::dst`] are unified
//! [`std::net::IpAddr`] values whichever family the packet uses.
//!
//! Only TCP and UDP set the port fields; for other transports
//! (`ICMP`, `ICMPv6`, `IPSec`, raw IP-in-IP) the port fields are
//! [`None`] and the payload is the transport-layer body following the
//! IP header.

use std::net::IpAddr;

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use thiserror::Error;

/// Errors returned by [`parse`].
///
/// The slice-level work is performed by [`etherparse`]; this enum exists
/// so callers can match on `bibeam-tun` errors without depending directly
/// on the [`etherparse`] error tree.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Failure inside `etherparse`'s IP slicer (truncated packet,
    /// unsupported IP version, malformed extension header, etc.).
    #[error("packet parse error: {0}")]
    Slice(#[from] etherparse::err::packet::SliceError),
    /// The slice was empty or did not contain enough bytes for a
    /// version-bit probe.
    #[error("packet too short for IP version probe")]
    TooShort,
    /// The packet's network layer was not IP (e.g. an ARP frame). The
    /// L3 pipeline only handles IPv4 and IPv6; everything else is a
    /// programming error or a malformed driver frame.
    #[error("non-IP network header in TUN slice")]
    NotIp,
}

/// A parsed view over an IPv4 or IPv6 packet.
///
/// The lifetime parameter ties [`ParsedPacket::payload`] to the input
/// slice — the parser never copies bytes. Callers can use the address
/// and port fields for routing or flow-tracking decisions; the
/// [`Self::payload`] borrow gives them the transport-layer body for
/// further inspection.
#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    /// Source IP address (IPv4 or IPv6).
    pub src: IpAddr,
    /// Destination IP address (IPv4 or IPv6).
    pub dst: IpAddr,
    /// IANA-assigned IP protocol number (e.g. `6` for TCP, `17` for UDP,
    /// `1` for ICMP, `58` for `ICMPv6`).
    pub proto: u8,
    /// Source port if the transport layer is TCP or UDP.
    pub src_port: Option<u16>,
    /// Destination port if the transport layer is TCP or UDP.
    pub dst_port: Option<u16>,
    /// Transport-layer payload (the bytes after the transport header,
    /// or the bytes after the IP header if no transport header was
    /// parsed). Borrowed from the input slice.
    pub payload: &'a [u8],
}

/// Parse a slice that starts at the IP header.
///
/// The input must be a complete IPv4 or IPv6 packet as it would appear
/// on the wire (or as it comes off a TUN device). Truncated packets or
/// unsupported IP versions return [`ParseError`].
///
/// # Errors
///
/// Returns [`ParseError::TooShort`] when `buf` is empty,
/// [`ParseError::Slice`] when [`etherparse`]'s slicer rejects the
/// layout, or [`ParseError::NotIp`] when the slice carries an ARP frame
/// or other non-IP network header (impossible from a well-behaved TUN
/// driver but defended against here to keep the type signature
/// honest).
pub fn parse(buf: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::TooShort);
    }
    let headers = PacketHeaders::from_ip_slice(buf)?;
    let net = headers.net.ok_or(ParseError::NotIp)?;
    let (src, dst, proto) = match net {
        NetHeaders::Ipv4(ip, _exts) => {
            (IpAddr::from(ip.source), IpAddr::from(ip.destination), ip.protocol.0)
        },
        NetHeaders::Ipv6(ip, _exts) => {
            (IpAddr::from(ip.source), IpAddr::from(ip.destination), ip.next_header.0)
        },
        NetHeaders::Arp(_) => return Err(ParseError::NotIp),
    };

    let (src_port, dst_port) = match headers.transport.as_ref() {
        Some(TransportHeader::Tcp(tcp)) => (Some(tcp.source_port), Some(tcp.destination_port)),
        Some(TransportHeader::Udp(udp)) => (Some(udp.source_port), Some(udp.destination_port)),
        Some(TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_)) | None => (None, None),
    };

    Ok(ParsedPacket {
        src,
        dst,
        proto,
        src_port,
        dst_port,
        payload: headers.payload.slice(),
    })
}

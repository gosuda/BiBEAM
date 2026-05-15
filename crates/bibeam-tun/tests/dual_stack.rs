#![forbid(unsafe_code)]
//! Dual-stack (IPv4 + IPv6) parser coverage for `bibeam_tun::parse`.
//!
//! The parser delegates dispatch between v4 and v6 to
//! `etherparse::PacketHeaders::from_ip_slice`, which keys on the
//! first nibble of the slice. A regression in that dispatch — for
//! example, accidentally hard-coding the v4 path or rejecting
//! `0x60`-prefixed slices — would silently drop one address family.
//! This test asserts both families parse and the extracted fields
//! match the input.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bibeam_tun::parse;
use etherparse::PacketBuilder;

const PAYLOAD: &[u8] = &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

#[test]
fn parse_ipv4_udp_packet() {
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
    let mut packet = Vec::with_capacity(builder.size(PAYLOAD.len()));
    builder.write(&mut packet, PAYLOAD).expect("serialize v4");

    let parsed = parse(&packet).expect("parse v4");
    assert_eq!(parsed.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(parsed.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(parsed.proto, 17, "UDP protocol number");
    assert_eq!(parsed.src_port, Some(1234));
    assert_eq!(parsed.dst_port, Some(5678));
    assert_eq!(parsed.payload, PAYLOAD);
}

#[test]
fn parse_ipv6_udp_packet() {
    let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
    let builder = PacketBuilder::ipv6(src_v6, dst_v6, 64).udp(4321, 8765);
    let mut packet = Vec::with_capacity(builder.size(PAYLOAD.len()));
    builder.write(&mut packet, PAYLOAD).expect("serialize v6");

    let parsed = parse(&packet).expect("parse v6");
    assert_eq!(parsed.src, IpAddr::V6(Ipv6Addr::from(src_v6)));
    assert_eq!(parsed.dst, IpAddr::V6(Ipv6Addr::from(dst_v6)));
    assert_eq!(parsed.proto, 17, "UDP protocol number");
    assert_eq!(parsed.src_port, Some(4321));
    assert_eq!(parsed.dst_port, Some(8765));
    assert_eq!(parsed.payload, PAYLOAD);
}

#![forbid(unsafe_code)]
//! MTU constants and TCP MSS clamping.
//!
//! ## Why clamp MSS
//!
//! When a TCP connection traverses our tunnel, the inner segment plus the
//! tunnel framing must fit inside the outer path MTU. If both endpoints
//! negotiate an MSS that assumes a direct path, oversized segments either
//! fragment (rare and slow) or land in a Path-MTU-Discovery black hole
//! (common with ICMP filters). Rewriting the MSS option in TCP SYN
//! segments — "MSS clamping" — fixes both peers' send sizes at handshake
//! time and avoids the problem entirely.
//!
//! ## Checksum correctness
//!
//! Mutating bytes inside a TCP header changes the header's
//! 16-bit one's-complement checksum. Recomputing the whole checksum
//! would require re-summing every word of the segment plus the
//! pseudo-header — fine offline, expensive in the data path. We instead
//! use RFC 1624's incremental update: for an in-place change of a single
//! 16-bit field from `old` to `new`,
//!
//! ```text
//! new_check = ~(~old_check + ~old + new)
//! ```
//!
//! all arithmetic in one's-complement (16-bit, end-around carry). The
//! implementation in [`clamp_tcp_mss`] adjusts the checksum word
//! alongside the MSS rewrite.

use crate::device::TunError;

/// Conventional Ethernet-edged tunnel MTU.
pub const DEFAULT_MTU: u16 = 1500;

/// Conservative byte budget for tunnel overhead.
///
/// Covers Noise AEAD tag + nonce + length prefix + transport framing.
/// The exact figure tightens once `bibeam-transport` lands its datagram
/// envelope; this value gives callers a safe upper bound for sizing
/// inner MTUs in the meantime.
pub const TUNNEL_OVERHEAD: u16 = 80;

/// IP + TCP header overhead for an unextended IPv4 segment.
const IPV4_TCP_HEADER_OVERHEAD: u16 = 40;

/// Minimum byte length for the parts of a TCP header this module
/// inspects (source/dest ports + seq + ack + data-offset + flags +
/// window + checksum + urgent = 20 bytes).
const TCP_MIN_HEADER_LEN: usize = 20;

/// TCP option kind for End-of-Option-List.
const TCP_OPT_EOL: u8 = 0;
/// TCP option kind for No-Operation.
const TCP_OPT_NOP: u8 = 1;
/// TCP option kind for Maximum Segment Size.
const TCP_OPT_MSS: u8 = 2;
/// Total length (kind + length + 16-bit value) of the MSS option.
const TCP_OPT_MSS_LEN: u8 = 4;

/// TCP flag bit for SYN.
const TCP_FLAG_SYN: u8 = 0x02;
/// Byte offset of the TCP flags within a TCP header.
const TCP_FLAGS_OFFSET: usize = 13;
/// Byte offset of the data-offset nibble (high 4 bits of byte 12).
const TCP_DATA_OFFSET_BYTE: usize = 12;
/// Byte offset of the TCP checksum within a TCP header.
const TCP_CHECKSUM_OFFSET: usize = 16;

/// Negotiate a tunnel-internal TCP MSS from a path MTU.
///
/// Subtracts the conventional IPv4 + TCP header overhead (`40`). Uses
/// [`u16::saturating_sub`] so a path MTU smaller than the header
/// overhead yields `0` rather than underflowing.
///
/// Callers are responsible for sanity-checking the result before
/// passing it as `target_mss` to [`clamp_tcp_mss`]. RFC 879
/// recommends a floor of `536`; values below that produce
/// degenerate SYNs. The validation/config layer that decides what
/// to do with too-small path MTUs (refuse the link, surface a
/// warning, fall back to the floor) lives in `bibeam-transport`,
/// not here.
#[must_use]
pub const fn negotiated_mss(path_mtu: u16) -> u16 {
    path_mtu.saturating_sub(IPV4_TCP_HEADER_OVERHEAD)
}

/// One's-complement add (16-bit, with end-around carry).
///
/// Inputs are widened to `u32` to give the carry bit somewhere to live;
/// the fold-back step `(sum & 0xffff) + (sum >> 16)` returns a value
/// that always fits in `u16` (max input is `0xffff + 0xffff = 0x1fffe`,
/// max output after fold is `0xfffe + 1 = 0xffff`). The narrowing cast
/// is exact, not truncating.
const fn ones_complement_add(left: u16, right: u16) -> u16 {
    let sum = left as u32 + right as u32;
    let folded = (sum & 0xffff) + (sum >> 16);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Folded value is bounded by 0xffff; the narrowing cast \
                  is exact, see the function docstring."
    )]
    let result = folded as u16;
    result
}

/// Apply the RFC 1624 incremental checksum update for a single 16-bit
/// field change.
const fn incremental_update(old_check: u16, old_value: u16, new_value: u16) -> u16 {
    // RFC 1624: HC' = ~(~HC + ~m + m')
    let part = ones_complement_add(!old_check, !old_value);
    let part = ones_complement_add(part, new_value);
    !part
}

/// Rewrite the TCP MSS option in `packet` if it is a SYN segment and the
/// existing MSS exceeds `target_mss`.
///
/// `packet` must be a pure TCP segment starting at the TCP header — the
/// caller has already stripped the IP header. The function:
///
/// 1. Verifies the segment is at least 20 bytes (TCP header floor).
/// 2. Checks the SYN flag; non-SYN segments are returned untouched.
/// 3. Walks the TCP options list and finds the MSS option (kind = 2,
///    length = 4).
/// 4. Reads the current MSS value; if it is larger than `target_mss`,
///    overwrites the two MSS bytes in place AND adjusts the TCP
///    checksum via an RFC 1624 incremental update.
///
/// Returns `Ok(true)` when an MSS rewrite occurred, `Ok(false)`
/// otherwise.
///
/// # Errors
///
/// Returns [`TunError::Packet`] when the segment is too short for a TCP
/// header, when the data-offset field reports a header length that does
/// not fit within `packet`, or when an option-length byte points past
/// the end of the options region.
#[allow(
    clippy::cognitive_complexity,
    reason = "This is an option-table state machine: parse kind, branch \
              on EOL / NOP / fixed-length / variable-length, repeat. \
              Splitting it across helpers would hide control flow that \
              is genuinely linear in the option layout."
)]
pub fn clamp_tcp_mss(packet: &mut [u8], target_mss: u16) -> Result<bool, TunError> {
    if packet.len() < TCP_MIN_HEADER_LEN {
        return Err(TunError::Packet(format!(
            "TCP segment too short ({} < {})",
            packet.len(),
            TCP_MIN_HEADER_LEN
        )));
    }
    let flags = packet[TCP_FLAGS_OFFSET];
    if flags & TCP_FLAG_SYN == 0 {
        return Ok(false);
    }

    // Data-offset is the high 4 bits of byte 12, measured in 32-bit
    // words. Multiply by 4 to get header length in bytes.
    let data_offset_words = (packet[TCP_DATA_OFFSET_BYTE] >> 4) as usize;
    let header_len = data_offset_words.saturating_mul(4);
    if header_len < TCP_MIN_HEADER_LEN || header_len > packet.len() {
        return Err(TunError::Packet(format!(
            "TCP data-offset {data_offset_words} (= {header_len} bytes) out of range for \
             segment of {} bytes",
            packet.len()
        )));
    }

    // Walk options bytes [20, header_len).
    let mut cursor = TCP_MIN_HEADER_LEN;
    while cursor < header_len {
        let kind = packet[cursor];
        if kind == TCP_OPT_EOL {
            return Ok(false);
        }
        if kind == TCP_OPT_NOP {
            cursor += 1;
            continue;
        }
        // Every option from here on carries a length byte at cursor+1.
        if cursor + 1 >= header_len {
            return Err(TunError::Packet("TCP option missing length byte".into()));
        }
        let opt_len = packet[cursor + 1] as usize;
        if opt_len < 2 || cursor + opt_len > header_len {
            return Err(TunError::Packet(format!(
                "TCP option length {opt_len} overruns options region"
            )));
        }
        if kind == TCP_OPT_MSS {
            if opt_len != TCP_OPT_MSS_LEN as usize {
                return Err(TunError::Packet(format!("TCP MSS option has wrong length {opt_len}")));
            }
            let mss_hi = packet[cursor + 2];
            let mss_lo = packet[cursor + 3];
            let current_mss = u16::from_be_bytes([mss_hi, mss_lo]);
            if current_mss <= target_mss {
                return Ok(false);
            }
            let check_hi = packet[TCP_CHECKSUM_OFFSET];
            let check_lo = packet[TCP_CHECKSUM_OFFSET + 1];
            let old_check = u16::from_be_bytes([check_hi, check_lo]);
            let new_check = incremental_update(old_check, current_mss, target_mss);
            let new_mss = target_mss.to_be_bytes();
            packet[cursor + 2] = new_mss[0];
            packet[cursor + 3] = new_mss[1];
            let new_check_bytes = new_check.to_be_bytes();
            packet[TCP_CHECKSUM_OFFSET] = new_check_bytes[0];
            packet[TCP_CHECKSUM_OFFSET + 1] = new_check_bytes[1];
            return Ok(true);
        }
        cursor += opt_len;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_mss_subtracts_v4_overhead() {
        assert_eq!(negotiated_mss(1500), 1460);
        assert_eq!(negotiated_mss(40), 0);
        assert_eq!(negotiated_mss(0), 0, "saturating, no underflow");
    }

    #[test]
    fn incremental_update_round_trips() {
        // Pick concrete values: pretend the segment had MSS = 1460
        // and an arbitrary checksum, then update MSS to 1280.
        let original_check = 0xb1d6;
        let after_first = incremental_update(original_check, 1460, 1280);
        let after_second = incremental_update(after_first, 1280, 1460);
        assert_eq!(after_second, original_check, "update is reversible");
    }

    /// Hand-rolled TCP-SYN-with-MSS segment.
    ///
    /// 20-byte header + 4-byte MSS option. Source-port 1, dest-port 2,
    /// seq 0, ack 0, data-offset 6 (24 bytes), flags = SYN, window
    /// 0xffff, checksum 0xabcd (test-only, not pseudo-header
    /// correct), urgent 0, option kind 2 length 4 MSS 1460.
    fn fixture_syn_with_mss(mss: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, 0x00, 0x02, // ports
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x60, 0x02, 0xff, 0xff, // data-offset(6) + SYN flag + window
            0xab, 0xcd, 0x00, 0x00, // checksum + urgent
        ];
        pkt.push(TCP_OPT_MSS);
        pkt.push(TCP_OPT_MSS_LEN);
        pkt.extend_from_slice(&mss.to_be_bytes());
        pkt
    }

    #[test]
    fn clamp_rewrites_mss_when_above_target() {
        let mut pkt = fixture_syn_with_mss(1460);
        let original_check =
            u16::from_be_bytes([pkt[TCP_CHECKSUM_OFFSET], pkt[TCP_CHECKSUM_OFFSET + 1]]);
        let rewrote = clamp_tcp_mss(&mut pkt, 1280).expect("clamp ok");
        assert!(rewrote);
        let new_mss = u16::from_be_bytes([pkt[22], pkt[23]]);
        assert_eq!(new_mss, 1280);
        let new_check =
            u16::from_be_bytes([pkt[TCP_CHECKSUM_OFFSET], pkt[TCP_CHECKSUM_OFFSET + 1]]);
        assert_ne!(new_check, original_check, "checksum updated");
        // Re-apply incremental update in reverse to confirm consistency.
        let reverted = incremental_update(new_check, 1280, 1460);
        assert_eq!(reverted, original_check);
    }

    #[test]
    fn clamp_leaves_mss_when_at_or_below_target() {
        let mut pkt = fixture_syn_with_mss(1200);
        let original = pkt.clone();
        let rewrote = clamp_tcp_mss(&mut pkt, 1280).expect("clamp ok");
        assert!(!rewrote);
        assert_eq!(pkt, original);
    }

    #[test]
    fn clamp_skips_non_syn_segments() {
        let mut pkt = fixture_syn_with_mss(1460);
        // Clear SYN, set ACK.
        pkt[TCP_FLAGS_OFFSET] = 0x10;
        let original = pkt.clone();
        let rewrote = clamp_tcp_mss(&mut pkt, 1280).expect("clamp ok");
        assert!(!rewrote);
        assert_eq!(pkt, original);
    }

    #[test]
    fn clamp_rejects_too_short_segment() {
        let mut pkt = vec![0u8; 10];
        let err = clamp_tcp_mss(&mut pkt, 1280).expect_err("too short");
        assert!(matches!(err, TunError::Packet(_)));
    }
}

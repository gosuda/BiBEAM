#![forbid(unsafe_code)]
//! Minimal RFC 8489 STUN client — just enough to learn our public
//! UDP address from a configured STUN server.
//!
//! `BiBEAM` does not need full STUN, ICE, or TURN here. F-TRANS.4
//! exists for one job: when a peer is sitting behind a NAT, find out
//! what `(public_ip, public_port)` the NAT has mapped its socket to,
//! so the coordinator can hand that address to other cohort members
//! for the ICE-lite simultaneous-open hole-punch in F-TRANS.5.
//!
//! We hand-roll the wire format (about 100 lines for parsing +
//! building) rather than pulling in `stun_codec` + `bytecodec`. The
//! pieces we actually need are:
//!
//! - A 20-byte header (2-byte message type + 2-byte length + 4-byte
//!   magic cookie + 12-byte transaction ID).
//! - A single `Binding Request` message type (`0x0001`).
//! - A single response attribute, `XOR-MAPPED-ADDRESS` (`0x0020`),
//!   which carries our public address with the magic cookie XOR'd in.
//!
//! All other STUN message types, authentication, and ICE attributes
//! are out of scope. A response we cannot parse is reported as
//! [`StunError::ResponseMalformed`].
//!
//! References:
//! - RFC 8489 §5 (header), §6 (message types), §14.1 (`XOR-MAPPED-ADDRESS`).
//! - The `XOR-MAPPED-ADDRESS` encoding XORs the port with the high
//!   16 bits of the magic cookie and XORs IPv4 addresses with the
//!   full magic cookie. (IPv6 addresses XOR with cookie ++ `txn_id` —
//!   not used by the IPv4-first MVP, but the parser handles them.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;

/// STUN magic cookie value, RFC 8489 §5.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// `Binding Request` message type, RFC 8489 §6.
const MESSAGE_TYPE_BINDING_REQUEST: u16 = 0x0001;

/// `Binding Success Response` message type, RFC 8489 §6.
const MESSAGE_TYPE_BINDING_SUCCESS: u16 = 0x0101;

/// `XOR-MAPPED-ADDRESS` attribute type, RFC 8489 §14.1.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Fixed STUN header length in bytes.
const STUN_HEADER_LEN: usize = 20;

/// Fixed transaction-ID length in bytes (12 octets, RFC 8489 §5).
const TXN_ID_LEN: usize = 12;

/// Errors emitted by [`discover_public_address`].
#[derive(Debug, Error)]
pub enum StunError {
    /// Underlying UDP socket I/O failed.
    #[error("stun: udp i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The STUN server did not respond within the caller-supplied
    /// timeout window.
    #[error("stun: server did not respond within {0:?}")]
    Timeout(Duration),
    /// The response was too short to be a valid STUN message, or did
    /// not parse as one we recognise (wrong message type, bad magic
    /// cookie, missing `XOR-MAPPED-ADDRESS`, malformed attribute).
    #[error("stun: response malformed: {0}")]
    ResponseMalformed(&'static str),
    /// The response carried a transaction ID that did not match the
    /// one we sent — could be a stale reply or an off-path
    /// injection attempt.
    #[error("stun: transaction id mismatch")]
    TransactionMismatch,
}

/// Issue one RFC 8489 Binding Request to `stun_server` over `socket`
/// and return the public `SocketAddr` the server saw us at.
///
/// The caller's `socket` is reused for both the request and the
/// response, so the resulting `(addr, port)` actually reflects the
/// NAT-mapped binding for that socket (this is the whole point of
/// the dance — making a fresh socket gives you a fresh, potentially
/// different, NAT binding).
///
/// `timeout` bounds the wait for the response. STUN does not have
/// the kind of retry machinery TURN has; we keep this fn minimal by
/// not retransmitting — callers that want retry should wrap us in
/// `tokio::retry`-style logic with a separate budget.
///
/// # Errors
///
/// Returns [`StunError::Io`] for socket failures,
/// [`StunError::Timeout`] when no response arrives in time,
/// [`StunError::TransactionMismatch`] if the response txn-id does
/// not match the request, and [`StunError::ResponseMalformed`] for
/// any parse failure on the response bytes.
pub async fn discover_public_address(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let txn_id: [u8; TXN_ID_LEN] = generate_transaction_id();
    let request = build_binding_request(txn_id);
    socket.send_to(&request, stun_server).await?;
    let mut response_buf = [0_u8; 512];
    let recv_outcome = tokio::time::timeout(timeout, socket.recv_from(&mut response_buf)).await;
    let recv_result = recv_outcome.map_err(|_elapsed| StunError::Timeout(timeout))?;
    let (recv_len, _src) = recv_result?;
    parse_binding_response(&response_buf[..recv_len], txn_id)
}

/// Generate a fresh 12-byte STUN transaction ID via the cryptographic
/// thread-local RNG.
fn generate_transaction_id() -> [u8; TXN_ID_LEN] {
    rand::random()
}

/// Build a 20-byte Binding Request with no attributes and the given
/// transaction ID.
fn build_binding_request(txn_id: [u8; TXN_ID_LEN]) -> [u8; STUN_HEADER_LEN] {
    let mut request = [0_u8; STUN_HEADER_LEN];
    request[0..2].copy_from_slice(&MESSAGE_TYPE_BINDING_REQUEST.to_be_bytes());
    // Message length (excludes header): zero attributes -> zero bytes.
    request[2..4].copy_from_slice(&0_u16.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&txn_id);
    request
}

/// Parse a STUN Binding Success Response and return the
/// `XOR-MAPPED-ADDRESS` it carries, after verifying the message type,
/// magic cookie, and transaction ID.
fn parse_binding_response(
    bytes: &[u8],
    expected_txn_id: [u8; TXN_ID_LEN],
) -> Result<SocketAddr, StunError> {
    let (header_msg_len, body) = parse_header(bytes, expected_txn_id)?;
    if body.len() < usize::from(header_msg_len) {
        return Err(StunError::ResponseMalformed("body shorter than declared length"));
    }
    let body = &body[..usize::from(header_msg_len)];
    let attribute = find_xor_mapped_address(body)?;
    parse_xor_mapped_address(attribute, expected_txn_id)
}

/// Validate the 20-byte STUN header and return `(message_length, body)`
/// — `body` is the slice immediately after the header.
fn parse_header(
    bytes: &[u8],
    expected_txn_id: [u8; TXN_ID_LEN],
) -> Result<(u16, &[u8]), StunError> {
    if bytes.len() < STUN_HEADER_LEN {
        return Err(StunError::ResponseMalformed("buffer shorter than STUN header"));
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if msg_type != MESSAGE_TYPE_BINDING_SUCCESS {
        return Err(StunError::ResponseMalformed("message type is not Binding Success"));
    }
    let msg_len = u16::from_be_bytes([bytes[2], bytes[3]]);
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::ResponseMalformed("magic cookie mismatch"));
    }
    if bytes[8..20] != expected_txn_id {
        return Err(StunError::TransactionMismatch);
    }
    Ok((msg_len, &bytes[STUN_HEADER_LEN..]))
}

/// Scan the TLV attribute body and return the first
/// `XOR-MAPPED-ADDRESS` attribute's *value* slice (i.e. the bytes
/// after that attribute's 4-byte TLV header).
fn find_xor_mapped_address(body: &[u8]) -> Result<&[u8], StunError> {
    let mut cursor: usize = 0;
    while cursor + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let attr_len = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]);
        let value_start = cursor + 4;
        let value_end = value_start + usize::from(attr_len);
        if value_end > body.len() {
            return Err(StunError::ResponseMalformed("attribute extends past body"));
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return Ok(&body[value_start..value_end]);
        }
        // Attributes are padded to a 4-byte boundary on the wire.
        cursor = value_end + ((4 - (usize::from(attr_len) % 4)) % 4);
    }
    Err(StunError::ResponseMalformed("XOR-MAPPED-ADDRESS attribute missing"))
}

/// Decode an `XOR-MAPPED-ADDRESS` value: family byte, port (XOR'd
/// with the high 16 bits of the cookie), and address bytes (XOR'd
/// with the cookie for IPv4, cookie ++ `txn_id` for IPv6).
fn parse_xor_mapped_address(
    value: &[u8],
    txn_id: [u8; TXN_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::ResponseMalformed("XOR-MAPPED-ADDRESS too short"));
    }
    let family = value[1];
    let port_xored = u16::from_be_bytes([value[2], value[3]]);
    let port = port_xored ^ u16::try_from(MAGIC_COOKIE >> 16).unwrap_or(0);
    let cookie_bytes: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
    match family {
        0x01 => parse_xor_address_ipv4(value, port, cookie_bytes),
        0x02 => parse_xor_address_ipv6(value, port, cookie_bytes, txn_id),
        _ => Err(StunError::ResponseMalformed("XOR-MAPPED-ADDRESS unknown family")),
    }
}

/// Decode the IPv4 form of `XOR-MAPPED-ADDRESS`.
fn parse_xor_address_ipv4(
    value: &[u8],
    port: u16,
    cookie_bytes: [u8; 4],
) -> Result<SocketAddr, StunError> {
    if value.len() < 8 {
        return Err(StunError::ResponseMalformed("XOR-MAPPED-ADDRESS v4 too short"));
    }
    let mut octets = [0_u8; 4];
    for (index, slot) in octets.iter_mut().enumerate() {
        *slot = value[4 + index] ^ cookie_bytes[index];
    }
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
}

/// Decode the IPv6 form of `XOR-MAPPED-ADDRESS`. Address bytes are
/// XOR'd against `cookie ++ txn_id` (16 bytes total).
fn parse_xor_address_ipv6(
    value: &[u8],
    port: u16,
    cookie_bytes: [u8; 4],
    txn_id: [u8; TXN_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if value.len() < 20 {
        return Err(StunError::ResponseMalformed("XOR-MAPPED-ADDRESS v6 too short"));
    }
    let mut octets = [0_u8; 16];
    let (cookie_part, txn_part) = octets.split_at_mut(4);
    for (index, slot) in cookie_part.iter_mut().enumerate() {
        *slot = value[4 + index] ^ cookie_bytes[index];
    }
    for (index, slot) in txn_part.iter_mut().enumerate() {
        *slot = value[8 + index] ^ txn_id[index];
    }
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::net::UdpSocket;

    use super::*;

    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn binding_request_has_correct_header_shape() {
        let txn_id = [0x42; TXN_ID_LEN];
        let request = build_binding_request(txn_id);
        assert_eq!(request.len(), STUN_HEADER_LEN);
        assert_eq!(&request[0..2], &MESSAGE_TYPE_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[2..4], &0_u16.to_be_bytes(), "no-attribute length");
        assert_eq!(&request[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..20], &txn_id);
    }

    #[test]
    fn parses_a_v4_xor_mapped_address_round_trip() {
        // Hand-build a valid Binding Success Response with one
        // XOR-MAPPED-ADDRESS attribute carrying 203.0.113.45:51820.
        let txn_id = [0x11; TXN_ID_LEN];
        let mapped_port: u16 = 51_820;
        let mapped_ip = Ipv4Addr::new(203, 0, 113, 45);
        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&MESSAGE_TYPE_BINDING_SUCCESS.to_be_bytes());
        response.extend_from_slice(&12_u16.to_be_bytes()); // attribute body length: 4-byte TLV header + 8-byte value
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        // Attribute TLV
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.push(0x00); // reserved
        response.push(0x01); // family = IPv4
        let cookie_high =
            u16::try_from(MAGIC_COOKIE >> 16).expect("STUN cookie upper half is 16 bits");
        response.extend_from_slice(&(mapped_port ^ cookie_high).to_be_bytes());
        let cookie_bytes: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
        let raw = mapped_ip.octets();
        for index in 0..4 {
            response.push(raw[index] ^ cookie_bytes[index]);
        }
        let decoded = parse_binding_response(&response, txn_id).expect("must parse");
        assert_eq!(
            decoded,
            SocketAddr::new(IpAddr::V4(mapped_ip), mapped_port),
            "XOR-MAPPED-ADDRESS round-trip",
        );
    }

    #[test]
    fn rejects_response_with_wrong_txn_id() {
        let req_txn = [0x55; TXN_ID_LEN];
        let resp_txn = [0x66; TXN_ID_LEN];
        let mut response = Vec::new();
        response.extend_from_slice(&MESSAGE_TYPE_BINDING_SUCCESS.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&resp_txn);
        let outcome = parse_binding_response(&response, req_txn);
        assert!(matches!(outcome, Err(StunError::TransactionMismatch)));
    }

    #[test]
    fn rejects_response_with_wrong_cookie() {
        let txn_id = [0x77; TXN_ID_LEN];
        let mut response = Vec::new();
        response.extend_from_slice(&MESSAGE_TYPE_BINDING_SUCCESS.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
        response.extend_from_slice(&txn_id);
        let outcome = parse_binding_response(&response, txn_id);
        assert!(matches!(outcome, Err(StunError::ResponseMalformed(_))));
    }

    #[test]
    fn rejects_response_missing_xor_mapped() {
        // Header-only success response with zero attributes => missing.
        let txn_id = [0x88; TXN_ID_LEN];
        let mut response = Vec::new();
        response.extend_from_slice(&MESSAGE_TYPE_BINDING_SUCCESS.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        let outcome = parse_binding_response(&response, txn_id);
        assert!(matches!(outcome, Err(StunError::ResponseMalformed(_))));
    }

    #[tokio::test]
    async fn discover_returns_timeout_when_server_is_silent() {
        // Bind a real loopback socket that we never read from — it
        // accepts the inbound STUN request but never replies, which
        // is exactly the "silent server" condition the timeout
        // branch is supposed to handle. Aiming at a routable
        // black-hole address (e.g. TEST-NET-1) is unsafe in a test
        // harness because Linux may surface an ICMP-derived ECONNREFUSED
        // on the recv side, which would mask the timeout path.
        let silent_server = UdpSocket::bind(loopback_v4_zero()).await.expect("bind silent");
        let silent_addr = silent_server.local_addr().expect("silent addr");
        let client_socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind client");
        let outcome =
            discover_public_address(&client_socket, silent_addr, Duration::from_millis(25))
                .await
                .expect_err("must time out");
        assert!(matches!(outcome, StunError::Timeout(_)));
        // `silent_server` is kept alive across the test so the OS
        // does not surface ECONNREFUSED on the client side.
        drop(silent_server);
    }

    #[tokio::test]
    async fn discover_round_trips_against_a_mock_stun_server() {
        // In-process mock STUN responder: bind a server socket, wait
        // for the request, reply with a hand-built Binding Success
        // mapped to a canned (ip, port).
        let server_socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind server");
        let server_addr = server_socket.local_addr().expect("server addr");
        let client_socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind client");

        let mapped_addr: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 64_321);

        let mock = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (recv_len, client_addr) =
                server_socket.recv_from(&mut buf).await.expect("server recv");
            assert!(recv_len >= STUN_HEADER_LEN);
            let txn_id: [u8; TXN_ID_LEN] = buf[8..20].try_into().expect("txn id slice fits");
            let response = build_mock_success_response(txn_id, mapped_addr);
            server_socket.send_to(&response, client_addr).await.expect("server send");
        });

        let observed = discover_public_address(&client_socket, server_addr, Duration::from_secs(1))
            .await
            .expect("client must succeed");
        mock.await.expect("server task joined");
        assert_eq!(observed, mapped_addr);
    }

    /// Hand-craft a STUN Binding Success Response carrying the
    /// caller-supplied `mapped_addr` as an `XOR-MAPPED-ADDRESS`
    /// attribute. The same routine the test in
    /// `parses_a_v4_xor_mapped_address_round_trip` uses for the
    /// in-memory case; lifted here so the live-socket mock test
    /// shares the encoder.
    fn build_mock_success_response(txn_id: [u8; TXN_ID_LEN], mapped_addr: SocketAddr) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&MESSAGE_TYPE_BINDING_SUCCESS.to_be_bytes());
        response.extend_from_slice(&12_u16.to_be_bytes()); // 4-byte attr header + 8-byte value
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.push(0x00); // reserved
        response.push(0x01); // family v4
        let cookie_high =
            u16::try_from(MAGIC_COOKIE >> 16).expect("STUN cookie upper half is 16 bits");
        response.extend_from_slice(&(mapped_addr.port() ^ cookie_high).to_be_bytes());
        match mapped_addr.ip() {
            IpAddr::V4(v4) => {
                let cookie_bytes: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
                let octets = v4.octets();
                for (index, octet) in octets.into_iter().enumerate() {
                    response.push(octet ^ cookie_bytes[index]);
                }
            },
            IpAddr::V6(_) => panic!("mock helper covers v4 only"),
        }
        response
    }
}

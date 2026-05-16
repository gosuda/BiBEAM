# bibeam-transport

`WireGuard` data plane built on the `boringtun` userspace state machine over a `tokio::net::UdpSocket`; coordinator-bound `rustls` HTTPS, STUN hole-punch, relay and SOCKS5 fallbacks, per-session rate limiter.

//! GatekeeperVPN Client Library
//!
//! Provides VPN client functionality for reuse in `gkvpn` CLI and other tools.
//!
//! # Main entry points
//! - [`connection::run_with_reconnect`] — VPN with auto-reconnect
//! - [`handshake::perform_handshake`] — Noise IK handshake
//! - [`test_mode::run_test_mode`] — Echo test mode

pub mod connection;
pub mod handshake;
pub mod signal;
pub mod test_mode;
pub mod vpn;

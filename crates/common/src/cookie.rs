//! DoS protection: cookie challenge + rate limiting
//!
//! - `CookieState` — keyed BLAKE2s cookie generation/validation with secret rotation
//! - `HandshakeRateLimiter` — per-IP and global rate limiting for handshake packets
//! - `RateLimitDecision` — result of rate limit check

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use blake2::Blake2sMac;
use blake2::digest::Mac;
use blake2::digest::consts::U32;
use subtle::ConstantTimeEq;

/// BLAKE2s MAC type with 32-byte output
type Blake2sMac256 = Blake2sMac<U32>;

/// Cookie size in bytes
pub const COOKIE_SIZE: usize = 32;

/// Secret rotation interval
const SECRET_ROTATION_SECS: u64 = 120;

/// Per-IP handshake limit per minute
const PER_IP_LIMIT: usize = 5;
/// Per-IP window duration
const PER_IP_WINDOW_SECS: u64 = 60;

/// Global handshake-per-second threshold to trigger cookie mode
const GLOBAL_THRESHOLD_PER_SEC: usize = 10;

/// Interval for cleaning up stale per-IP entries
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Result of rate limit check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Below thresholds — process handshake normally
    Allow,
    /// Global threshold exceeded — require cookie challenge
    RequireCookie,
    /// Per-IP limit exceeded — silently drop
    Drop,
}

/// Cookie generation and validation using keyed BLAKE2s.
///
/// Maintains current and previous secrets for rotation tolerance.
pub struct CookieState {
    current_secret: [u8; 32],
    previous_secret: [u8; 32],
    last_rotation: Instant,
}

impl Default for CookieState {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieState {
    /// Create a new CookieState with random secrets
    pub fn new() -> Self {
        let mut current = [0u8; 32];
        let mut previous = [0u8; 32];
        rand::fill(&mut current);
        rand::fill(&mut previous);

        Self {
            current_secret: current,
            previous_secret: previous,
            last_rotation: Instant::now(),
        }
    }

    /// Rotate the secret if enough time has passed.
    /// Returns true if rotation occurred.
    pub fn maybe_rotate(&mut self) -> bool {
        if self.last_rotation.elapsed().as_secs() >= SECRET_ROTATION_SECS {
            self.previous_secret = self.current_secret;
            rand::fill(&mut self.current_secret);
            self.last_rotation = Instant::now();
            true
        } else {
            false
        }
    }

    /// Generate a cookie for the given address
    pub fn generate_cookie(&self, addr: &IpAddr) -> [u8; COOKIE_SIZE] {
        self.mac_with_secret(&self.current_secret, addr)
    }

    /// Validate a cookie against current or previous secret (constant-time)
    pub fn validate_cookie(&self, addr: &IpAddr, cookie: &[u8; COOKIE_SIZE]) -> bool {
        let expected_current = self.mac_with_secret(&self.current_secret, addr);
        let expected_previous = self.mac_with_secret(&self.previous_secret, addr);

        let match_current = expected_current.ct_eq(cookie);
        let match_previous = expected_previous.ct_eq(cookie);

        // Either match is acceptable
        (match_current | match_previous).into()
    }

    fn mac_with_secret(&self, secret: &[u8; 32], addr: &IpAddr) -> [u8; COOKIE_SIZE] {
        let mut mac = Blake2sMac256::new_from_slice(secret).expect("BLAKE2s accepts 32-byte key");

        match addr {
            IpAddr::V4(v4) => mac.update(&v4.octets()),
            IpAddr::V6(v6) => mac.update(&v6.octets()),
        }

        let result = mac.finalize();
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&result.into_bytes());
        cookie
    }

    /// Force rotation (for testing)
    #[cfg(test)]
    fn force_rotate(&mut self) {
        self.previous_secret = self.current_secret;
        rand::fill(&mut self.current_secret);
        self.last_rotation = Instant::now();
    }
}

/// Per-IP and global rate limiter for handshake packets.
pub struct HandshakeRateLimiter {
    /// Per-IP handshake timestamps
    per_ip: HashMap<IpAddr, Vec<Instant>>,
    /// Global handshake timestamps (last second window)
    global: Vec<Instant>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl Default for HandshakeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeRateLimiter {
    pub fn new() -> Self {
        Self {
            per_ip: HashMap::new(),
            global: Vec::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Check whether a handshake from `addr` should be allowed, challenged, or dropped.
    pub fn check(&mut self, addr: &IpAddr) -> RateLimitDecision {
        let now = Instant::now();

        self.maybe_cleanup(now);

        // Per-IP check first (most restrictive → Drop)
        if let Some(timestamps) = self.per_ip.get(addr) {
            let cutoff = now - std::time::Duration::from_secs(PER_IP_WINDOW_SECS);
            let recent = timestamps.iter().filter(|t| **t > cutoff).count();
            if recent >= PER_IP_LIMIT {
                return RateLimitDecision::Drop;
            }
        }

        // Global check (RequireCookie if above threshold)
        let one_sec_ago = now - std::time::Duration::from_secs(1);
        let global_recent = self.global.iter().filter(|t| **t > one_sec_ago).count();
        if global_recent >= GLOBAL_THRESHOLD_PER_SEC {
            return RateLimitDecision::RequireCookie;
        }

        RateLimitDecision::Allow
    }

    /// Record that a handshake from `addr` was processed.
    pub fn record(&mut self, addr: &IpAddr) {
        let now = Instant::now();

        self.per_ip.entry(*addr).or_default().push(now);
        self.global.push(now);
    }

    /// Remove stale entries periodically
    fn maybe_cleanup(&mut self, now: Instant) {
        if now.duration_since(self.last_cleanup).as_secs() < CLEANUP_INTERVAL_SECS {
            return;
        }

        let ip_cutoff = now - std::time::Duration::from_secs(PER_IP_WINDOW_SECS);
        self.per_ip.retain(|_, timestamps| {
            timestamps.retain(|t| *t > ip_cutoff);
            !timestamps.is_empty()
        });

        let global_cutoff = now - std::time::Duration::from_secs(1);
        self.global.retain(|t| *t > global_cutoff);

        self.last_cleanup = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet))
    }

    // --- CookieState tests ---

    #[test]
    fn cookie_generate_validate() {
        let state = CookieState::new();
        let a = addr(1);
        let cookie = state.generate_cookie(&a);
        assert!(state.validate_cookie(&a, &cookie));
    }

    #[test]
    fn cookie_different_addr_fails() {
        let state = CookieState::new();
        let a1 = addr(1);
        let a2 = addr(2);
        let cookie = state.generate_cookie(&a1);
        assert!(!state.validate_cookie(&a2, &cookie));
    }

    #[test]
    fn cookie_survives_one_rotation() {
        let mut state = CookieState::new();
        let a = addr(1);
        let cookie = state.generate_cookie(&a);

        // Rotate once — previous secret should still validate
        state.force_rotate();
        assert!(state.validate_cookie(&a, &cookie));
    }

    #[test]
    fn cookie_fails_after_double_rotation() {
        let mut state = CookieState::new();
        let a = addr(1);
        let cookie = state.generate_cookie(&a);

        // Two rotations — original secret is lost
        state.force_rotate();
        state.force_rotate();
        assert!(!state.validate_cookie(&a, &cookie));
    }

    // --- HandshakeRateLimiter tests ---

    #[test]
    fn rate_limiter_allow_below_threshold() {
        let mut limiter = HandshakeRateLimiter::new();
        let a = addr(1);

        // First handshake should be allowed
        assert_eq!(limiter.check(&a), RateLimitDecision::Allow);
        limiter.record(&a);

        // Still below per-IP limit
        assert_eq!(limiter.check(&a), RateLimitDecision::Allow);
    }

    #[test]
    fn rate_limiter_require_cookie_above_threshold() {
        let mut limiter = HandshakeRateLimiter::new();

        // Flood from different IPs to trigger global threshold
        for i in 0..GLOBAL_THRESHOLD_PER_SEC {
            let a = addr(i as u8 + 10);
            limiter.record(&a);
        }

        // Next handshake from a new IP should require cookie
        let new_addr = addr(200);
        assert_eq!(limiter.check(&new_addr), RateLimitDecision::RequireCookie);
    }

    #[test]
    fn rate_limiter_drop_per_ip() {
        let mut limiter = HandshakeRateLimiter::new();
        let a = addr(1);

        // Record PER_IP_LIMIT handshakes from the same IP
        for _ in 0..PER_IP_LIMIT {
            limiter.record(&a);
        }

        // Next should be dropped
        assert_eq!(limiter.check(&a), RateLimitDecision::Drop);
    }

    #[test]
    fn rate_limiter_cleanup_stale() {
        let mut limiter = HandshakeRateLimiter::new();
        let a = addr(1);

        // Record some entries
        limiter.record(&a);
        assert!(!limiter.per_ip.is_empty());
        assert!(!limiter.global.is_empty());

        // Force cleanup by manipulating last_cleanup
        limiter.last_cleanup =
            Instant::now() - std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);

        // Entries are fresh so they survive cleanup
        let _ = limiter.check(&a);
        assert!(!limiter.per_ip.is_empty());

        // But global entries older than 1 second are cleaned
        // (our entries are very fresh, so they survive)
        assert!(!limiter.global.is_empty());
    }
}

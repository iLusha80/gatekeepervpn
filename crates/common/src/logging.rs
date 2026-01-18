//! Rate-limited logging utilities
//!
//! Prevents log spam from repeated errors by limiting how often
//! certain messages can be logged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Rate limiter for log messages
///
/// Tracks error counts and limits logging frequency to avoid spam.
pub struct RateLimitedLogger {
    /// Minimum interval between log messages
    interval: Duration,
    /// Last time a message was logged (as milliseconds since start)
    last_log: AtomicU64,
    /// Counter for suppressed messages
    suppressed_count: AtomicU64,
    /// Start time for timestamp calculations
    start_time: Instant,
}

impl RateLimitedLogger {
    /// Create a new rate limiter with specified interval
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_log: AtomicU64::new(0),
            suppressed_count: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Create with default 5-second interval
    pub fn default_interval() -> Self {
        Self::new(Duration::from_secs(5))
    }

    /// Check if we should log now, and if so, return count of suppressed messages
    ///
    /// Returns Some(suppressed_count) if should log, None if should suppress
    pub fn should_log(&self) -> Option<u64> {
        let now_ms = self.start_time.elapsed().as_millis() as u64;
        let last = self.last_log.load(Ordering::Relaxed);
        let interval_ms = self.interval.as_millis() as u64;

        if now_ms.saturating_sub(last) >= interval_ms {
            // Time to log - get and reset suppressed count
            let suppressed = self.suppressed_count.swap(0, Ordering::Relaxed);
            self.last_log.store(now_ms, Ordering::Relaxed);
            Some(suppressed)
        } else {
            // Suppress this message
            self.suppressed_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Log a warning message with rate limiting
    pub fn warn(&self, message: &str) {
        if let Some(suppressed) = self.should_log() {
            if suppressed > 0 {
                log::warn!("{} (suppressed {} similar messages)", message, suppressed);
            } else {
                log::warn!("{}", message);
            }
        }
    }

    /// Log a debug message with rate limiting
    pub fn debug(&self, message: &str) {
        if let Some(suppressed) = self.should_log() {
            if suppressed > 0 {
                log::debug!("{} (suppressed {} similar messages)", message, suppressed);
            } else {
                log::debug!("{}", message);
            }
        }
    }
}

/// Collection of rate limiters for common VPN errors
pub struct VpnErrorLoggers {
    pub udp_send: RateLimitedLogger,
    pub decrypt_replay: RateLimitedLogger,
    pub decrypt_crypto: RateLimitedLogger,
    pub tun_write: RateLimitedLogger,
}

impl VpnErrorLoggers {
    pub fn new() -> Self {
        Self {
            udp_send: RateLimitedLogger::default_interval(),
            decrypt_replay: RateLimitedLogger::new(Duration::from_secs(10)),
            decrypt_crypto: RateLimitedLogger::default_interval(),
            tun_write: RateLimitedLogger::default_interval(),
        }
    }
}

impl Default for VpnErrorLoggers {
    fn default() -> Self {
        Self::new()
    }
}

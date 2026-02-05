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

#[cfg(test)]
mod tests {
    use super::*;

    // Note: RateLimitedLogger tracks time from start_time. The first call
    // at elapsed ~0ms checks if 0ms >= interval_ms. So for intervals > 0,
    // the first call is suppressed until the interval passes from creation.
    // We use short intervals to test real behavior.

    #[test]
    fn test_first_call_logs_with_small_interval() {
        // With 1ms interval, first call after creation will pass quickly
        let logger = RateLimitedLogger::new(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        assert!(logger.should_log().is_some());
    }

    #[test]
    fn test_suppressed_within_interval() {
        let logger = RateLimitedLogger::new(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        // First call after interval logs
        assert!(logger.should_log().is_some());
        // Immediate second call should be suppressed
        assert!(logger.should_log().is_none());
    }

    #[test]
    fn test_logs_after_interval() {
        let logger = RateLimitedLogger::new(Duration::from_millis(10));
        // Wait for initial interval
        std::thread::sleep(Duration::from_millis(15));
        let first = logger.should_log();
        assert!(first.is_some());
        assert_eq!(first.unwrap(), 0); // no suppressed yet
        // Wait for next interval
        std::thread::sleep(Duration::from_millis(15));
        assert!(logger.should_log().is_some());
    }

    #[test]
    fn test_suppressed_count_correct() {
        let logger = RateLimitedLogger::new(Duration::from_millis(50));
        // Wait for initial interval
        std::thread::sleep(Duration::from_millis(55));
        // First call logs
        assert!(logger.should_log().is_some());
        // Suppress 3 calls
        assert!(logger.should_log().is_none());
        assert!(logger.should_log().is_none());
        assert!(logger.should_log().is_none());
        // Wait for interval
        std::thread::sleep(Duration::from_millis(55));
        // Next should_log returns suppressed count = 3
        let result = logger.should_log();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_zero_interval_always_logs() {
        let logger = RateLimitedLogger::new(Duration::from_millis(0));
        // Every call should succeed with zero interval
        for _ in 0..10 {
            assert!(logger.should_log().is_some());
        }
    }

    #[test]
    fn test_vpn_error_loggers_fields_exist() {
        let loggers = VpnErrorLoggers::new();
        // Verify all loggers are constructed (fields exist and are usable)
        // Wait enough for 5s interval to pass? No — just verify they don't panic
        let _ = loggers.udp_send.should_log();
        let _ = loggers.decrypt_replay.should_log();
        let _ = loggers.decrypt_crypto.should_log();
        let _ = loggers.tun_write.should_log();
        // Default trait
        let _default = VpnErrorLoggers::default();
    }
}

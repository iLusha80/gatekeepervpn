//! VPN metrics and statistics
//!
//! Thread-safe counters for tracking VPN traffic and connection statistics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// VPN metrics with atomic counters for thread-safe access
pub struct VpnMetrics {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub replay_packets_dropped: AtomicU64,
    pub roaming_events: AtomicU64,
    pub active_clients: AtomicU64,
    pub start_time: Instant,
}

impl Default for VpnMetrics {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            replay_packets_dropped: AtomicU64::new(0),
            roaming_events: AtomicU64::new(0),
            active_clients: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

impl VpnMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sent packet
    pub fn record_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a received packet
    pub fn record_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a successful handshake
    pub fn record_handshake_ok(&self) {
        self.handshakes_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed handshake
    pub fn record_handshake_fail(&self) {
        self.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replayed packet drop
    pub fn record_replay(&self) {
        self.replay_packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a roaming event (client endpoint change)
    pub fn record_roaming(&self) {
        self.roaming_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the number of active clients
    pub fn set_active_clients(&self, n: u64) {
        self.active_clients.store(n, Ordering::Relaxed);
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Format human-readable summary
    pub fn format_summary(&self) -> String {
        let uptime = self.uptime_secs();
        let hours = uptime / 3600;
        let minutes = (uptime % 3600) / 60;
        let seconds = uptime % 60;

        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);

        format!(
            "Uptime: {:02}:{:02}:{:02}\n\
             Active clients: {}\n\
             Packets sent: {}, received: {}\n\
             Bytes sent: {}, received: {}\n\
             Handshakes: {} ok, {} failed\n\
             Replay packets dropped: {}\n\
             Roaming events: {}",
            hours,
            minutes,
            seconds,
            self.active_clients.load(Ordering::Relaxed),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
            format_bytes(bytes_sent),
            format_bytes(bytes_received),
            self.handshakes_completed.load(Ordering::Relaxed),
            self.handshakes_failed.load(Ordering::Relaxed),
            self.replay_packets_dropped.load(Ordering::Relaxed),
            self.roaming_events.load(Ordering::Relaxed),
        )
    }

    /// Serialize to JSON string (without serde_json dependency)
    pub fn to_json(&self) -> String {
        format!(
            "{{\
            \"uptime_secs\":{},\
            \"active_clients\":{},\
            \"packets_sent\":{},\
            \"packets_received\":{},\
            \"bytes_sent\":{},\
            \"bytes_received\":{},\
            \"handshakes_completed\":{},\
            \"handshakes_failed\":{},\
            \"replay_packets_dropped\":{},\
            \"roaming_events\":{}\
            }}",
            self.uptime_secs(),
            self.active_clients.load(Ordering::Relaxed),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.handshakes_completed.load(Ordering::Relaxed),
            self.handshakes_failed.load(Ordering::Relaxed),
            self.replay_packets_dropped.load(Ordering::Relaxed),
            self.roaming_events.load(Ordering::Relaxed),
        )
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_zeroed() {
        let m = VpnMetrics::new();
        assert_eq!(m.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(m.packets_received.load(Ordering::Relaxed), 0);
        assert_eq!(m.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(m.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(m.handshakes_completed.load(Ordering::Relaxed), 0);
        assert_eq!(m.handshakes_failed.load(Ordering::Relaxed), 0);
        assert_eq!(m.replay_packets_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(m.roaming_events.load(Ordering::Relaxed), 0);
        assert_eq!(m.active_clients.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_sent() {
        let m = VpnMetrics::new();
        m.record_sent(100);
        m.record_sent(200);
        assert_eq!(m.packets_sent.load(Ordering::Relaxed), 2);
        assert_eq!(m.bytes_sent.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_record_received() {
        let m = VpnMetrics::new();
        m.record_received(500);
        assert_eq!(m.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(m.bytes_received.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_record_handshake_ok() {
        let m = VpnMetrics::new();
        m.record_handshake_ok();
        m.record_handshake_ok();
        assert_eq!(m.handshakes_completed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_handshake_fail() {
        let m = VpnMetrics::new();
        m.record_handshake_fail();
        assert_eq!(m.handshakes_failed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_record_replay() {
        let m = VpnMetrics::new();
        m.record_replay();
        m.record_replay();
        m.record_replay();
        assert_eq!(m.replay_packets_dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_set_active_clients() {
        let m = VpnMetrics::new();
        m.set_active_clients(5);
        assert_eq!(m.active_clients.load(Ordering::Relaxed), 5);
        m.set_active_clients(3);
        assert_eq!(m.active_clients.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_format_summary_contains_fields() {
        let m = VpnMetrics::new();
        m.record_sent(1024);
        m.record_received(2048);
        m.set_active_clients(2);
        let summary = m.format_summary();
        assert!(summary.contains("Active clients: 2"));
        assert!(summary.contains("Packets sent: 1, received: 1"));
        assert!(summary.contains("1.0 KiB"));
        assert!(summary.contains("2.0 KiB"));
    }

    #[test]
    fn test_to_json_valid_format() {
        let m = VpnMetrics::new();
        m.record_sent(100);
        m.record_handshake_ok();
        let json = m.to_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"packets_sent\":1"));
        assert!(json.contains("\"bytes_sent\":100"));
        assert!(json.contains("\"handshakes_completed\":1"));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(VpnMetrics::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let m = m.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.record_sent(10);
                    m.record_received(20);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(m.packets_sent.load(Ordering::Relaxed), 1000);
        assert_eq!(m.bytes_sent.load(Ordering::Relaxed), 10000);
        assert_eq!(m.packets_received.load(Ordering::Relaxed), 1000);
        assert_eq!(m.bytes_received.load(Ordering::Relaxed), 20000);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn test_record_roaming() {
        let m = VpnMetrics::new();
        assert_eq!(m.roaming_events.load(Ordering::Relaxed), 0);
        m.record_roaming();
        m.record_roaming();
        assert_eq!(m.roaming_events.load(Ordering::Relaxed), 2);
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] snow::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid packet")]
    InvalidPacket,

    #[error("replayed or out-of-order packet")]
    ReplayedPacket,

    #[error("handshake not completed")]
    HandshakeNotCompleted,

    #[error("invalid key format")]
    InvalidKey,

    #[error("config error: {0}")]
    Config(String),

    #[error("TUN device error: {0}")]
    Tun(String),

    #[error("routing error: {0}")]
    Route(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("obfuscation error: {0}")]
    Obfuscation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_invalid_packet() {
        let e = Error::InvalidPacket;
        assert_eq!(e.to_string(), "invalid packet");
    }

    #[test]
    fn test_display_replayed_packet() {
        let e = Error::ReplayedPacket;
        assert_eq!(e.to_string(), "replayed or out-of-order packet");
    }

    #[test]
    fn test_display_handshake_not_completed() {
        let e = Error::HandshakeNotCompleted;
        assert_eq!(e.to_string(), "handshake not completed");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
        assert!(e.to_string().contains("file not found"));
    }

    #[test]
    fn test_display_config_and_variants() {
        let e = Error::Config("bad value".to_string());
        assert_eq!(e.to_string(), "config error: bad value");

        let e = Error::Tun("tun fail".to_string());
        assert_eq!(e.to_string(), "TUN device error: tun fail");

        let e = Error::Route("route fail".to_string());
        assert_eq!(e.to_string(), "routing error: route fail");

        let e = Error::Dns("dns fail".to_string());
        assert_eq!(e.to_string(), "DNS error: dns fail");

        let e = Error::Obfuscation("obf fail".to_string());
        assert_eq!(e.to_string(), "obfuscation error: obf fail");

        let e = Error::InvalidKey;
        assert_eq!(e.to_string(), "invalid key format");
    }
}

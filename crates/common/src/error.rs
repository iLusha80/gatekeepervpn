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
}

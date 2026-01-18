//! IPv4 packet header parsing utilities

use std::net::Ipv4Addr;

use crate::Error;

/// Minimum IPv4 header size (without options)
pub const IPV4_MIN_HEADER_SIZE: usize = 20;

/// IPv4 version number
pub const IPV4_VERSION: u8 = 4;

/// Get the IP version from a packet
///
/// Returns the version number (4 for IPv4, 6 for IPv6)
pub fn get_ip_version(packet: &[u8]) -> Option<u8> {
    packet.first().map(|b| b >> 4)
}

/// Check if packet is IPv4
pub fn is_ipv4(packet: &[u8]) -> bool {
    get_ip_version(packet) == Some(IPV4_VERSION)
}

/// Extract source IP address from an IPv4 packet
///
/// # Arguments
/// * `packet` - Raw IP packet bytes (starting with IP header)
///
/// # Returns
/// * `Ok(Ipv4Addr)` - Source IP address
/// * `Err` - If packet is too short or not IPv4
pub fn get_source_ip(packet: &[u8]) -> Result<Ipv4Addr, Error> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    // Source IP is at offset 12-15
    let src_bytes: [u8; 4] = packet[12..16]
        .try_into()
        .map_err(|_| Error::InvalidPacket)?;

    Ok(Ipv4Addr::from(src_bytes))
}

/// Extract destination IP address from an IPv4 packet
///
/// # Arguments
/// * `packet` - Raw IP packet bytes (starting with IP header)
///
/// # Returns
/// * `Ok(Ipv4Addr)` - Destination IP address
/// * `Err` - If packet is too short or not IPv4
pub fn get_destination_ip(packet: &[u8]) -> Result<Ipv4Addr, Error> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    // Destination IP is at offset 16-19
    let dst_bytes: [u8; 4] = packet[16..20]
        .try_into()
        .map_err(|_| Error::InvalidPacket)?;

    Ok(Ipv4Addr::from(dst_bytes))
}

/// Extract both source and destination IP addresses from an IPv4 packet
///
/// More efficient than calling `get_source_ip` and `get_destination_ip` separately
pub fn get_src_dst_ips(packet: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), Error> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    let src_bytes: [u8; 4] = packet[12..16]
        .try_into()
        .map_err(|_| Error::InvalidPacket)?;
    let dst_bytes: [u8; 4] = packet[16..20]
        .try_into()
        .map_err(|_| Error::InvalidPacket)?;

    Ok((Ipv4Addr::from(src_bytes), Ipv4Addr::from(dst_bytes)))
}

/// Get the IP protocol number from an IPv4 packet
///
/// Common values:
/// - 1: ICMP
/// - 6: TCP
/// - 17: UDP
pub fn get_protocol(packet: &[u8]) -> Result<u8, Error> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    // Protocol is at offset 9
    Ok(packet[9])
}

/// Get the total length of the IP packet from the header
pub fn get_total_length(packet: &[u8]) -> Result<u16, Error> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    // Total length is at offset 2-3 (big-endian)
    Ok(u16::from_be_bytes([packet[2], packet[3]]))
}

/// Get the IP header length in bytes
///
/// Returns the actual header length (IHL * 4)
pub fn get_header_length(packet: &[u8]) -> Result<usize, Error> {
    if packet.is_empty() {
        return Err(Error::InvalidPacket);
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(Error::InvalidPacket);
    }

    // IHL is in lower 4 bits of first byte
    let ihl = (packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;

    if header_len < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidPacket);
    }

    Ok(header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid IPv4 packet for testing
    fn make_test_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        // Version (4) + IHL (5 = 20 bytes)
        packet[0] = 0x45;
        // Total length (20 bytes)
        packet[2] = 0;
        packet[3] = 20;
        // Protocol (TCP = 6)
        packet[9] = 6;
        // Source IP (offset 12-15)
        packet[12..16].copy_from_slice(&src.octets());
        // Destination IP (offset 16-19)
        packet[16..20].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    fn test_get_source_ip() {
        let src = Ipv4Addr::new(10, 10, 10, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let packet = make_test_packet(src, dst);

        assert_eq!(get_source_ip(&packet).unwrap(), src);
    }

    #[test]
    fn test_get_destination_ip() {
        let src = Ipv4Addr::new(10, 10, 10, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let packet = make_test_packet(src, dst);

        assert_eq!(get_destination_ip(&packet).unwrap(), dst);
    }

    #[test]
    fn test_get_src_dst_ips() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let packet = make_test_packet(src, dst);

        let (parsed_src, parsed_dst) = get_src_dst_ips(&packet).unwrap();
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_packet_too_short() {
        let packet = vec![0x45; 10]; // Too short
        assert!(get_source_ip(&packet).is_err());
        assert!(get_destination_ip(&packet).is_err());
    }

    #[test]
    fn test_not_ipv4() {
        // IPv6 packet (version = 6)
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // Version 6

        assert!(get_source_ip(&packet).is_err());
        assert!(get_destination_ip(&packet).is_err());
    }

    #[test]
    fn test_get_protocol() {
        let packet = make_test_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(get_protocol(&packet).unwrap(), 6); // TCP
    }

    #[test]
    fn test_get_total_length() {
        let packet = make_test_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(get_total_length(&packet).unwrap(), 20);
    }

    #[test]
    fn test_get_header_length() {
        let packet = make_test_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(get_header_length(&packet).unwrap(), 20);
    }

    #[test]
    fn test_is_ipv4() {
        let packet = make_test_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert!(is_ipv4(&packet));

        let mut ipv6_packet = vec![0u8; 40];
        ipv6_packet[0] = 0x60;
        assert!(!is_ipv4(&ipv6_packet));
    }

    #[test]
    fn test_get_ip_version() {
        let packet = make_test_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(get_ip_version(&packet), Some(4));

        let mut ipv6_packet = vec![0u8; 40];
        ipv6_packet[0] = 0x60;
        assert_eq!(get_ip_version(&ipv6_packet), Some(6));

        assert_eq!(get_ip_version(&[]), None);
    }
}

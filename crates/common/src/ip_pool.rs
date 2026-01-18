//! IP address pool management for VPN subnet allocation

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::Error;

/// IP address pool for managing VPN client addresses
#[derive(Debug, Clone)]
pub struct IpPool {
    /// Network address (e.g., 10.10.10.0)
    network: u32,
    /// Subnet mask in CIDR notation (e.g., 24)
    mask: u8,
    /// Allocated IP addresses
    allocated: HashSet<Ipv4Addr>,
    /// Next IP to try allocating
    next_ip: u32,
}

impl IpPool {
    /// Create a new IP pool from subnet specification
    ///
    /// # Arguments
    /// * `subnet` - Network address (e.g., "10.10.10.0")
    /// * `mask` - CIDR mask (e.g., 24 for /24)
    ///
    /// # Example
    /// ```
    /// use gatekeeper_common::ip_pool::IpPool;
    /// let pool = IpPool::new("10.10.10.0", 24).unwrap();
    /// ```
    pub fn new(subnet: &str, mask: u8) -> Result<Self, Error> {
        if mask > 30 {
            return Err(Error::Config(format!(
                "Subnet mask /{} too small (min /30)",
                mask
            )));
        }

        let network_addr: Ipv4Addr = subnet
            .parse()
            .map_err(|_| Error::Config(format!("Invalid subnet address: {}", subnet)))?;

        let network = u32::from(network_addr);

        // Verify the address is actually a network address
        let host_bits = 32 - mask;
        let network_mask = !((1u32 << host_bits) - 1);
        if network & !network_mask != 0 {
            return Err(Error::Config(format!(
                "Address {} is not a valid network address for /{} (expected {})",
                subnet,
                mask,
                Ipv4Addr::from(network & network_mask)
            )));
        }

        // Start allocation from .2 (skip network .0 and server .1)
        let next_ip = network + 2;

        Ok(Self {
            network,
            mask,
            allocated: HashSet::new(),
            next_ip,
        })
    }

    /// Get the server address (first usable IP in subnet)
    ///
    /// Returns the .1 address (e.g., 10.10.10.1 for 10.10.10.0/24)
    pub fn server_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network + 1)
    }

    /// Get the network address
    pub fn network_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    /// Get the broadcast address
    pub fn broadcast_address(&self) -> Ipv4Addr {
        let host_bits = 32 - self.mask;
        let broadcast = self.network | ((1u32 << host_bits) - 1);
        Ipv4Addr::from(broadcast)
    }

    /// Get the subnet mask
    pub fn subnet_mask(&self) -> u8 {
        self.mask
    }

    /// Get netmask as Ipv4Addr (e.g., 255.255.255.0 for /24)
    pub fn netmask(&self) -> Ipv4Addr {
        let host_bits = 32 - self.mask;
        let mask = !((1u32 << host_bits) - 1);
        Ipv4Addr::from(mask)
    }

    /// Get the maximum number of client addresses available
    pub fn max_clients(&self) -> u32 {
        let host_bits = 32 - self.mask;
        // Total hosts - network - broadcast - server
        (1u32 << host_bits) - 3
    }

    /// Get the number of currently allocated addresses
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if an IP is within this subnet
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let host_bits = 32 - self.mask;
        let network_mask = !((1u32 << host_bits) - 1);
        (ip_u32 & network_mask) == self.network
    }

    /// Allocate the next available IP address
    ///
    /// Returns `None` if pool is exhausted
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        let broadcast = u32::from(self.broadcast_address());
        let start = self.next_ip;
        let mut current = self.next_ip;

        loop {
            let ip = Ipv4Addr::from(current);

            // Skip if already allocated
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                // Move next_ip forward
                self.next_ip = if current + 1 >= broadcast {
                    self.network + 2 // Wrap around
                } else {
                    current + 1
                };
                return Some(ip);
            }

            // Move to next IP
            current = if current + 1 >= broadcast {
                self.network + 2 // Wrap around
            } else {
                current + 1
            };

            // Full circle - pool exhausted
            if current == start {
                return None;
            }
        }
    }

    /// Allocate a specific IP address
    ///
    /// Returns `Err` if the IP is not in subnet, already allocated, or reserved
    pub fn allocate_specific(&mut self, ip: Ipv4Addr) -> Result<(), Error> {
        let ip_u32 = u32::from(ip);

        // Check if in subnet
        if !self.contains(ip) {
            return Err(Error::Config(format!(
                "IP {} is not in subnet {}/{}",
                ip,
                Ipv4Addr::from(self.network),
                self.mask
            )));
        }

        // Check if it's the network or broadcast address
        if ip_u32 == self.network || ip_u32 == u32::from(self.broadcast_address()) {
            return Err(Error::Config(format!(
                "Cannot allocate reserved address {}",
                ip
            )));
        }

        // Check if it's the server address
        if ip == self.server_address() {
            return Err(Error::Config(format!(
                "Cannot allocate server address {}",
                ip
            )));
        }

        // Check if already allocated
        if self.allocated.contains(&ip) {
            return Err(Error::Config(format!("IP {} already allocated", ip)));
        }

        self.allocated.insert(ip);
        Ok(())
    }

    /// Release an allocated IP address
    pub fn release(&mut self, ip: Ipv4Addr) -> bool {
        self.allocated.remove(&ip)
    }

    /// Check if an IP is allocated
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.allocated.contains(&ip)
    }

    /// Get all allocated IPs
    pub fn allocated_ips(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.allocated.iter()
    }

    /// Set the next IP to allocate (for restoring state)
    pub fn set_next_ip(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        if self.contains(ip) && ip_u32 > self.network + 1 {
            self.next_ip = ip_u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool() {
        let pool = IpPool::new("10.10.10.0", 24).unwrap();
        assert_eq!(pool.server_address(), Ipv4Addr::new(10, 10, 10, 1));
        assert_eq!(pool.network_address(), Ipv4Addr::new(10, 10, 10, 0));
        assert_eq!(pool.broadcast_address(), Ipv4Addr::new(10, 10, 10, 255));
        assert_eq!(pool.max_clients(), 253); // 256 - 3 (network, broadcast, server)
    }

    #[test]
    fn test_new_pool_16() {
        let pool = IpPool::new("10.10.0.0", 16).unwrap();
        assert_eq!(pool.server_address(), Ipv4Addr::new(10, 10, 0, 1));
        assert_eq!(pool.broadcast_address(), Ipv4Addr::new(10, 10, 255, 255));
        assert_eq!(pool.max_clients(), 65533); // 65536 - 3
    }

    #[test]
    fn test_invalid_network_address() {
        let result = IpPool::new("10.10.10.5", 24);
        assert!(result.is_err());
    }

    #[test]
    fn test_allocate() {
        let mut pool = IpPool::new("10.10.10.0", 24).unwrap();

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 10, 10, 2));

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 10, 10, 3));

        assert_eq!(pool.allocated_count(), 2);
    }

    #[test]
    fn test_allocate_specific() {
        let mut pool = IpPool::new("10.10.10.0", 24).unwrap();

        pool.allocate_specific(Ipv4Addr::new(10, 10, 10, 100))
            .unwrap();
        assert!(pool.is_allocated(Ipv4Addr::new(10, 10, 10, 100)));

        // Double allocation should fail
        let result = pool.allocate_specific(Ipv4Addr::new(10, 10, 10, 100));
        assert!(result.is_err());
    }

    #[test]
    fn test_release() {
        let mut pool = IpPool::new("10.10.10.0", 24).unwrap();

        let ip = pool.allocate().unwrap();
        assert!(pool.is_allocated(ip));

        pool.release(ip);
        assert!(!pool.is_allocated(ip));
    }

    #[test]
    fn test_contains() {
        let pool = IpPool::new("10.10.10.0", 24).unwrap();

        assert!(pool.contains(Ipv4Addr::new(10, 10, 10, 50)));
        assert!(!pool.contains(Ipv4Addr::new(10, 10, 11, 50)));
        assert!(!pool.contains(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_netmask() {
        let pool24 = IpPool::new("10.10.10.0", 24).unwrap();
        assert_eq!(pool24.netmask(), Ipv4Addr::new(255, 255, 255, 0));

        let pool16 = IpPool::new("10.10.0.0", 16).unwrap();
        assert_eq!(pool16.netmask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_small_pool() {
        let mut pool = IpPool::new("192.168.1.0", 30).unwrap();
        assert_eq!(pool.max_clients(), 1); // /30 = 4 addresses - 3 reserved = 1 client

        let ip = pool.allocate().unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 2));

        // Pool should be exhausted
        assert!(pool.allocate().is_none());
    }

    #[test]
    fn test_wrap_around() {
        let mut pool = IpPool::new("10.10.10.0", 30).unwrap();

        // Allocate and release
        let ip = pool.allocate().unwrap();
        pool.release(ip);

        // Should get the same IP back
        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip, ip2);
    }
}

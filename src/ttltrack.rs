use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// Constants
const TCP_CONNRECORD_KEY_LEN: usize = 37; // Length of the TCP connection record key
const TCP_CLEANUP_INTERVAL_SEC: u64 = 30; // Cleanup interval in seconds

// TCP connection tracking information structure
#[derive(Clone)]
pub struct TcpConntrackInfo {
    pub is_ipv6: u8, // Whether the connection is IPv6
    pub ttl: u8, // Time to live
    pub src_ip: [u32; 4], // Source IP address
    pub src_port: u16, // Source port
    pub dst_ip: [u32; 4], // Destination IP address
    pub dst_port: u16, // Destination port
}

// TCP connection record structure
#[derive(Clone)]
struct TcpConnrecord {
    key: [u8; TCP_CONNRECORD_KEY_LEN], // Connection key
    time: SystemTime, // Record time
    ttl: u16, // Time to live
}

// TCP connection tracking structure
pub struct TcpConntrack {
    conntrack: HashMap<[u8; TCP_CONNRECORD_KEY_LEN], TcpConnrecord>, // HashMap of connection records
    last_cleanup: SystemTime, // Last cleanup time
}

impl TcpConntrack {
    // Create a new TCP connection tracking instance
    pub fn new() -> Self {
        Self {
            conntrack: HashMap::new(),
            last_cleanup: SystemTime::now(),
        }
    }

    // Fill key data
    fn fill_key_data(
        key: &mut [u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: u8,
        src_ip: &[u32; 4],
        dst_ip: &[u32; 4],
        src_port: u16,
        dst_port: u16,
    ) {
        let mut offset = 0;

        // Set IP version
        key[offset] = if is_ipv6 != 0 { b'6' } else { b'4' };
        offset += 1;

        // Fill IP addresses and ports
        if is_ipv6 != 0 {
            key[offset..offset + 16].copy_from_slice(&src_ip.iter().flat_map(|&x| x.to_be_bytes()).collect::<Vec<_>>());
            offset += 16;
            key[offset..offset + 16].copy_from_slice(&dst_ip.iter().flat_map(|&x| x.to_be_bytes()).collect::<Vec<_>>());
            offset += 16;
        } else {
            key[offset..offset + 4].copy_from_slice(&src_ip[0].to_be_bytes());
            offset += 4;
            key[offset..offset + 4].copy_from_slice(&dst_ip[0].to_be_bytes());
            offset += 4;
        }

        key[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
        offset += 2;
        key[offset..offset + 2].copy_from_slice(&dst_port.to_be_bytes());
    }

    // Parse data from key
    fn fill_data_from_key(
        key: &[u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: &mut u8,
        src_ip: &mut [u32; 4],
        dst_ip: &mut [u32; 4],
        src_port: &mut u16,
        dst_port: &mut u16,
    ) {
        let mut offset = 0;

        // Parse IP version
        *is_ipv6 = if key[0] == b'6' { 1 } else { 0 };
        offset += 1;

        // Parse IP addresses and ports
        if *is_ipv6 != 0 {
            for i in 0..4 {
                src_ip[i] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
                offset += 4;
            }
            for i in 0..4 {
                dst_ip[i] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
                offset += 4;
            }
        } else {
            src_ip[0] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
            offset += 4;
            dst_ip[0] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
            offset += 4;
        }

        *src_port = u16::from_be_bytes([key[offset], key[offset + 1]]);
        offset += 2;
        *dst_port = u16::from_be_bytes([key[offset], key[offset + 1]]);
    }

    // Construct key
    fn construct_key(
        src_ip: &[u32; 4],
        dst_ip: &[u32; 4],
        src_port: u16,
        dst_port: u16,
        key: &mut [u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: u8,
    ) {
        Self::fill_key_data(key, is_ipv6, src_ip, dst_ip, src_port, dst_port);
    }

    // Deconstruct key and fill connection info
    fn deconstruct_key(
        key: &[u8; TCP_CONNRECORD_KEY_LEN],
        connrecord: &TcpConnrecord,
        conn_info: &mut TcpConntrackInfo,
    ) {
        Self::fill_data_from_key(
            key,
            &mut conn_info.is_ipv6,
            &mut conn_info.src_ip,
            &mut conn_info.dst_ip,
            &mut conn_info.src_port,
            &mut conn_info.dst_port,
        );
        conn_info.ttl = connrecord.ttl as u8;
    }

    // Check and get TCP connection record
    fn check_get_tcp_conntrack_key(&self, key: &[u8; TCP_CONNRECORD_KEY_LEN]) -> Option<&TcpConnrecord> {
        self.conntrack.get(key)
    }

    // Add TCP connection record
    fn add_tcp_conntrack(
        &mut self,
        src_ip: &[u32; 4],
        dst_ip: &[u32; 4],
        src_port: u16,
        dst_port: u16,
        is_ipv6: u8,
        ttl: u8,
    ) -> bool {
        // Check if IP addresses and ports are valid
        if src_ip.iter().all(|&x| x == 0) || dst_ip.iter().all(|&x| x == 0) || src_port == 0 || dst_port == 0 {
            return false;
        }

        let mut key = [0u8; TCP_CONNRECORD_KEY_LEN];
        Self::construct_key(src_ip, dst_ip, src_port, dst_port, &mut key, is_ipv6);

        // If record does not exist, add new record
        if self.check_get_tcp_conntrack_key(&key).is_none() {
            let connrecord = TcpConnrecord {
                key,
                time: SystemTime::now(),
                ttl: ttl as u16,
            };
            self.conntrack.insert(key, connrecord);
            true
        } else {
            false
        }
    }

    // Cleanup expired connection records
    fn tcp_cleanup(&mut self) {
        let now = SystemTime::now();
        if now.duration_since(self.last_cleanup).unwrap_or(Duration::new(0, 0)).as_secs() >= TCP_CLEANUP_INTERVAL_SEC {
            self.last_cleanup = now;
            self.conntrack.retain(|_, connrecord| {
                now.duration_since(connrecord.time).unwrap_or(Duration::new(0, 0)).as_secs() < TCP_CLEANUP_INTERVAL_SEC
            });
        }
    }

    // Handle incoming connection
    pub fn tcp_handle_incoming(
        &mut self,
        src_ip: [u32; 4],
        dst_ip: [u32; 4],
        src_port: u16,
        dst_port: u16,
        is_ipv6: u8,
        ttl: u8,
    ) -> bool {
        self.tcp_cleanup();
        self.add_tcp_conntrack(&src_ip, &dst_ip, src_port, dst_port, is_ipv6, ttl)
    }

    // Handle outgoing connection
    pub fn tcp_handle_outgoing(
        &mut self,
        src_ip: &[u32; 4],
        dst_ip: &[u32; 4],
        src_port: u16,
        dst_port: u16,
        conn_info: &mut TcpConntrackInfo,
        is_ipv6: u8,
    ) -> bool {
        let mut key = [0u8; TCP_CONNRECORD_KEY_LEN];
        Self::construct_key(dst_ip, src_ip, dst_port, src_port, &mut key, is_ipv6);

        // If record exists, deconstruct and remove record
        if let Some(connrecord) = self.check_get_tcp_conntrack_key(&key) {
            Self::deconstruct_key(&key, connrecord, conn_info);
            self.conntrack.remove(&key);
            true
        } else {
            false
        }
    }
}

// Calculate TTL for fake packet
pub fn tcp_get_auto_ttl(
    ttl: u8,
    auto_ttl_1: u8,
    auto_ttl_2: u8,
    min_hops: u8,
    max_ttl: u8,
) -> u8 {
    let nhops = if ttl > 98 && ttl < 128 {
        128 - ttl
    } else if ttl > 34 && ttl < 64 {
        64 - ttl
    } else {
        return 0;
    };

    if nhops <= auto_ttl_1 || nhops < min_hops {
        return 0;
    }

    let mut ttl_of_fake_packet = nhops - auto_ttl_2;
    if ttl_of_fake_packet < auto_ttl_2 && nhops <= 9 {
        ttl_of_fake_packet = nhops - auto_ttl_1 - ((auto_ttl_2 - auto_ttl_1) as f32 * (nhops as f32 / 10.0)).trunc() as u8;
    }

    if max_ttl != 0 && ttl_of_fake_packet > max_ttl {
        ttl_of_fake_packet = max_ttl;
    }

    ttl_of_fake_packet
}

// Set HTTP fragment size option
static mut HTTP_FRAGMENT_SIZE: Option<u32> = None;

pub fn set_http_fragment_size_option(fragment_size: u32) {
    unsafe {
        match HTTP_FRAGMENT_SIZE {
            None => HTTP_FRAGMENT_SIZE = Some(fragment_size),
            Some(size) if size != fragment_size => {
                println!(
                    "WARNING: HTTP fragment size is already set to {}, not changing.",
                    size
                );
            }
            _ => {}
        }
    }
}

// Handle outgoing connection and parse packet
pub fn tcp_handle_outgoing_ttl_parse_packet_if(
    conntrack: &mut TcpConntrack,
    packet_v4: bool,
    packet_v6: bool,
    src_addr_v4: Option<&[u32; 4]>,
    dst_addr_v4: Option<&[u32; 4]>,
    src_port: u16,
    dst_port: u16,
    src_addr_v6: Option<&[u32; 4]>,
    dst_addr_v6: Option<&[u32; 4]>,
    tcp_conn_info: &mut TcpConntrackInfo,
    do_auto_ttl: bool,
    ttl_min_hops: u8,
    auto_ttl_1: u8,
    auto_ttl_2: u8,
    auto_ttl_max: u8,
    do_tcp_verb: bool,
) -> bool {
    if (packet_v4 && conntrack.tcp_handle_outgoing(
            src_addr_v4.unwrap(),
            dst_addr_v4.unwrap(),
            src_port,
            dst_port,
            tcp_conn_info,
            0,
        )) || (packet_v6 && conntrack.tcp_handle_outgoing(
            src_addr_v6.unwrap(),
            dst_addr_v6.unwrap(),
            src_port,
            dst_port,
            tcp_conn_info,
            1,
        )) {
        if do_auto_ttl {
            let ttl_of_fake_packet = tcp_get_auto_ttl(
                tcp_conn_info.ttl,
                auto_ttl_1,
                auto_ttl_2,
                ttl_min_hops,
                auto_ttl_max,
            );
            if do_tcp_verb {
                println!(
                    "Connection TTL = {}, Fake TTL = {}",
                    tcp_conn_info.ttl, ttl_of_fake_packet
                );
            }
        } else if ttl_min_hops > 0 {
            if tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_hops, 0) == 0 {
                return false;
            }
        }
        true
    } else {
        false
    }
}

// Handle outgoing fake packet
pub fn tcp_handle_outgoing_fake_packet<F>(
    conntrack: &mut TcpConntrack,
    func: F,
    packet_v4: bool,
    packet_v6: bool,
    src_addr_v4: Option<&[u32; 4]>,
    dst_addr_v4: Option<&[u32; 4]>,
    src_port: u16,
    dst_port: u16,
    src_addr_v6: Option<&[u32; 4]>,
    dst_addr_v6: Option<&[u32; 4]>,
    tcp_conn_info: &mut TcpConntrackInfo,
    do_auto_ttl: bool,
    ttl_min_hops: u8,
    auto_ttl_1: u8,
    auto_ttl_2: u8,
    auto_ttl_max: u8,
    do_tcp_verb: bool,
    w_filter: &str,
    addr: &str,
    packet: &[u8],
    packet_len: usize,
    ttl_of_fake_packet: u8,
    do_wrong_chksum: bool,
    do_wrong_seq: bool,
) where
    F: Fn(&str, &str, &[u8], usize, bool, u8, bool, bool),
{
    let mut should_send_fake = true;
    if do_auto_ttl || ttl_min_hops > 0 {
        if tcp_handle_outgoing_ttl_parse_packet_if(
            conntrack,
            packet_v4,
            packet_v6,
            src_addr_v4,
            dst_addr_v4,
            src_port,
            dst_port,
            src_addr_v6,
            dst_addr_v6,
            tcp_conn_info,
            do_auto_ttl,
            ttl_min_hops,
            auto_ttl_1,
            auto_ttl_2,
            auto_ttl_max,
            do_tcp_verb,
        ) {
            if do_auto_ttl {
                let ttl_of_fake_packet = tcp_get_auto_ttl(
                    tcp_conn_info.ttl,
                    auto_ttl_1,
                    auto_ttl_2,
                    ttl_min_hops,
                    auto_ttl_max,
                );
                if do_tcp_verb {
                    println!(
                        "Connection TTL = {}, Fake TTL = {}",
                        tcp_conn_info.ttl, ttl_of_fake_packet
                    );
                }
            } else if ttl_min_hops > 0 {
                if tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_hops, 0) == 0 {
                    should_send_fake = false;
                }
            }
        }
    }
    if should_send_fake {
        func(
            w_filter,
            addr,
            packet,
            packet_len,
            packet_v6,
            ttl_of_fake_packet,
            do_wrong_chksum,
            do_wrong_seq,
        );
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_tcp_conntrack() {
        let mut conntrack = TcpConntrack::new();
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];
        let src_port = 12345;
        let dst_port = 80;
        let is_ipv6 = 0;
        let ttl = 64;

        assert!(conntrack.add_tcp_conntrack(&src_ip, &dst_ip, src_port, dst_port, is_ipv6, ttl));
    }

    #[test]
    fn test_tcp_handle_incoming() {
        let mut conntrack = TcpConntrack::new();
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];
        let src_port = 12345;
        let dst_port = 80;
        let is_ipv6 = 0;
        let ttl = 64;

        assert!(conntrack.tcp_handle_incoming(src_ip, dst_ip, src_port, dst_port, is_ipv6, ttl));
    }

    #[test]
    fn test_tcp_handle_outgoing() {
        let mut conntrack = TcpConntrack::new();
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];
        let src_port = 12345;
        let dst_port = 80;
        let is_ipv6 = 0;
        let ttl = 64;

        conntrack.add_tcp_conntrack(&src_ip, &dst_ip, src_port, dst_port, is_ipv6, ttl);

        let mut conn_info = TcpConntrackInfo {
            is_ipv6,
            ttl,
            src_ip: [0; 4],
            src_port: 0,
            dst_ip: [0; 4],
            dst_port: 0,
        };

        assert!(conntrack.tcp_handle_outgoing(&dst_ip, &src_ip, dst_port, src_port, &mut conn_info, is_ipv6));
    }

    #[test]
    fn test_tcp_get_auto_ttl() {
        let ttl = 100;
        let auto_ttl_1 = 2;
        let auto_ttl_2 = 1;
        let min_hops = 1;
        let max_ttl = 64;

        let result = tcp_get_auto_ttl(ttl, auto_ttl_1, auto_ttl_2, min_hops, max_ttl);
        assert_eq!(result, 27);
    }

    #[test]
    fn test_set_http_fragment_size_option() {
        set_http_fragment_size_option(1500);
        unsafe {
            assert_eq!(HTTP_FRAGMENT_SIZE, Some(1500));
        }
    }
}

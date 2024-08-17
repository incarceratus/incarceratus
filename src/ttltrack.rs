/*
参考ttltrack 注释全部由copilot生成
 */
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// 常量定义
const TCP_CONNRECORD_KEY_LEN: usize = 37; // TCP连接记录键的长度
const TCP_CLEANUP_INTERVAL_SEC: u64 = 30; // 清理间隔时间（秒）

// TCP连接跟踪信息结构体
#[derive(Clone)]
pub struct TcpConntrackInfo {
    pub is_ipv6: u8, // 是否为IPv6
    pub ttl: u8, // 生存时间
    pub srcip: [u32; 4], // 源IP地址
    pub srcport: u16, // 源端口
    pub dstip: [u32; 4], // 目标IP地址
    pub dstport: u16, // 目标端口
}

// TCP连接记录结构体
#[derive(Clone)]
struct TcpConnrecord {
    key: [u8; TCP_CONNRECORD_KEY_LEN], // 连接键
    time: SystemTime, // 记录时间
    ttl: u16, // 生存时间
}

// TCP连接跟踪结构体
pub struct TcpConntrack {
    conntrack: HashMap<[u8; TCP_CONNRECORD_KEY_LEN], TcpConnrecord>, // 连接记录的哈希表
    last_cleanup: SystemTime, // 上次清理时间
}

impl TcpConntrack {
    // 创建新的TCP连接跟踪实例
    pub fn new() -> Self {
        Self {
            conntrack: HashMap::new(),
            last_cleanup: SystemTime::now(),
        }
    }

    // 填充键数据
    fn fill_key_data(
        key: &mut [u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: u8,
        srcip: &[u32; 4],
        dstip: &[u32; 4],
        srcport: u16,
        dstport: u16,
    ) {
        let mut offset = 0;

        // 设置IP版本
        key[offset] = if is_ipv6 != 0 { b'6' } else { b'4' };
        offset += 1;

        // 填充IP地址和端口
        if is_ipv6 != 0 {
            key[offset..offset + 16].copy_from_slice(&srcip.iter().flat_map(|&x| x.to_be_bytes()).collect::<Vec<_>>());
            offset += 16;
            key[offset..offset + 16].copy_from_slice(&dstip.iter().flat_map(|&x| x.to_be_bytes()).collect::<Vec<_>>());
            offset += 16;
        } else {
            key[offset..offset + 4].copy_from_slice(&srcip[0].to_be_bytes());
            offset += 4;
            key[offset..offset + 4].copy_from_slice(&dstip[0].to_be_bytes());
            offset += 4;
        }

        key[offset..offset + 2].copy_from_slice(&srcport.to_be_bytes());
        offset += 2;
        key[offset..offset + 2].copy_from_slice(&dstport.to_be_bytes());
    }

    // 从键中解析数据
    fn fill_data_from_key(
        key: &[u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: &mut u8,
        srcip: &mut [u32; 4],
        dstip: &mut [u32; 4],
        srcport: &mut u16,
        dstport: &mut u16,
    ) {
        let mut offset = 0;

        // 解析IP版本
        *is_ipv6 = if key[0] == b'6' { 1 } else { 0 };
        offset += 1;

        // 解析IP地址和端口
        if *is_ipv6 != 0 {
            for i in 0..4 {
                srcip[i] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
                offset += 4;
            }
            for i in 0..4 {
                dstip[i] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
                offset += 4;
            }
        } else {
            srcip[0] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
            offset += 4;
            dstip[0] = u32::from_be_bytes([key[offset], key[offset + 1], key[offset + 2], key[offset + 3]]);
            offset += 4;
        }

        *srcport = u16::from_be_bytes([key[offset], key[offset + 1]]);
        offset += 2;
        *dstport = u16::from_be_bytes([key[offset], key[offset + 1]]);
    }

    // 构造键
    fn construct_key(
        srcip: &[u32; 4],
        dstip: &[u32; 4],
        srcport: u16,
        dstport: u16,
        key: &mut [u8; TCP_CONNRECORD_KEY_LEN],
        is_ipv6: u8,
    ) {
        Self::fill_key_data(key, is_ipv6, srcip, dstip, srcport, dstport);
    }

    // 从键中解析连接记录并填充连接信息
    fn deconstruct_key(
        key: &[u8; TCP_CONNRECORD_KEY_LEN],
        connrecord: &TcpConnrecord,
        conn_info: &mut TcpConntrackInfo,
    ) {
        Self::fill_data_from_key(
            key,
            &mut conn_info.is_ipv6,
            &mut conn_info.srcip,
            &mut conn_info.dstip,
            &mut conn_info.srcport,
            &mut conn_info.dstport,
        );
        conn_info.ttl = connrecord.ttl as u8;
    }

    // 检查并获取TCP连接记录
    fn check_get_tcp_conntrack_key(&self, key: &[u8; TCP_CONNRECORD_KEY_LEN]) -> Option<&TcpConnrecord> {
        self.conntrack.get(key)
    }

    // 添加TCP连接记录
    fn add_tcp_conntrack(
        &mut self,
        srcip: &[u32; 4],
        dstip: &[u32; 4],
        srcport: u16,
        dstport: u16,
        is_ipv6: u8,
        ttl: u8,
    ) -> bool {
        // 检查IP地址和端口是否有效
        if srcip.iter().all(|&x| x == 0) || dstip.iter().all(|&x| x == 0) || srcport == 0 || dstport == 0 {
            return false;
        }

        let mut key = [0u8; TCP_CONNRECORD_KEY_LEN];
        Self::construct_key(srcip, dstip, srcport, dstport, &mut key, is_ipv6);

        // 如果记录不存在，则添加新记录
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

    // 清理过期连接记录
    fn tcp_cleanup(&mut self) {
        let now = SystemTime::now();
        if now.duration_since(self.last_cleanup).unwrap_or(Duration::new(0, 0)).as_secs() >= TCP_CLEANUP_INTERVAL_SEC {
            self.last_cleanup = now;
            self.conntrack.retain(|_, connrecord| {
                now.duration_since(connrecord.time).unwrap_or(Duration::new(0, 0)).as_secs() < TCP_CLEANUP_INTERVAL_SEC
            });
        }
    }

    // 处理传入连接
    pub fn tcp_handle_incoming(
        &mut self,
        srcip: [u32; 4],
        dstip: [u32; 4],
        srcport: u16,
        dstport: u16,
        is_ipv6: u8,
        ttl: u8,
    ) -> bool {
        self.tcp_cleanup();
        self.add_tcp_conntrack(&srcip, &dstip, srcport, dstport, is_ipv6, ttl)
    }

    // 处理传出连接
    pub fn tcp_handle_outgoing(
        &mut self,
        srcip: &[u32; 4],
        dstip: &[u32; 4],
        srcport: u16,
        dstport: u16,
        conn_info: &mut TcpConntrackInfo,
        is_ipv6: u8,
    ) -> bool {
        let mut key = [0u8; TCP_CONNRECORD_KEY_LEN];
        Self::construct_key(dstip, srcip, dstport, srcport, &mut key, is_ipv6);

        // 如果记录存在，则解析并移除记录
        if let Some(connrecord) = self.check_get_tcp_conntrack_key(&key) {
            Self::deconstruct_key(&key, connrecord, conn_info);
            self.conntrack.remove(&key);
            true
        } else {
            false
        }
    }
}

// 计算伪造包的TTL值
pub fn tcp_get_auto_ttl(
    ttl: u8,
    autottl1: u8,
    autottl2: u8,
    minhops: u8,
    maxttl: u8,
) -> u8 {
    let nhops = if ttl > 98 && ttl < 128 {
        128 - ttl
    } else if ttl > 34 && ttl < 64 {
        64 - ttl
    } else {
        return 0;
    };

    if nhops <= autottl1 || nhops < minhops {
        return 0;
    }

    let mut ttl_of_fake_packet = nhops - autottl2;
    if ttl_of_fake_packet < autottl2 && nhops <= 9 {
        ttl_of_fake_packet = nhops - autottl1 - ((autottl2 - autottl1) as f32 * (nhops as f32 / 10.0)).trunc() as u8;
    }

    if maxttl != 0 && ttl_of_fake_packet > maxttl {
        ttl_of_fake_packet = maxttl;
    }

    ttl_of_fake_packet
}

// 新增的宏转换为函数
static mut HTTP_FRAGMENT_SIZE: Option<u32> = None;

// 设置HTTP片段大小选项
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

// 处理传出连接并解析包
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
    ttl_min_nhops: u8,
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
                ttl_min_nhops,
                auto_ttl_max,
            );
            if do_tcp_verb {
                println!(
                    "Connection TTL = {}, Fake TTL = {}",
                    tcp_conn_info.ttl, ttl_of_fake_packet
                );
            }
        } else if ttl_min_nhops > 0 {
            if !tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0) {
                return false;
            }
        }
        true
    } else {
        false
    }
}

// 处理传出伪造包
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
    ttl_min_nhops: u8,
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
    if do_auto_ttl || ttl_min_nhops > 0 {
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
            ttl_min_nhops,
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
                    ttl_min_nhops,
                    auto_ttl_max,
                );
                if do_tcp_verb {
                    println!(
                        "Connection TTL = {}, Fake TTL = {}",
                        tcp_conn_info.ttl, ttl_of_fake_packet
                    );
                }
            } else if ttl_min_nhops > 0 {
                if !tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0) {
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
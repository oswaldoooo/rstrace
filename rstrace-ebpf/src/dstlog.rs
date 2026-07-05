use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_buf},
    macros::{kprobe, map},
    maps::{Array, HashMap},
    programs::ProbeContext,
};
use rstrace_common::{
    AF_INET, AF_INET6, CommFilter, DstKey, DstLogConfig, IPPROTO_TCP, IPPROTO_UDP,
    MAX_DST_ENTRIES, MSGHDR_MSG_NAME_OFFSET,
};

use crate::helpers::comm_matches;

#[map]
static DST_MAP_A: HashMap<DstKey, u64> = HashMap::with_max_entries(MAX_DST_ENTRIES, 0);

#[map]
static DST_MAP_B: HashMap<DstKey, u64> = HashMap::with_max_entries(MAX_DST_ENTRIES, 0);

/// 0 = ebpf writes DST_MAP_A, 1 = writes DST_MAP_B
#[map]
static ACTIVE_BUF: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static DSTLOG_COMM_FILTER: Array<CommFilter> = Array::with_max_entries(1, 0);

#[map]
static DSTLOG_CONFIG: Array<DstLogConfig> = Array::with_max_entries(1, 0);

#[kprobe(function = "tcp_connect")]
pub fn dstlog_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_dstlog_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_dstlog_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let cfg = DSTLOG_CONFIG.get(0).ok_or(0)?;
    if cfg.tcp_enabled == 0 {
        return Ok(0);
    }
    if !passes_comm_filter(&ctx)? {
        return Ok(0);
    }

    // tcp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    let uaddr: *const u8 = ctx.arg(1).ok_or(0)?;
    if uaddr.is_null() {
        return Ok(0);
    }

    if let Some(key) = parse_sockaddr(uaddr, IPPROTO_TCP)? {
        if is_external(&key) {
            record_dst(key)?;
        }
    }
    Ok(0)
}

#[kprobe(function = "udp_sendmsg")]
pub fn dstlog_udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_dstlog_udp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_dstlog_udp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let cfg = DSTLOG_CONFIG.get(0).ok_or(0)?;
    if cfg.udp_enabled == 0 {
        return Ok(0);
    }
    if !passes_comm_filter(&ctx)? {
        return Ok(0);
    }

    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    let msg: *const u8 = ctx.arg(1).ok_or(0)?;
    if msg.is_null() {
        return Ok(0);
    }

    let name_ptr_addr = unsafe { msg.add(MSGHDR_MSG_NAME_OFFSET) as *const *const u8 };
    let name: *const u8 = unsafe { bpf_probe_read_kernel(name_ptr_addr).map_err(|e| e as i64)? };
    if name.is_null() {
        return Ok(0);
    }

    if let Some(key) = parse_sockaddr(name, IPPROTO_UDP)? {
        if is_external(&key) {
            record_dst(key)?;
        }
    }
    Ok(0)
}

fn passes_comm_filter(ctx: &ProbeContext) -> Result<bool, i64> {
    let filter = DSTLOG_COMM_FILTER.get(0).ok_or(0)?;
    if filter.enabled == 0 {
        return Ok(false);
    }
    let comm = ctx.command().map_err(|_| 0)?;
    Ok(comm_matches(&filter.comm, &comm))
}

fn parse_sockaddr(sa: *const u8, proto: u8) -> Result<Option<DstKey>, i64> {
    let family: u16 = unsafe {
        bpf_probe_read_kernel(sa as *const u16).map_err(|e| e as i64)?
    };

    match family as u8 {
        AF_INET => parse_sockaddr_in(sa, proto),
        AF_INET6 => parse_sockaddr_in6(sa, proto),
        _ => Ok(None),
    }
}

fn parse_sockaddr_in(sa: *const u8, proto: u8) -> Result<Option<DstKey>, i64> {
    let mut addr = [0u8; 4];
    unsafe {
        bpf_probe_read_kernel_buf(sa.add(4), &mut addr).map_err(|e| e as i64)?;
    }
    let mut key_addr = [0u8; 16];
    key_addr[..4].copy_from_slice(&addr);
    Ok(Some(DstKey {
        addr: key_addr,
        family: AF_INET,
        proto,
        _pad: [0; 2],
    }))
}

fn parse_sockaddr_in6(sa: *const u8, proto: u8) -> Result<Option<DstKey>, i64> {
    let mut addr = [0u8; 16];
    unsafe {
        bpf_probe_read_kernel_buf(sa.add(8), &mut addr).map_err(|e| e as i64)?;
    }
    Ok(Some(DstKey {
        addr,
        family: AF_INET6,
        proto,
        _pad: [0; 2],
    }))
}

fn is_external(key: &DstKey) -> bool {
    match key.family {
        AF_INET => is_external_v4(&key.addr[..4]),
        AF_INET6 => is_external_v6(&key.addr),
        _ => false,
    }
}

fn is_external_v4(octets: &[u8]) -> bool {
    let [a, b, c, d] = [octets[0], octets[1], octets[2], octets[3]];
    if a == 0 {
        return false;
    }
    if a == 10 {
        return false;
    }
    if a == 127 {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    // CGNAT 100.64.0.0/10
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    !(a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_external_v6(addr: &[u8; 16]) -> bool {
    if addr == &[0u8; 16] {
        return false;
    }
    if addr == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return false;
    }
    if addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80 {
        return false;
    }
    if (addr[0] & 0xfe) == 0xfc {
        return false;
    }
    if addr[0] == 0xff {
        return false;
    }
    true
}

fn record_dst(key: DstKey) -> Result<(), i64> {
    let active = ACTIVE_BUF.get(0).ok_or(0)?;
    if *active == 0 {
        incr_dst(&DST_MAP_A, key)
    } else {
        incr_dst(&DST_MAP_B, key)
    }
}

fn incr_dst(map: &HashMap<DstKey, u64>, key: DstKey) -> Result<(), i64> {
    if let Some(count) = map.get_ptr_mut(&key) {
        unsafe {
            *count += 1;
        }
    } else {
        let one = 1u64;
        map.insert(&key, &one, 0)?;
    }
    Ok(())
}

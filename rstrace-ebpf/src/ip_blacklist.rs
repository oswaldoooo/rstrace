use core::mem::size_of;

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie},
    programs::XdpContext,
};
use rstrace_common::{
    IpBlacklistConfig, IPPROTO_TCP, IPPROTO_UDP, MAX_BLACKLIST_RANGES, MAX_DST_ENTRIES,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_8021Q: u16 = 0x8100;
const IPV4_HDR_LEN: usize = 20;

#[map]
static BLACKLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(MAX_BLACKLIST_RANGES, 0);

#[map]
static BLACKLIST_HITS: Array<u64> = Array::with_max_entries(MAX_BLACKLIST_RANGES, 0);

#[map]
static DRY_RUN: Array<u8> = Array::with_max_entries(1, 0);

#[map]
static DRY_RUN_MAP_A: HashMap<u32, u64> = HashMap::with_max_entries(MAX_DST_ENTRIES, 0);

#[map]
static DRY_RUN_MAP_B: HashMap<u32, u64> = HashMap::with_max_entries(MAX_DST_ENTRIES, 0);

/// 0 = ebpf writes DRY_RUN_MAP_A, 1 = writes DRY_RUN_MAP_B
#[map]
static DRY_RUN_ACTIVE_BUF: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static BLACKLIST_CONFIG: Array<IpBlacklistConfig> = Array::with_max_entries(1, 0);

/// Blacklist IPs allowed through because the UDP payload looks like a STUN Binding Request.
#[map]
static STUN_PASS_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_DST_ENTRIES, 0);

const STUN_HDR_LEN: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_INDICATION: u16 = 0x0011;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_BINDING_ERROR: u16 = 0x0111;
const STUN_PORT: u16 = 3478;

#[xdp]
pub fn ip_blacklist(ctx: XdpContext) -> u32 {
    match try_ip_blacklist(ctx) {
        Ok(action) => action,
        Err(_) => XDP_PASS,
    }
}

fn try_ip_blacklist(ctx: XdpContext) -> Result<u32, i32> {
    let ip_off = ipv4_offset(&ctx)?;
    let src = read_be_u32_at(&ctx, ip_off + 12)?;
    let dst = read_be_u32_at(&ctx, ip_off + 16)?;
    let proto = read_u8_at(&ctx, ip_off + 9)?;

    if !protocol_enabled(proto) {
        return Ok(XDP_PASS);
    }

    let src_hit = ip_blocked(src);
    let dst_hit = ip_blocked(dst);

    if dry_run_enabled() {
        if src_hit {
            record_dry_run_ip(src)?;
        }
        if dst_hit && dst != src {
            record_dry_run_ip(dst)?;
        }
        return Ok(XDP_PASS);
    }

    if src_hit || dst_hit {
        if proto == IPPROTO_UDP && is_stun_message(&ctx, ip_off)? {
            if src_hit {
                record_stun_pass(src)?;
            }
            if dst_hit && dst != src {
                record_stun_pass(dst)?;
            }
            return Ok(XDP_PASS);
        }
        if src_hit {
            bump_hit_ip(src);
        }
        if dst_hit && dst != src {
            bump_hit_ip(dst);
        }
        return Ok(XDP_DROP);
    }
    Ok(XDP_PASS)
}

fn dry_run_enabled() -> bool {
    match DRY_RUN.get(0) {
        Some(v) => *v != 0,
        None => false,
    }
}

#[inline(always)]
fn protocol_enabled(proto: u8) -> bool {
    let Some(cfg) = BLACKLIST_CONFIG.get(0) else {
        return false;
    };
    match proto {
        IPPROTO_TCP => cfg.tcp_enabled != 0,
        IPPROTO_UDP => cfg.udp_enabled != 0,
        _ => false,
    }
}

#[inline(always)]
fn ip_blocked(ip: u32) -> bool {
    BLACKLIST.get(&Key::new(32, lpm_ip_word(ip))).is_some()
}

#[inline(always)]
fn bump_hit_ip(ip: u32) {
    if let Some(idx) = BLACKLIST.get(&Key::new(32, lpm_ip_word(ip))).copied() {
        bump_hit(idx);
    }
}

fn record_dry_run_ip(ip: u32) -> Result<(), i32> {
    let active = DRY_RUN_ACTIVE_BUF.get(0).ok_or(0)?;
    if *active == 0 {
        incr_ip(&DRY_RUN_MAP_A, ip)
    } else {
        incr_ip(&DRY_RUN_MAP_B, ip)
    }
}

fn incr_ip(map: &HashMap<u32, u64>, ip: u32) -> Result<(), i32> {
    if let Some(count) = map.get_ptr_mut(&ip) {
        unsafe {
            *count += 1;
        }
    } else {
        let one = 1u64;
        map.insert(&ip, &one, 0)?;
    }
    Ok(())
}

fn record_stun_pass(ip: u32) -> Result<(), i32> {
    incr_ip(&STUN_PASS_COUNTS, ip)
}

fn is_stun_binding_msg_type(msg_type: u16) -> bool {
    msg_type == STUN_BINDING_REQUEST
        || msg_type == STUN_BINDING_INDICATION
        || msg_type == STUN_BINDING_SUCCESS
        || msg_type == STUN_BINDING_ERROR
}

fn is_stun_message(ctx: &XdpContext, ip_off: usize) -> Result<bool, i32> {
    let ihl = (read_u8_at(ctx, ip_off)? & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_LEN {
        return Ok(false);
    }

    let udp_off = ip_off + ihl;
    if udp_off + 8 > ctx.data_end() {
        return Ok(false);
    }

    let udp_len = read_be_u16_at(ctx, udp_off + 4)? as usize;
    if udp_len < 8 {
        return Ok(false);
    }

    let payload_off = udp_off + 8;
    let payload_len = udp_len - 8;
    if payload_len < STUN_HDR_LEN || payload_off + payload_len > ctx.data_end() {
        return Ok(false);
    }

    let msg_type = read_be_u16_at(ctx, payload_off)?;
    if !is_stun_binding_msg_type(msg_type) {
        return Ok(false);
    }

    let msg_len = read_be_u16_at(ctx, payload_off + 2)? as usize;
    if msg_len > payload_len - STUN_HDR_LEN {
        return Ok(false);
    }

    let cookie = read_be_u32_at(ctx, payload_off + 4)?;
    if cookie == STUN_MAGIC_COOKIE {
        return Ok(true);
    }

    // RFC 3489: no magic cookie; require the well-known STUN port on either side.
    let src_port = read_be_u16_at(ctx, udp_off)?;
    let dst_port = read_be_u16_at(ctx, udp_off + 2)?;
    if (src_port == STUN_PORT || dst_port == STUN_PORT) && msg_len <= 256 {
        return Ok(true);
    }

    Ok(false)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(0);
    }

    Ok((start + offset) as *const T)
}

fn ipv4_offset(ctx: &XdpContext) -> Result<usize, i32> {
    if ctx.data() + ETH_HDR_LEN > ctx.data_end() {
        return Err(0);
    }

    let mut ethertype = read_be_u16_at(ctx, 12)?;
    let mut ip_off = ETH_HDR_LEN;
    if ethertype == ETH_P_8021Q {
        ip_off += 4;
        if ctx.data() + ip_off > ctx.data_end() {
            return Err(0);
        }
        ethertype = read_be_u16_at(ctx, ip_off - 2)?;
    }
    if ethertype != ETH_P_IP {
        return Err(0);
    }
    if ctx.data() + ip_off + IPV4_HDR_LEN > ctx.data_end() {
        return Err(0);
    }
    Ok(ip_off)
}

fn read_be_u16_at(ctx: &XdpContext, offset: usize) -> Result<u16, i32> {
    Ok(u16::from_be_bytes([
        unsafe { *ptr_at(ctx, offset)? },
        unsafe { *ptr_at(ctx, offset + 1)? },
    ]))
}

fn read_be_u32_at(ctx: &XdpContext, offset: usize) -> Result<u32, i32> {
    Ok(u32::from_be_bytes([
        unsafe { *ptr_at(ctx, offset)? },
        unsafe { *ptr_at(ctx, offset + 1)? },
        unsafe { *ptr_at(ctx, offset + 2)? },
        unsafe { *ptr_at(ctx, offset + 3)? },
    ]))
}

fn read_u8_at(ctx: &XdpContext, offset: usize) -> Result<u8, i32> {
    Ok(unsafe { *ptr_at(ctx, offset)? })
}

fn bump_hit(index: u32) {
    if let Some(count) = BLACKLIST_HITS.get_ptr_mut(index) {
        unsafe {
            *count += 1;
        }
    }
}

fn lpm_ip_word(ip: u32) -> u32 {
    ip.to_be()
}

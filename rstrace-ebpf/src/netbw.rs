use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::{Array, HashMap},
    programs::ProbeContext,
};
use rstrace_common::{CommFilter, MAX_PIDS, SKB_LEN_OFFSET};

use crate::helpers::{add_tx_bytes, comm_matches};

#[map]
static TCP_TX_BYTES: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PIDS, 0);

#[map]
static UDP_TX_BYTES: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PIDS, 0);

#[map]
static NETBW_COMM_FILTER: Array<CommFilter> = Array::with_max_entries(1, 0);

#[kprobe(function = "tcp_write_xmit")]
pub fn tcp_write_xmit(ctx: ProbeContext) -> u32 {
    match try_tcp_write_xmit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tcp_write_xmit(ctx: ProbeContext) -> Result<u32, i64> {
    if !passes_comm_filter(&ctx)? {
        return Ok(0);
    }

    let skb: *const u8 = ctx.arg(1).ok_or(0)?;
    if skb.is_null() {
        return Ok(0);
    }

    let len = read_skb_len(skb)?;
    if len == 0 {
        return Ok(0);
    }

    let pid = ctx.tgid();
    add_tx_bytes(&TCP_TX_BYTES, pid, len as u64)?;
    Ok(0)
}

#[kprobe(function = "udp_sendmsg")]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_udp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    if !passes_comm_filter(&ctx)? {
        return Ok(0);
    }

    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    let len: u64 = ctx.arg(2).ok_or(0)?;
    if len == 0 {
        return Ok(0);
    }

    let pid = ctx.tgid();
    add_tx_bytes(&UDP_TX_BYTES, pid, len)?;
    Ok(0)
}

fn passes_comm_filter(ctx: &ProbeContext) -> Result<bool, i64> {
    let filter = NETBW_COMM_FILTER.get(0).ok_or(0)?;
    if filter.enabled == 0 {
        return Ok(true);
    }
    let comm = ctx.command().map_err(|_| 0)?;
    Ok(comm_matches(&filter.comm, &comm))
}

fn read_skb_len(skb: *const u8) -> Result<u32, i64> {
    let len_ptr = unsafe { skb.add(SKB_LEN_OFFSET) as *const u32 };
    unsafe { bpf_probe_read_kernel(len_ptr) }.map_err(|e| e as i64)
}

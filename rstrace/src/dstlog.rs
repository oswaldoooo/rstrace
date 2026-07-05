use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use aya::{
    maps::{Array, HashMap},
    programs::KProbe,
    Ebpf,
};
use rstrace_common::{CommFilter, DstKey, DstLogConfig};
use tokio::signal;

use crate::util::build_comm_filter;

pub async fn run(args: super::DstLogArgs) -> anyhow::Result<()> {
    if !args.tcp && !args.udp {
        bail!("at least one of -t (TCP) or -u (UDP) must be specified");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rstrace"
    )))?;

    if args.tcp {
        let program: &mut KProbe = ebpf
            .program_mut("dstlog_tcp_connect")
            .context("dstlog_tcp_connect program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp_connect", 0)?;
        log::info!("attached kprobe: tcp_connect");
    }

    if args.udp {
        let program: &mut KProbe = ebpf
            .program_mut("dstlog_udp_sendmsg")
            .context("dstlog_udp_sendmsg program not found")?
            .try_into()?;
        program.load()?;
        program.attach("udp_sendmsg", 0)?;
        log::info!("attached kprobe: udp_sendmsg");
    }

    let filter = build_comm_filter(&args.comm)?;
    let mut comm_filter: Array<_, CommFilter> =
        Array::try_from(ebpf.map_mut("DSTLOG_COMM_FILTER").unwrap())?;
    comm_filter.set(0, filter, 0)?;

    let config = DstLogConfig {
        tcp_enabled: u8::from(args.tcp),
        udp_enabled: u8::from(args.udp),
    };
    let mut cfg_map: Array<_, DstLogConfig> =
        Array::try_from(ebpf.map_mut("DSTLOG_CONFIG").unwrap())?;
    cfg_map.set(0, config, 0)?;

    let mut write_buf: u32 = 0;
    {
        let mut active_buf: Array<_, u32> = Array::try_from(ebpf.map_mut("ACTIVE_BUF").unwrap())?;
        active_buf.set(0, write_buf, 0)?;
    }

    log::info!(
        "dstlog watching comm={} (sync every {}s); press Ctrl+C to stop",
        args.comm,
        args.duration
    );

    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let drain_buf = write_buf;
                write_buf = 1 - write_buf;
                {
                    let mut active_buf: Array<_, u32> =
                        Array::try_from(ebpf.map_mut("ACTIVE_BUF").unwrap())?;
                    active_buf.set(0, write_buf, 0)?;
                }

                let map_name = if drain_buf == 0 { "DST_MAP_A" } else { "DST_MAP_B" };
                drain_and_print(ebpf.map_mut(map_name).unwrap())?;
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    Ok(())
}

fn drain_and_print(map: &mut aya::maps::Map) -> anyhow::Result<()> {
    let mut hash = HashMap::<_, DstKey, u64>::try_from(map)?;
    let entries: Vec<(DstKey, u64)> = hash
        .iter()
        .map(|item| item.map(|(k, v)| (k, v)))
        .collect::<Result<_, _>>()?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    for (key, count) in &entries {
        if let Some(ip) = format_dst_key(key) {
            println!("{ip} {ts} {count}");
        }
    }

    for (key, _) in entries {
        hash.remove(&key)?;
    }
    Ok(())
}

fn format_dst_key(key: &DstKey) -> Option<String> {
    match key.family {
        rstrace_common::AF_INET => {
            let ip = Ipv4Addr::new(key.addr[0], key.addr[1], key.addr[2], key.addr[3]);
            Some(ip.to_string())
        }
        rstrace_common::AF_INET6 => {
            let ip = Ipv6Addr::from(key.addr);
            Some(ip.to_string())
        }
        _ => None,
    }
}

use std::collections::HashMap as StdHashMap;
use std::fmt::Write as _;
use std::fs;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use aya::{
    maps::{Array, HashMap},
    programs::KProbe,
};
use serde::Serialize;
use tokio::signal;

use crate::util::{build_comm_filter, format_bandwidth, format_bytes};
use crate::NetBwSortKey;

pub async fn run(args: super::NetBwCollectArgs) -> anyhow::Result<()> {
    if !args.tcp && !args.udp {
        bail!("at least one of -t (TCP) or -u (UDP) must be specified");
    }

    if let Some(NetBwSortKey::Tcp) = args.sort {
        if !args.tcp {
            bail!("--sort tcp requires -t");
        }
    }
    if let Some(NetBwSortKey::Udp) = args.sort {
        if !args.udp {
            bail!("--sort udp requires -u");
        }
    }

    let mut ebpf = crate::util::load_ebpf()?;

    if args.tcp {
        let program: &mut KProbe = ebpf
            .program_mut("tcp_write_xmit")
            .context("tcp_write_xmit program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp_write_xmit", 0)?;
        if !args.json {
            log::info!("attached kprobe: tcp_write_xmit");
        }
    }

    if args.udp {
        let program: &mut KProbe = ebpf
            .program_mut("udp_sendmsg")
            .context("udp_sendmsg program not found")?
            .try_into()?;
        program.load()?;
        program.attach("udp_sendmsg", 0)?;
        if !args.json {
            log::info!("attached kprobe: udp_sendmsg");
        }
    }

    if let Some(comm) = &args.comm {
        let filter = build_comm_filter(comm)?;
        let mut comm_filter: Array<_, rstrace_common::CommFilter> =
            Array::try_from(ebpf.map_mut("NETBW_COMM_FILTER").unwrap())?;
        comm_filter.set(0, filter, 0)?;
        if !args.json {
            log::info!("filtering by comm: {}", comm);
        }
    } else if !args.json {
        log::info!("collecting network bandwidth from all processes");
    }

    if !args.json {
        log::info!(
            "netbw-collect running (sync every {}s); press Ctrl+C to stop",
            args.duration
        );
    }

    let started_at = Instant::now();
    let interval = Duration::from_secs(args.duration);
    let opts = RenderOpts {
        duration_secs: args.duration as f64,
        collect_tcp: args.tcp,
        collect_udp: args.udp,
        cumulative: args.sum,
        sort: args.sort,
        json: args.json,
    };
    let output_path = args.output;
    let comm = args.comm.as_ref().map(|v| v.as_str());
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let tcp = if opts.collect_tcp {
                    read_bytes_map(&mut ebpf.map_mut("TCP_TX_BYTES").unwrap())?
                } else {
                    StdHashMap::new()
                };
                let udp = if opts.collect_udp {
                    read_bytes_map(&mut ebpf.map_mut("UDP_TX_BYTES").unwrap())?
                } else {
                    StdHashMap::new()
                };
                emit_stats(&tcp, &udp, &opts, started_at.elapsed(), output_path.as_deref(), comm)?;
                if !opts.cumulative {
                    if opts.collect_tcp {
                        clear_bytes_map(&mut ebpf.map_mut("TCP_TX_BYTES").unwrap())?;
                    }
                    if opts.collect_udp {
                        clear_bytes_map(&mut ebpf.map_mut("UDP_TX_BYTES").unwrap())?;
                    }
                }
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    Ok(())
}

struct RenderOpts {
    duration_secs: f64,
    collect_tcp: bool,
    collect_udp: bool,
    cumulative: bool,
    sort: Option<NetBwSortKey>,
    json: bool,
}

#[derive(Serialize)]
struct NetBwReport {
    duration: u64,
    elapsed_secs: f64,
    cumulative: bool,
    entries: Vec<NetBwEntry>,
}

#[derive(Serialize)]
struct NetBwEntry {
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_bps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_bps: Option<f64>,
}

fn read_bytes_map(map: &mut aya::maps::Map) -> anyhow::Result<StdHashMap<u32, u64>> {
    let hash = HashMap::<_, u32, u64>::try_from(map)?;
    let mut out = StdHashMap::new();
    for item in hash.iter() {
        let (pid, bytes) = item?;
        out.insert(pid, bytes);
    }
    Ok(out)
}

fn clear_bytes_map(map: &mut aya::maps::Map) -> anyhow::Result<()> {
    let mut hash = HashMap::<_, u32, u64>::try_from(map)?;
    let keys: Vec<u32> = hash
        .iter()
        .map(|item| item.map(|(k, _)| k))
        .collect::<Result<_, _>>()?;
    for key in keys {
        hash.remove(&key)?;
    }
    Ok(())
}

fn emit_stats(
    tcp: &StdHashMap<u32, u64>,
    udp: &StdHashMap<u32, u64>,
    opts: &RenderOpts,
    elapsed: Duration,
    output_path: Option<&std::path::Path>,
    comm: Option<&str>,
) -> anyhow::Result<()> {
    let text = if opts.json {
        format_stats_json(tcp, udp, opts, elapsed, comm)?
    } else {
        format_stats_text(tcp, udp, opts, elapsed, comm)?
    };

    print!("{text}");
    if let Some(path) = output_path {
        fs::write(path, &text)
            .with_context(|| format!("failed to write output file {}", path.display()))?;
    }
    Ok(())
}

fn collect_pids(
    tcp: &StdHashMap<u32, u64>,
    udp: &StdHashMap<u32, u64>,
    comm: Option<&str>,
) -> Vec<u32> {
    let mut pids: Vec<u32> = tcp.keys().chain(udp.keys()).copied().collect();
    pids.sort_unstable();
    pids.dedup();

    if let Some(comm) = comm {
        pids.retain(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .is_some_and(|s| s.trim() == comm)
        });
    }

    pids.retain(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
    pids
}

fn format_stats_json(
    tcp: &StdHashMap<u32, u64>,
    udp: &StdHashMap<u32, u64>,
    opts: &RenderOpts,
    elapsed: Duration,
    comm: Option<&str>,
) -> anyhow::Result<String> {
    let mut pids = collect_pids(tcp, udp, comm);
    sort_pids(&mut pids, tcp, udp, opts.sort);

    let entries: Vec<NetBwEntry> = pids
        .into_iter()
        .map(|pid| {
            let tcp_bytes = opts
                .collect_tcp
                .then(|| tcp.get(&pid).copied().unwrap_or(0));
            let udp_bytes = opts
                .collect_udp
                .then(|| udp.get(&pid).copied().unwrap_or(0));
            let tcp_bps = (!opts.cumulative && opts.collect_tcp).then(|| {
                tcp.get(&pid).copied().unwrap_or(0) as f64 / opts.duration_secs
            });
            let udp_bps = (!opts.cumulative && opts.collect_udp).then(|| {
                udp.get(&pid).copied().unwrap_or(0) as f64 / opts.duration_secs
            });
            NetBwEntry {
                pid,
                tcp_bytes,
                udp_bytes,
                tcp_bps,
                udp_bps,
            }
        })
        .collect();

    let report = NetBwReport {
        duration: opts.duration_secs as u64,
        elapsed_secs: elapsed.as_secs_f64(),
        cumulative: opts.cumulative,
        entries,
    };
    Ok(format!("{}\n", serde_json::to_string(&report)?))
}

fn format_stats_text(
    tcp: &StdHashMap<u32, u64>,
    udp: &StdHashMap<u32, u64>,
    opts: &RenderOpts,
    elapsed: Duration,
    comm: Option<&str>,
) -> anyhow::Result<String> {
    let mut pids = collect_pids(tcp, udp, comm);

    let mut out = String::new();

    if pids.is_empty() {
        if opts.cumulative {
            writeln!(out, "--- no outbound traffic since start ---")?;
        } else {
            writeln!(out, "--- no outbound traffic in interval ---")?;
        }
        return Ok(out);
    }

    sort_pids(&mut pids, tcp, udp, opts.sort);

    if opts.cumulative {
        writeln!(
            out,
            "--- net traffic total (since start, {:.0}s) ---",
            elapsed.as_secs_f64()
        )?;
    } else {
        writeln!(
            out,
            "--- net bandwidth (interval: {:.0}s) ---",
            opts.duration_secs
        )?;
    }
    writeln!(out, "{:<10} {:>16} {:>16}", "PID", "TCP TX", "UDP TX")?;

    for pid in pids {
        let tcp_str = format_tcp_value(tcp.get(&pid).copied().unwrap_or(0), opts);
        let udp_str = format_udp_value(udp.get(&pid).copied().unwrap_or(0), opts);
        writeln!(out, "{:<10} {:>16} {:>16}", pid, tcp_str, udp_str)?;
    }
    writeln!(out)?;

    Ok(out)
}

fn sort_pids(
    pids: &mut [u32],
    tcp: &StdHashMap<u32, u64>,
    udp: &StdHashMap<u32, u64>,
    sort: Option<NetBwSortKey>,
) {
    match sort {
        Some(NetBwSortKey::Tcp) => {
            pids.sort_by(|a, b| {
                tcp.get(b)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&tcp.get(a).copied().unwrap_or(0))
            });
        }
        Some(NetBwSortKey::Udp) => {
            pids.sort_by(|a, b| {
                udp.get(b)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&udp.get(a).copied().unwrap_or(0))
            });
        }
        None => {}
    }
}

fn format_tcp_value(bytes: u64, opts: &RenderOpts) -> String {
    if !opts.collect_tcp {
        return "-".to_string();
    }
    if opts.cumulative {
        format_bytes(bytes)
    } else {
        format_bandwidth(bytes as f64 / opts.duration_secs)
    }
}

fn format_udp_value(bytes: u64, opts: &RenderOpts) -> String {
    if !opts.collect_udp {
        return "-".to_string();
    }
    if opts.cumulative {
        format_bytes(bytes)
    } else {
        format_bandwidth(bytes as f64 / opts.duration_secs)
    }
}

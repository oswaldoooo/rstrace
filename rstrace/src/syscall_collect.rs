use std::time::Duration;

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap},
    programs::RawTracePoint,
    Ebpf,
};
use serde::Serialize;
use tokio::signal;

use crate::util::build_comm_filter;

use super::syscall_names;

pub async fn run(args: super::SyscallCollectArgs) -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rstrace"
    )))?;

    let program: &mut RawTracePoint = ebpf
        .program_mut("syscall_collect")
        .context("syscall_collect program not found")?
        .try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    if let Some(comm) = &args.comm {
        let filter = build_comm_filter(comm)?;
        let mut comm_filter: Array<_, rstrace_common::CommFilter> =
            Array::try_from(ebpf.map_mut("COMM_FILTER").unwrap())?;
        comm_filter.set(0, filter, 0)?;
        if !args.json {
            log::info!("filtering by comm: {}", comm);
        }
    } else if !args.json {
        log::info!("collecting syscalls from all processes");
    }

    if !args.json {
        log::info!(
            "syscall-collect running (sync every {}s); press Ctrl+C to stop",
            args.duration
        );
    }

    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let mut map = HashMap::<_, u32, u64>::try_from(
                    ebpf.map_mut("SYSCALL_COUNTS").unwrap(),
                )?;
                emit_stats(&mut map, args.duration, args.json)?;
                clear_map(&mut map)?;
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct SyscallReport {
    duration: u64,
    total: u64,
    entries: Vec<SyscallEntry>,
}

#[derive(Serialize)]
struct SyscallEntry {
    syscall_id: u32,
    name: String,
    count: u64,
    ratio: f64,
}

fn emit_stats(
    map: &mut HashMap<&mut aya::maps::MapData, u32, u64>,
    duration: u64,
    json: bool,
) -> anyhow::Result<()> {
    let mut entries: Vec<(u32, u64)> = Vec::new();
    for item in map.iter() {
        let (key, value) = item?;
        entries.push((key, value));
    }

    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let total: u64 = entries.iter().map(|(_, c)| c).sum();

    if json {
        let report = SyscallReport {
            duration,
            total,
            entries: entries
                .into_iter()
                .map(|(id, count)| {
                    let name = syscall_names::syscall_name(id);
                    let name = if name == "unknown" {
                        format!("sys_{id}")
                    } else {
                        name.to_string()
                    };
                    let ratio = if total == 0 {
                        0.0
                    } else {
                        count as f64 / total as f64
                    };
                    SyscallEntry {
                        syscall_id: id,
                        name,
                        count,
                        ratio,
                    }
                })
                .collect(),
        };
        println!("{}\n", serde_json::to_string(&report)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("--- no syscalls in interval ---");
        return Ok(());
    }

    println!("--- syscall stats (total: {}) ---", total);
    println!("{:<24} {:>12} {:>8}", "syscall", "count", "ratio");
    for (id, count) in entries {
        let name = syscall_names::syscall_name(id);
        let ratio = (count as f64 / total as f64) * 100.0;
        if name == "unknown" {
            println!("{:<24} {:>12} {:>7.2}%", format!("sys_{}", id), count, ratio);
        } else {
            println!("{:<24} {:>12} {:>7.2}%", name, count, ratio);
        }
    }
    println!();
    Ok(())
}

fn clear_map(map: &mut HashMap<&mut aya::maps::MapData, u32, u64>) -> anyhow::Result<()> {
    let keys: Vec<u32> = map.iter().map(|item| item.map(|(k, _)| k)).collect::<Result<_, _>>()?;
    for key in keys {
        map.remove(&key)?;
    }
    Ok(())
}

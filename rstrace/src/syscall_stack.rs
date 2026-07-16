use std::io::{self, Write as _};
use std::ops::Range;
use std::time::Duration;

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, StackTraceMap},
    programs::RawTracePoint,
};
use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
use rstrace_common::StackCount;
use tokio::signal;

use crate::util::build_comm_filter;

use super::syscall_names;

pub async fn run(args: super::SyscallStackArgs) -> anyhow::Result<()> {
    let syscall_id = syscall_names::syscall_id(&args.syscall).with_context(|| {
        format!(
            "unknown syscall {:?}; use a Linux x86_64 syscall name (e.g. clock_gettime, futex)",
            args.syscall
        )
    })?;

    let mut ebpf = crate::util::load_ebpf()?;

    let program: &mut RawTracePoint = ebpf
        .program_mut("syscall_stack")
        .context("syscall_stack program not found")?
        .try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    let filter = build_comm_filter(&args.comm)?;
    let mut comm_filter: Array<_, rstrace_common::CommFilter> =
        Array::try_from(ebpf.map_mut("STACK_COMM_FILTER").unwrap())?;
    comm_filter.set(0, filter, 0)?;

    let mut target: Array<_, u32> = Array::try_from(ebpf.map_mut("TARGET_SYSCALL").unwrap())?;
    target.set(0, syscall_id, 0)?;

    log::info!(
        "syscall-stack watching comm={} syscall={} (id={}); interval {}s; Ctrl+C to stop",
        args.comm,
        args.syscall,
        syscall_id,
        args.duration
    );

    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                match emit_stats(&mut ebpf, &args.syscall, &args.comm) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::BrokenPipe => break,
                    Err(err) => return Err(err.into()),
                }
                clear_counts(&mut ebpf)?;
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    Ok(())
}

fn emit_stats(
    ebpf: &mut aya::Ebpf,
    syscall: &str,
    comm: &str,
) -> io::Result<()> {
    let entries: Vec<(u32, StackCount)> = {
        let counts: HashMap<_, u32, StackCount> =
            HashMap::try_from(ebpf.map_mut("STACK_COUNTS").unwrap())
                .expect("STACK_COUNTS map");
        let mut v: Vec<(u32, StackCount)> = counts
            .iter()
            .map(|item| item.map(|(k, sample)| (k, sample)))
            .collect::<Result<_, _>>()
            .expect("STACK_COUNTS iteration");
        v.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        v
    };
    let stacks = StackTraceMap::try_from(ebpf.map("STACK_TRACES").unwrap())
        .expect("STACK_TRACES map");

    let total: u64 = entries.iter().map(|(_, sample)| sample.count).sum();
    if entries.is_empty() {
        return writeln!(
            io::stdout(),
            "--- no {syscall} stacks for comm={comm} in interval ---"
        );
    }

    let symbolizer = Symbolizer::new();
    let mut range_cache = RangeCache::default();

    writeln!(
        io::stdout(),
        "--- {syscall} stacks (comm={comm}, total hits: {total}) ---"
    )?;
    writeln!(io::stdout(), "{:<8} {:>8}  stack", "ratio", "count")?;

    for (stack_id, sample) in entries {
        let ratio = sample.count as f64 / total as f64 * 100.0;
        let stack = format_stack(
            &stacks,
            &symbolizer,
            &mut range_cache,
            sample.pid,
            stack_id,
        );
        writeln!(
            io::stdout(),
            "{ratio:>6.2}% {:>8}  {stack}",
            sample.count
        )?;
    }
    writeln!(io::stdout())?;
    Ok(())
}

fn format_stack(
    stacks: &StackTraceMap<&aya::maps::MapData>,
    symbolizer: &Symbolizer,
    range_cache: &mut RangeCache,
    pid: u32,
    stack_id: u32,
) -> String {
    let Ok(trace) = stacks.get(&stack_id, 0) else {
        return format!("<missing stack_id {stack_id}>");
    };

    let mut frames: Vec<u64> = trace
        .frames()
        .iter()
        .map(|f| f.ip)
        .filter(|ip| *ip != 0)
        .collect();
    if frames.is_empty() {
        return "<empty stack>".to_string();
    }
    frames.reverse();

    let code_frames = filter_code_frames(pid, &frames, range_cache);
    if code_frames.is_empty() {
        return frames
            .iter()
            .map(|ip| format!("{ip:#x}"))
            .collect::<Vec<_>>()
            .join(" -> ");
    }

    symbolize_frames(symbolizer, pid, &code_frames).join(" -> ")
}

fn filter_code_frames(pid: u32, frames: &[u64], cache: &mut RangeCache) -> Vec<u64> {
    let ranges = cache.ranges_for(pid);
    frames
        .iter()
        .copied()
        .filter(|ip| is_plausible_frame(*ip) && ranges.iter().any(|r| r.contains(ip)))
        .collect()
}

fn is_plausible_frame(ip: u64) -> bool {
    if ip < 0x1000 {
        return false;
    }
    // bpf_get_stackid user-stack placeholders for failed unwind steps.
    if ip >= 0xffff_0000_0000_0000 {
        return false;
    }
    true
}

#[derive(Default)]
struct RangeCache {
    pid: u32,
    ranges: Vec<Range<u64>>,
}

impl RangeCache {
    fn ranges_for(&mut self, pid: u32) -> &[Range<u64>] {
        if self.pid != pid || self.ranges.is_empty() {
            self.pid = pid;
            self.ranges = executable_ranges(pid);
        }
        &self.ranges
    }
}

fn executable_ranges(pid: u32) -> Vec<Range<u64>> {
    let path = format!("/proc/{pid}/maps");
    let Ok(data) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    data.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let span = parts.next()?;
            if !parts.any(|p| p == "r-xp") {
                return None;
            }
            let (start, end) = span.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            Some(start..end)
        })
        .collect()
}

fn symbolize_frames(symbolizer: &Symbolizer, pid: u32, frames: &[u64]) -> Vec<String> {
    let addrs: Vec<Addr> = frames.iter().copied().map(|a| a as Addr).collect();
    let src = Source::Process(Process::new(Pid::from(pid)));
    let syms = match symbolizer.symbolize(&src, Input::AbsAddr(&addrs)) {
        Ok(syms) => syms,
        Err(err) => {
            log::warn!("symbolize pid={pid} failed: {err:#}");
            return frames.iter().map(|ip| format!("{ip:#x}")).collect();
        }
    };

    syms.into_iter()
        .zip(frames.iter())
        .map(|(sym, ip)| match sym {
            Symbolized::Sym(s) => {
                if s.offset > 0 {
                    format!("{}+{}", s.name, s.offset)
                } else {
                    s.name.to_string()
                }
            }
            Symbolized::Unknown(_) => format!("{ip:#x}"),
        })
        .collect()
}

fn clear_counts(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut counts: HashMap<_, u32, StackCount> =
        HashMap::try_from(ebpf.map_mut("STACK_COUNTS").unwrap())?;
    let keys: Vec<u32> = counts
        .iter()
        .map(|item| item.map(|(k, _)| k))
        .collect::<Result<_, _>>()?;
    for key in keys {
        counts.remove(&key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_ranges_self() {
        fn marker() {}
        let pid = std::process::id();
        let ranges = executable_ranges(pid);
        assert!(!ranges.is_empty());
        let rip = marker as *const () as u64;
        assert!(ranges.iter().any(|r| r.contains(&rip)));
    }

    #[test]
    fn filters_bpf_placeholders() {
        assert!(!is_plausible_frame(0));
        assert!(!is_plausible_frame(0xffff_fffe_0000_002a));
        assert!(is_plausible_frame(0xb73c90));
    }
}

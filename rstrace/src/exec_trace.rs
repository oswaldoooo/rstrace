use std::mem::size_of;

use anyhow::{bail, Context as _};
use aya::{
    maps::{perf::PerfEvent, Array, PerfEventArray},
    programs::RawTracePoint,
    util::online_cpus,
};
use rstrace_common::{CommFilter, ExecEvent, MAX_EXEC_COMM_FILTERS};
use tokio::io::unix::AsyncFd;
use tokio::signal;

use crate::util::build_comm_filter;

const MAX_CWD_LEN: usize = 64;

/// 0 = unused, 1 = --comm allowlist, 2 = --ignore denylist (must match eBPF).
const COMM_MODE_ALLOW: u32 = 1;
const COMM_MODE_DENY: u32 = 2;

/// Trace `execve`/`execveat`. At least one of `--filter` / `--comm` / `--ignore`.
#[derive(clap::Parser)]
#[command(group(
    clap::ArgGroup::new("scope")
        .required(true)
        .multiple(true)
        .args(["filter", "comm", "ignore"])
))]
pub struct ExeTraceArgs {
    /// Match exec filename / argv (substring). May repeat.
    #[arg(long)]
    filter: Option<Vec<String>>,
    /// Match calling process comm (exact). Mutually exclusive with `--ignore`.
    #[arg(long, conflicts_with = "ignore")]
    comm: Option<Vec<String>>,
    /// Exclude these comms; collect everything else. Mutually exclusive with `--comm`.
    #[arg(long, conflicts_with = "comm")]
    ignore: Option<Vec<String>>,
}

/// 系统调用 exe 追踪；命中后输出到 stdout：
/// `$pid $comm $cmd $args $root_pid $root_comm $cwd $root_cwd`
///
/// `root_*`：沿 ppid 链向上，取父进程为 1（或不可达）之前的那个祖先。
/// `cwd` / `root_cwd`：`/proc/<pid>/cwd`，最多 64 字节。
pub async fn run(arg: ExeTraceArgs) -> anyhow::Result<()> {
    let filters: Vec<String> = arg
        .filter
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let comms: Vec<String> = arg
        .comm
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let ignores: Vec<String> = arg
        .ignore
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

    if filters.is_empty() && comms.is_empty() && ignores.is_empty() {
        bail!("at least one of --filter, --comm, or --ignore must be set (non-empty)");
    }
    if !comms.is_empty() && !ignores.is_empty() {
        bail!("--comm and --ignore are mutually exclusive");
    }

    let (comm_mode, comm_list) = if !comms.is_empty() {
        (COMM_MODE_ALLOW, &comms)
    } else if !ignores.is_empty() {
        (COMM_MODE_DENY, &ignores)
    } else {
        (0u32, &comms) // count 0 → eBPF passes all
    };

    if comm_list.len() as u32 > MAX_EXEC_COMM_FILTERS {
        bail!(
            "too many --comm/--ignore entries (max {})",
            MAX_EXEC_COMM_FILTERS
        );
    }

    let mut ebpf = crate::util::load_ebpf()?;

    eprintln!("exec-trace: loading raw_tracepoint/sys_enter program `exec_trace`");

    let program: &mut RawTracePoint = ebpf
        .program_mut("exec_trace")
        .context("exec_trace program not found")?
        .try_into()?;
    program.load().context("BPF load exec_trace failed")?;
    program.attach("sys_enter")?;
    eprintln!("exec-trace: attached; waiting for execve/execveat");
    log::info!("attached raw_tracepoint: sys_enter (execve/execveat)");

    {
        let mut count_map: Array<_, u32> =
            Array::try_from(ebpf.map_mut("EXEC_COMM_FILTER_COUNT").unwrap())?;
        count_map.set(0, comm_list.len() as u32, 0)?;

        let mut mode_map: Array<_, u32> =
            Array::try_from(ebpf.map_mut("EXEC_COMM_FILTER_MODE").unwrap())?;
        mode_map.set(0, comm_mode, 0)?;

        let mut filters_map: Array<_, CommFilter> =
            Array::try_from(ebpf.map_mut("EXEC_COMM_FILTERS").unwrap())?;
        for (i, name) in comm_list.iter().enumerate() {
            let filter = build_comm_filter(name)?;
            filters_map.set(i as u32, filter, 0)?;
        }
    }

    let mut perf_array =
        PerfEventArray::try_from(ebpf.take_map("EXEC_EVENTS").context("EXEC_EVENTS")?)?;

    let mut handles = Vec::new();
    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        let buf = perf_array.open(cpu_id, Some(8)).with_context(|| {
            format!(
                "open EXEC_EVENTS perf buf cpu={cpu_id} (ENOSPC often means memlock; try: ulimit -l unlimited)"
            )
        })?;
        let filters = filters.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = poll_cpu(buf, filters).await {
                eprintln!("exec-trace: cpu reader error: {e:#}");
            }
        }));
    }

    log::info!(
        "exec-trace running (filter={filters:?} comm={comms:?} ignore={ignores:?})"
    );

    signal::ctrl_c().await?;
    for h in handles {
        h.abort();
    }
    Ok(())
}

async fn poll_cpu(
    buf: aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>,
    filters: Vec<String>,
) -> anyhow::Result<()> {
    let mut async_fd = AsyncFd::new(buf)?;
    loop {
        let mut guard = async_fd.readable_mut().await?;
        {
            let buf = guard.get_inner_mut();
            buf.for_each(|event| match event {
                PerfEvent::Sample { head, tail } => {
                    if let Some(ev) = parse_exec_event(head, tail) {
                        if matches_filter(&ev, &filters) {
                            print_event(&ev);
                        }
                    }
                }
                PerfEvent::Lost { count } => {
                    log::warn!("lost {count} exec events");
                }
            });
        }
        guard.clear_ready();
    }
}

fn parse_exec_event(head: &[u8], tail: &[u8]) -> Option<ExecEvent> {
    let need = size_of::<ExecEvent>();
    if head.len() + tail.len() < need {
        return None;
    }
    let mut raw = [0u8; size_of::<ExecEvent>()];
    let n = head.len().min(need);
    raw[..n].copy_from_slice(&head[..n]);
    if n < need {
        raw[n..].copy_from_slice(&tail[..need - n]);
    }
    Some(unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<ExecEvent>()) })
}

fn matches_filter(ev: &ExecEvent, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    let cmd = cstr_lossy(&ev.cmd);
    let args = cstr_lossy(&ev.args);
    filters
        .iter()
        .any(|f| cmd.contains(f) || args.contains(f))
}

fn print_event(ev: &ExecEvent) {
    let comm = cstr_lossy(&ev.comm);
    let cmd = cstr_lossy(&ev.cmd);
    let args = cstr_lossy(&ev.args);
    let (root_pid, root_comm) = resolve_root_process(ev.pid);
    let cwd = read_proc_cwd(ev.pid);
    let root_cwd = read_proc_cwd(root_pid);
    println!(
        "{} {} {} {} {} {} {} {}",
        ev.pid, comm, cmd, args, root_pid, root_comm, cwd, root_cwd
    );
}

/// Walk `/proc/<pid>/stat` ppid chain; return the ancestor just below pid 1.
fn resolve_root_process(pid: u32) -> (u32, String) {
    const MAX_DEPTH: usize = 64;

    let mut cur = pid;
    let mut root_pid = pid;
    let mut root_comm = read_proc_comm(pid);

    for _ in 0..MAX_DEPTH {
        let Some(ppid) = read_proc_ppid(cur) else {
            break;
        };
        if ppid <= 1 {
            break;
        }
        if ppid == cur {
            break;
        }
        root_pid = ppid;
        root_comm = read_proc_comm(ppid);
        cur = ppid;
    }

    (root_pid, root_comm)
}

fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    let mut fields = stat[rparen + 1..].split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

fn read_proc_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_else(|_| "?".into())
}

fn read_proc_cwd(pid: u32) -> String {
    match std::fs::read_link(format!("/proc/{pid}/cwd")) {
        Ok(path) => truncate_bytes(&path.to_string_lossy(), MAX_CWD_LEN),
        Err(_) => "?".into(),
    }
}

fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn cstr_lossy(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

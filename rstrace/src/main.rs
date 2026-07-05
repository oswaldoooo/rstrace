mod compute_effective;
mod dstlog;
mod netbw_collect;
mod syscall_collect;
mod syscall_names;
mod util;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "rstrace", about = "Linux eBPF process resource collector")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Collect system call ratio statistics via raw_syscalls/sys_enter tracepoint.
    SyscallCollect(SyscallCollectArgs),
    /// Collect per-process outbound network bandwidth via kprobes.
    #[command(name = "netbw-collect")]
    NetBwCollect(NetBwCollectArgs),
    /// Measure CPU compute efficiency with a fixed pure-compute workload.
    #[command(name = "compute_effective")]
    ComputeEffective(ComputeEffectiveArgs),
    /// Log outbound TCP/UDP destination IPs for a given process comm.
    #[command(name = "dstlog")]
    DstLog(DstLogArgs),
}

#[derive(Parser)]
pub struct SyscallCollectArgs {
    /// Interval in seconds between syncing and printing statistics from the eBPF map.
    #[arg(long, default_value_t = 1)]
    duration: u64,

    /// Only collect syscalls from tasks whose comm matches this name (e.g. bash, nginx).
    #[arg(long)]
    comm: Option<String>,

    /// Emit JSON to stdout (one object per sync, no other stdout output).
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
pub struct NetBwCollectArgs {
    /// Interval in seconds between syncing and printing statistics from the eBPF map.
    #[arg(long, default_value_t = 1)]
    duration: u64,

    /// Only collect traffic from tasks whose comm matches this name.
    #[arg(long)]
    comm: Option<String>,

    /// Include TCP outbound bandwidth (kprobe: tcp_write_xmit).
    #[arg(short = 't')]
    tcp: bool,

    /// Include UDP outbound bandwidth (kprobe: udp_sendmsg).
    #[arg(short = 'u')]
    udp: bool,

    /// Report cumulative bytes since start (maps are not reset between syncs).
    #[arg(long)]
    sum: bool,

    /// Overwrite this file with stats on every sync interval.
    #[arg(short = 'o')]
    output: Option<std::path::PathBuf>,

    /// Sort results by TCP or UDP value descending.
    #[arg(long, value_enum)]
    sort: Option<NetBwSortKey>,

    /// Emit JSON to stdout (one object per sync, no other stdout output).
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
pub struct ComputeEffectiveArgs {
    /// Number of benchmark rounds; median elapsed time is used for the score.
    #[arg(long, default_value_t = 3)]
    rounds: usize,

    /// Fixed deterministic work units per round (equal compute across platforms).
    #[arg(long, default_value_t = compute_effective::DEFAULT_WORK_UNITS)]
    work_units: u64,

    /// Emit JSON to stdout (no other stdout output).
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
pub struct DstLogArgs {
    /// Interval in seconds between map rotation and draining the inactive buffer.
    #[arg(long, default_value_t = 1)]
    duration: u64,

    /// Process comm to monitor (required).
    #[arg(long)]
    comm: String,

    /// Capture TCP outbound destinations (kprobe: tcp_connect).
    #[arg(short = 't')]
    tcp: bool,

    /// Capture UDP outbound destinations (kprobe: udp_sendmsg).
    #[arg(short = 'u')]
    udp: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum NetBwSortKey {
    Tcp,
    Udp,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json = match &cli.command {
        Commands::SyscallCollect(a) => a.json,
        Commands::NetBwCollect(a) => a.json,
        Commands::ComputeEffective(a) => a.json,
        Commands::DstLog(_) => false,
    };
    util::init_logging(json);

    match cli.command {
        Commands::SyscallCollect(args) => syscall_collect::run(args).await?,
        Commands::NetBwCollect(args) => netbw_collect::run(args).await?,
        Commands::ComputeEffective(args) => compute_effective::run(args)?,
        Commands::DstLog(args) => dstlog::run(args).await?,
    }

    Ok(())
}

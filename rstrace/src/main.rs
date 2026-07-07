mod compute_effective;
mod dns_capture;
mod dstlog;
mod ip_blacklist;
mod ip_blacklist_test;
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
    /// Capture DNS queries (UDP dst port 53) via pnet. Output: domain qtype timestamp.
    #[command(name = "dns_capture")]
    DnsCapture(DnsCaptureArgs),
    /// Drop IPv4 traffic matching blacklist CIDR ranges via XDP.
    #[command(name = "ip-blacklist")]
    IpBlacklist(IpBlacklistArgs),
    /// Detach the XDP blacklist program from a network interface.
    #[command(name = "ip-blacklist-detach")]
    IpBlacklistDetach(IpBlacklistDetachArgs),
    #[command(name = "ip-blacklist-test")]
    IpBlacklistTest(IpBlacklistTestArgs),
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
    #[arg(long)]
    blacklist: Option<String>,
}

#[derive(Parser)]
pub struct DnsCaptureArgs {
    /// Interval in seconds between printing aggregated DNS records.
    #[arg(long, default_value_t = 1)]
    duration: u64,

    /// Network interface to sniff (default: all active interfaces including lo).
    #[arg(long, short = 'i')]
    interface: Option<String>,
}

#[derive(Parser)]
pub struct IpBlacklistArgs {
    /// Network interface to attach the XDP program.
    #[arg(long, short = 'd')]
    interface: String,
    #[arg(long, short = 'i')]
    input: Option<std::path::PathBuf>,

    /// Add a CIDR range before attaching (may repeat).
    #[arg(long)]
    add: Vec<String>,

    /// Remove a CIDR range before attaching (may repeat).
    #[arg(long)]
    delete: Vec<String>,

    /// Interval in seconds between writing hit stats to -o (default: 60).
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Overwrite this file with per-range drop counts each interval (only ranges with hits).
    #[arg(short = 'o')]
    output: Option<std::path::PathBuf>,

    /// Do not drop packets; print matched blacklist IPs to stdout (dstlog-style).
    #[arg(long)]
    dry_run: bool,

    /// Drop TCP packets when src/dst matches the blacklist.
    #[arg(short = 't')]
    tcp: bool,

    /// Drop UDP packets when src/dst matches the blacklist.
    #[arg(short = 'u')]
    udp: bool,
}

#[derive(Parser)]
pub struct IpBlacklistDetachArgs {
    /// Network interface to detach the XDP program from.
    #[arg(long, short = 'd')]
    interface: String,
}

#[derive(Parser)]
pub struct IpBlacklistTestArgs {
    #[arg(long, short = 'f')]
    file: std::path::PathBuf,
    ///test ip list
    targets: Option<Vec<String>>,
    ///json model output
    #[arg(long)]
    json: bool,
    ///stream model,input by stdin
    #[arg(long)]
    stream: bool,
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
        Commands::DnsCapture(_) => false,
        Commands::IpBlacklist(_) => false,
        Commands::IpBlacklistDetach(_) => false,
        Commands::IpBlacklistTest(a) => a.json,
    };
    util::init_logging(json);

    match cli.command {
        Commands::SyscallCollect(args) => syscall_collect::run(args).await?,
        Commands::NetBwCollect(args) => netbw_collect::run(args).await?,
        Commands::ComputeEffective(args) => compute_effective::run(args)?,
        Commands::DstLog(args) => dstlog::run(args).await?,
        Commands::DnsCapture(args) => dns_capture::run(args).await?,
        Commands::IpBlacklist(args) => ip_blacklist::run(args).await?,
        Commands::IpBlacklistDetach(args) => {
            ip_blacklist::detach_xdp(&args.interface)?;
            println!("XDP detached from {}", args.interface);
        }
        Commands::IpBlacklistTest(args) => ip_blacklist_test::run(args)?,
    }

    Ok(())
}

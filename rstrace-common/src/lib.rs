#![no_std]

pub const MAX_COMM_LEN: usize = 16;
pub const MAX_SYSCALLS: u32 = 512;
pub const MAX_PIDS: u32 = 8192;
pub const MAX_DST_ENTRIES: u32 = 16384;
pub const MAX_BLACKLIST_RANGES: u32 = 2048;
pub const MAX_STACK_TRACES: u32 = 1024;
pub const MAX_STACK_SAMPLES: u32 = 4096;
pub const MAX_EXEC_COMM_FILTERS: u32 = 32;
pub const MAX_EXEC_CMD_LEN: usize = 96;
pub const MAX_EXEC_ARGS_LEN: usize = 192;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// sk_buff field offsets for x86_64 (verified on 5.x / 6.x with pahole + BTF).
pub const SKB_LEN_OFFSET: usize = 112;

// struct msghdr on x86_64
pub const MSGHDR_MSG_NAME_OFFSET: usize = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommFilter {
    pub comm: [u8; MAX_COMM_LEN],
    pub enabled: u8,
}

impl CommFilter {
    pub fn disabled() -> Self {
        Self {
            comm: [0; MAX_COMM_LEN],
            enabled: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DstKey {
    pub addr: [u8; 16],
    pub family: u8,
    pub proto: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DstLogConfig {
    pub tcp_enabled: u8,
    pub udp_enabled: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpBlacklistConfig {
    pub tcp_enabled: u8,
    pub udp_enabled: u8,
}

/// Execve event sent via PerfEventArray.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub _pad: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub cmd: [u8; MAX_EXEC_CMD_LEN],
    pub args: [u8; MAX_EXEC_ARGS_LEN],
}

impl Default for ExecEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            _pad: 0,
            comm: [0; MAX_COMM_LEN],
            cmd: [0; MAX_EXEC_CMD_LEN],
            args: [0; MAX_EXEC_ARGS_LEN],
        }
    }
}

/// Per-stack hit counter plus the process that produced the sample (for symbolization).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StackCount {
    pub count: u64,
    pub pid: u32,
    pub _pad: u32,
}

/// IPv4 inclusive range in network byte order (`start <= ip <= end`).
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Range {
    pub start: u32,
    pub end: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommFilter {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ipv4Range {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DstKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DstLogConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpBlacklistConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StackCount {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

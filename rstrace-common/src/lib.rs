#![no_std]

pub const MAX_COMM_LEN: usize = 16;
pub const MAX_SYSCALLS: u32 = 512;
pub const MAX_PIDS: u32 = 8192;
pub const MAX_DST_ENTRIES: u32 = 16384;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// sk_buff field offsets for x86_64 (verified on 5.x / 6.x with pahole + BTF).
pub const SKB_LEN_OFFSET: usize = 112;

// struct msghdr::msg_name on x86_64
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommFilter {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DstKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DstLogConfig {}

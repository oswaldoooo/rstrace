#![no_std]

pub const MAX_COMM_LEN: usize = 16;
pub const MAX_SYSCALLS: u32 = 512;
pub const MAX_PIDS: u32 = 8192;

// sk_buff field offsets for x86_64 (verified on 5.x / 6.x with pahole + BTF).
pub const SKB_LEN_OFFSET: usize = 112;

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommFilter {}

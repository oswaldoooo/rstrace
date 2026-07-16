#![no_std]
#![no_main]

mod dstlog;
mod exec_trace;
mod helpers;
mod netbw;
mod syscall;
mod syscall_stack;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

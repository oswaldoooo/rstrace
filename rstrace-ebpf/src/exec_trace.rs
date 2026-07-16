use aya_ebpf::{
    EbpfContext,
    helpers::{
        generated::bpf_get_current_comm,
        bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, raw_tracepoint},
    maps::{Array, PerfEventArray, PerCpuArray},
    programs::RawTracePointContext,
};
use rstrace_common::{
    CommFilter, ExecEvent, MAX_COMM_LEN, MAX_EXEC_ARGS_LEN, MAX_EXEC_CMD_LEN, MAX_EXEC_COMM_FILTERS,
};

/// x86_64 syscall numbers
const SYS_EXECVE: u64 = 59;
const SYS_EXECVEAT: u64 = 322;

/// Small limits so the verifier can track the copy loops.
const MAX_ARGV: u32 = 3;
const ARG_CHUNK: usize = 32;

#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[map]
static EXEC_COMM_FILTERS: Array<CommFilter> = Array::with_max_entries(MAX_EXEC_COMM_FILTERS, 0);

#[map]
static EXEC_COMM_FILTER_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// 0 = pass all (count==0), 1 = allowlist (--comm), 2 = denylist (--ignore).
#[map]
static EXEC_COMM_FILTER_MODE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

const COMM_MODE_ALLOW: u32 = 1;
const COMM_MODE_DENY: u32 = 2;

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn exec_trace(ctx: RawTracePointContext) -> i32 {
    match try_exec_trace(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_exec_trace(ctx: RawTracePointContext) -> Result<i32, i64> {
    let syscall_id: u64 = ctx.arg(1);
    if syscall_id != SYS_EXECVE && syscall_id != SYS_EXECVEAT {
        return Ok(0);
    }

    let mut comm: [u8; MAX_COMM_LEN] =
        unsafe { core::mem::MaybeUninit::<[u8; MAX_COMM_LEN]>::uninit().assume_init() };
    read_comm(&mut comm)?;

    if !passes_comm_filter(&comm)? {
        return Ok(0);
    }

    let regs: *const u8 = ctx.arg(0);
    if regs.is_null() {
        return Ok(0);
    }

    // x86_64 pt_regs field offsets (bytes).
    const OFF_RDX: usize = 12 * 8;
    const OFF_RSI: usize = 13 * 8;
    const OFF_RDI: usize = 14 * 8;

    let (filename, argv) = if syscall_id == SYS_EXECVE {
        (read_reg(regs, OFF_RDI)?, read_reg(regs, OFF_RSI)?)
    } else {
        (read_reg(regs, OFF_RSI)?, read_reg(regs, OFF_RDX)?)
    };

    let event = unsafe {
        let ptr = EXEC_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
        &mut *ptr
    };

    event.pid = ctx.tgid();
    event._pad = 0;
    event.cmd[0] = 0;
    event.args[0] = 0;
    let mut i = 0;
    while i < MAX_COMM_LEN {
        event.comm[i] = comm[i];
        i += 1;
    }

    if filename != 0 {
        // Full fixed-size field — verifier can prove the bound.
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename as *const u8, &mut event.cmd)
        };
    }

    if argv != 0 {
        read_argv(argv as *const u64, &mut event.args);
    }

    EXEC_EVENTS.output(&ctx, event, 0);
    Ok(0)
}

#[inline(always)]
fn read_comm(out: &mut [u8; MAX_COMM_LEN]) -> Result<(), i64> {
    let ret = unsafe { bpf_get_current_comm(out.as_mut_ptr().cast(), MAX_COMM_LEN as u32) };
    if ret == 0 {
        Ok(())
    } else {
        Err(ret as i64)
    }
}

#[inline(always)]
fn read_reg(regs: *const u8, off: usize) -> Result<u64, i64> {
    let ptr = unsafe { regs.add(off) as *const u64 };
    unsafe { bpf_probe_read_kernel(ptr) }.map_err(|e| e as i64)
}

#[inline(always)]
fn passes_comm_filter(comm: &[u8; MAX_COMM_LEN]) -> Result<bool, i64> {
    let count = match EXEC_COMM_FILTER_COUNT.get(0) {
        Some(c) => *c,
        None => return Ok(true),
    };
    if count == 0 {
        return Ok(true);
    }

    let mode = match EXEC_COMM_FILTER_MODE.get(0) {
        Some(m) => *m,
        None => COMM_MODE_ALLOW,
    };

    let mut matched = false;
    let mut i = 0u32;
    while i < MAX_EXEC_COMM_FILTERS {
        if i >= count {
            break;
        }
        if let Some(filter) = EXEC_COMM_FILTERS.get(i) {
            if filter.enabled != 0 && comm_eq(&filter.comm, comm) {
                matched = true;
                break;
            }
        }
        i += 1;
    }

    if mode == COMM_MODE_DENY {
        Ok(!matched)
    } else {
        Ok(matched)
    }
}

#[inline(always)]
fn comm_eq(filter: &[u8; MAX_COMM_LEN], comm: &[u8; MAX_COMM_LEN]) -> bool {
    let mut i = 0;
    while i < MAX_COMM_LEN {
        let a = filter[i];
        if a == 0 {
            return true;
        }
        if a != comm[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Probe each argv into a **stack** buffer (fixed size), then copy into `out`.
/// Never call `bpf_probe_read_str` with a dynamic `&mut out[off..]` into a map value —
/// the verifier cannot prove that bound (`off=312 size=190`).
#[inline(always)]
fn read_argv(argv: *const u64, out: &mut [u8; MAX_EXEC_ARGS_LEN]) {
    let mut off: u32 = 0;
    let mut ai: u32 = 0;

    while ai < MAX_ARGV {
        let ptr: u64 = match unsafe { bpf_probe_read_user(argv.add(ai as usize)) } {
            Ok(p) => p,
            Err(_) => break,
        };
        if ptr == 0 {
            break;
        }

        let mut tmp: [u8; ARG_CHUNK] =
            unsafe { core::mem::MaybeUninit::<[u8; ARG_CHUNK]>::uninit().assume_init() };
        let Ok(s) = (unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, &mut tmp) }) else {
            break;
        };
        let mut n = s.len();
        if n == 0 {
            break;
        }
        if n > ARG_CHUNK {
            n = ARG_CHUNK;
        }
        let n = n as u32;

        if off > 0 {
            if off >= MAX_EXEC_ARGS_LEN as u32 {
                break;
            }
            out[off as usize] = b' ';
            off += 1;
        }

        let mut j: u32 = 0;
        while j < ARG_CHUNK as u32 {
            if j >= n {
                break;
            }
            if off >= MAX_EXEC_ARGS_LEN as u32 {
                break;
            }
            out[off as usize] = tmp[j as usize];
            off += 1;
            j += 1;
        }

        if off >= MAX_EXEC_ARGS_LEN as u32 {
            break;
        }
        ai += 1;
    }

    if off < MAX_EXEC_ARGS_LEN as u32 {
        out[off as usize] = 0;
    }
}

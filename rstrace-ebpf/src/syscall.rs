use aya_ebpf::{
    EbpfContext,
    macros::{map, raw_tracepoint},
    maps::{Array, HashMap},
    programs::RawTracePointContext,
};
use rstrace_common::{CommFilter, MAX_SYSCALLS};

use crate::helpers::comm_matches;

#[map]
static SYSCALL_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(MAX_SYSCALLS, 0);

#[map]
static COMM_FILTER: Array<CommFilter> = Array::with_max_entries(1, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscall_collect(ctx: RawTracePointContext) -> i32 {
    match try_syscall_collect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

fn try_syscall_collect(ctx: RawTracePointContext) -> Result<i32, i64> {
    let filter = COMM_FILTER.get(0).ok_or(0)?;
    if filter.enabled != 0 {
        let comm = ctx.command().map_err(|_| 0)?;
        if !comm_matches(&filter.comm, &comm) {
            return Ok(0);
        }
    }

    let syscall_id: i64 = ctx.arg(1);
    if syscall_id < 0 {
        return Ok(0);
    }
    let key = syscall_id as u32;

    if let Some(count) = SYSCALL_COUNTS.get_ptr_mut(&key) {
        unsafe {
            *count += 1;
        }
    } else {
        let one = 1u64;
        SYSCALL_COUNTS.insert(&key, &one, 0)?;
    }

    Ok(0)
}

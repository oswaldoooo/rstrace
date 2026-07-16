use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_USER_STACK,
    macros::{map, raw_tracepoint},
    maps::{Array, HashMap, StackTrace},
    programs::{
        RawTracePointContext,
        tracing::StackIdContext as _,
    },
};
use rstrace_common::{CommFilter, StackCount, MAX_STACK_SAMPLES, MAX_STACK_TRACES, MAX_SYSCALLS};

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(MAX_STACK_TRACES, 0);

#[map]
static STACK_COUNTS: HashMap<u32, StackCount> = HashMap::with_max_entries(MAX_STACK_SAMPLES, 0);

#[map]
static STACK_COMM_FILTER: Array<CommFilter> = Array::with_max_entries(1, 0);

#[map]
static TARGET_SYSCALL: Array<u32> = Array::with_max_entries(1, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscall_stack(ctx: RawTracePointContext) -> i32 {
    match try_syscall_stack(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

fn try_syscall_stack(ctx: RawTracePointContext) -> Result<i32, i64> {
    let filter = STACK_COMM_FILTER.get(0).ok_or(0)?;
    if filter.enabled != 0 {
        let comm = ctx.command().map_err(|_| 0)?;
        if !crate::helpers::comm_matches(&filter.comm, &comm) {
            return Ok(0);
        }
    }

    let target = TARGET_SYSCALL.get(0).ok_or(0)?;
    let syscall_id: i64 = ctx.arg(1);
    if syscall_id < 0 || syscall_id as u32 >= MAX_SYSCALLS || syscall_id as u32 != *target {
        return Ok(0);
    }

    let stack_id = ctx.get_stackid(&STACK_TRACES, BPF_F_USER_STACK as u64)?;
    if stack_id < 0 {
        return Ok(0);
    }
    let key = stack_id as u32;
    let pid = ctx.tgid();

    if let Some(sample) = STACK_COUNTS.get_ptr_mut(&key) {
        unsafe {
            (*sample).count += 1;
            (*sample).pid = pid;
        }
    } else {
        let sample = StackCount {
            count: 1,
            pid,
            _pad: 0,
        };
        STACK_COUNTS.insert(&key, &sample, 0)?;
    }

    Ok(0)
}

pub fn comm_matches(filter: &[u8; rstrace_common::MAX_COMM_LEN], comm: &[u8; rstrace_common::MAX_COMM_LEN]) -> bool {
    for (a, b) in filter.iter().zip(comm.iter()) {
        if *a == 0 {
            break;
        }
        if *a != *b {
            return false;
        }
    }
    true
}

pub fn add_tx_bytes(
    map: &aya_ebpf::maps::HashMap<u32, u64>,
    pid: u32,
    bytes: u64,
) -> Result<(), i64> {
    if let Some(total) = map.get_ptr_mut(&pid) {
        unsafe {
            *total += bytes;
        }
    } else {
        map.insert(&pid, &bytes, 0)?;
    }
    Ok(())
}

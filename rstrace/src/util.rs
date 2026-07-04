use rstrace_common::{CommFilter, MAX_COMM_LEN};

pub fn build_comm_filter(comm: &str) -> anyhow::Result<CommFilter> {
    if comm.is_empty() {
        anyhow::bail!("comm filter must not be empty");
    }
    if comm.len() > MAX_COMM_LEN - 1 {
        anyhow::bail!(
            "comm filter too long (max {} bytes)",
            MAX_COMM_LEN - 1
        );
    }

    let mut filter = CommFilter::disabled();
    filter.enabled = 1;
    for (i, b) in comm.bytes().enumerate() {
        filter.comm[i] = b;
    }
    Ok(filter)
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;

    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{:.2} B", b)
    }
}

pub fn init_logging(json: bool) {
    use env_logger::Env;
    let mut builder = env_logger::Builder::from_env(Env::default());
    if json {
        builder.filter_level(log::LevelFilter::Error);
    }
    builder.init();
}

pub fn format_bandwidth(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.2} B/s", bytes_per_sec)
    }
}

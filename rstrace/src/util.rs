use anyhow::Context as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rstrace_common::{CommFilter, MAX_COMM_LEN};

use aya::Ebpf;

pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rstrace"
    )))
    .map_err(Into::into)
}

pub fn load_ebpf_xdp() -> anyhow::Result<Ebpf> {
    raise_memlock_limit()?;
    Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rstrace-xdp"
    )))
    .map_err(Into::into)
}

fn raise_memlock_limit() -> anyhow::Result<()> {
    let target = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &target) } != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!(
            "failed to raise RLIMIT_MEMLOCK ({err}); run as root and/or: ulimit -l unlimited"
        );
    }
    Ok(())
}

pub fn build_comm_filter(comm: &str) -> anyhow::Result<CommFilter> {
    if comm.is_empty() {
        anyhow::bail!("comm filter must not be empty");
    }
    if comm.len() > MAX_COMM_LEN - 1 {
        anyhow::bail!("comm filter too long (max {} bytes)", MAX_COMM_LEN - 1);
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
/// ChaCha20-Poly1305 decrypt. Input layout: `nonce(12) || ciphertext || tag(16)`.
pub fn decrypt(src: &[u8]) -> anyhow::Result<Vec<u8>> {
    const SECRET_KEY: &str = "09e8d507f17e486802493c0dd1de9214cb3aabe4f0fa2713caef55159d262d25";
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    if src.len() < NONCE_LEN + TAG_LEN {
        anyhow::bail!("ciphertext too short");
    }

    let key = hex::decode(SECRET_KEY).context("invalid secret key hex")?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).context("invalid ChaCha20-Poly1305 key length")?;

    let (nonce_bytes, ciphertext) = src.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod decrypt_tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;

    #[test]
    fn decrypt_roundtrip() {
        const SECRET_KEY: &str =
            "09e8d507f17e486802493c0dd1de9214cb3aabe4f0fa2713caef55159d262d25";
        let key = hex::decode(SECRET_KEY).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(b"unique nonce");
        let plaintext = b"hello rstrace";
        let mut blob = nonce.to_vec();
        blob.extend(
            cipher
                .encrypt(nonce, plaintext.as_ref())
                .unwrap(),
        );
        assert_eq!(decrypt(&blob).unwrap(), plaintext);
    }
}

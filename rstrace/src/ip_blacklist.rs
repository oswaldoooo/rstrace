use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use aya::{
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie},
    programs::{Xdp, XdpMode},
};
use rstrace_common::{IpBlacklistConfig, Ipv4Range, MAX_BLACKLIST_RANGES};
use tokio::signal;

pub async fn run(args: super::IpBlacklistArgs) -> anyhow::Result<()> {
    let mut ranges = Blacklist::new();
    let input = args
        .input
        .unwrap_or(std::path::PathBuf::new().join("/etc/.ip_blacklist"));
    ranges.load_file(&input)?;
    for cidr in &args.add {
        ranges.add_cidr(cidr)?;
    }
    for cidr in &args.delete {
        ranges.remove_cidr(cidr)?;
    }

    if ranges.is_empty() {
        anyhow::bail!("blacklist is empty; use -i or --add");
    }
    if !args.tcp && !args.udp {
        anyhow::bail!("at least one of -t (TCP) or -u (UDP) must be specified");
    }

    let mut ebpf = crate::util::load_ebpf_xdp()?;
    ranges.sync_to_ebpf(&mut ebpf, args.dry_run, args.tcp, args.udp)?;

    detach_xdp(&args.interface)?;

    let program: &mut Xdp = ebpf
        .program_mut("ip_blacklist")
        .context("ip_blacklist program not found")?
        .try_into()?;
    program.load()?;
    program.attach(&args.interface, XdpMode::default())?;

    log::info!(
        "ip-blacklist attached on {} ({} ranges, proto: {}{}); press Ctrl+C to stop",
        args.interface,
        ranges.len(),
        protocol_label(args.tcp, args.udp),
        if args.dry_run { " [dry-run]" } else { "" }
    );

    if args.dry_run {
        run_dry_run_loop(&mut ebpf, args.duration).await?;
        return Ok(());
    }

    if args.output.is_none() && args.stun_output.is_none() {
        signal::ctrl_c().await?;
        return Ok(());
    }

    let output = args.output.clone();
    let stun_output = args.stun_output.clone();
    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(path) = &output {
                    ranges.dump_hits(&mut ebpf, path)?;
                }
                if let Some(path) = &stun_output {
                    dump_stun_passes(&mut ebpf, path)?;
                }
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    Ok(())
}

fn protocol_label(tcp: bool, udp: bool) -> &'static str {
    match (tcp, udp) {
        (true, true) => "tcp+udp",
        (true, false) => "tcp",
        (false, true) => "udp",
        (false, false) => "none",
    }
}

async fn run_dry_run_loop(ebpf: &mut aya::Ebpf, duration_secs: u64) -> anyhow::Result<()> {
    let mut write_buf: u32 = 0;
    {
        let mut active: Array<_, u32> =
            Array::try_from(ebpf.map_mut("DRY_RUN_ACTIVE_BUF").unwrap())?;
        active.set(0, write_buf, 0)?;
    }

    let interval = Duration::from_secs(duration_secs);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let drain_buf = write_buf;
                write_buf = 1 - write_buf;
                {
                    let mut active: Array<_, u32> =
                        Array::try_from(ebpf.map_mut("DRY_RUN_ACTIVE_BUF").unwrap())?;
                    active.set(0, write_buf, 0)?;
                }
                let map_name = if drain_buf == 0 {
                    "DRY_RUN_MAP_A"
                } else {
                    "DRY_RUN_MAP_B"
                };
                drain_dry_run(ebpf.map_mut(map_name).unwrap())?;
            }
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }
    Ok(())
}

fn drain_dry_run(map: &mut aya::maps::Map) -> anyhow::Result<()> {
    let mut hash = HashMap::<_, u32, u64>::try_from(map)?;
    let entries: Vec<(u32, u64)> = hash
        .iter()
        .map(|item| item.map(|(k, v)| (k, v)))
        .collect::<Result<_, _>>()?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    for (ip, count) in &entries {
        if let Some(text) = format_ip_key(*ip) {
            println!("{text} {ts} {count}");
        }
    }

    for (ip, _) in entries {
        hash.remove(&ip)?;
    }
    Ok(())
}

fn format_ip_key(ip: u32) -> Option<String> {
    Some(Ipv4Addr::from(ip.to_be_bytes()).to_string())
}

fn dump_stun_passes(ebpf: &mut aya::Ebpf, output: &Path) -> anyhow::Result<()> {
    let mut counts: HashMap<_, u32, u64> =
        HashMap::try_from(ebpf.map_mut("STUN_PASS_COUNTS").unwrap())?;

    let mut entries: Vec<(String, u64)> = counts
        .iter()
        .filter_map(|item| {
            item.ok()
                .and_then(|(ip, count)| format_ip_key(ip).map(|text| (text, count)))
        })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let body = if entries.is_empty() {
        String::new()
    } else {
        let mut lines = Vec::with_capacity(entries.len());
        for (ip, count) in entries {
            lines.push(format!("{ip} {count}"));
        }
        format!("{}\n", lines.join("\n"))
    };
    fs::write(output, body).with_context(|| format!("write {}", output.display()))?;
    Ok(())
}

/// RFC 5389 / RFC 3489 STUN Binding message heuristic (mirrors eBPF checks).
pub fn is_stun_binding_message(payload: &[u8], src_port: u16, dst_port: u16) -> bool {
    const STUN_HDR_LEN: usize = 20;
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
    const STUN_BINDING_REQUEST: u16 = 0x0001;
    const STUN_BINDING_INDICATION: u16 = 0x0011;
    const STUN_BINDING_SUCCESS: u16 = 0x0101;
    const STUN_BINDING_ERROR: u16 = 0x0111;
    const STUN_PORT: u16 = 3478;

    if payload.len() < STUN_HDR_LEN {
        return false;
    }
    let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
    let known = msg_type == STUN_BINDING_REQUEST
        || msg_type == STUN_BINDING_INDICATION
        || msg_type == STUN_BINDING_SUCCESS
        || msg_type == STUN_BINDING_ERROR;
    if !known {
        return false;
    }
    let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if msg_len > payload.len() - STUN_HDR_LEN {
        return false;
    }
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie == STUN_MAGIC_COOKIE {
        return true;
    }
    (src_port == STUN_PORT || dst_port == STUN_PORT) && msg_len <= 256
}

/// Backward-compatible alias for Binding Request checks in tests.
pub fn is_stun_binding_request(payload: &[u8], src_port: u16, dst_port: u16) -> bool {
    if payload.len() < 2 {
        return false;
    }
    let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
    if msg_type != 0x0001 {
        return false;
    }
    is_stun_binding_message(payload, src_port, dst_port)
}

/// Detach any XDP program from `interface` via `ip link` (no bpftool required).
pub fn detach_xdp(interface: &str) -> anyhow::Result<()> {
    const MODES: &[&str] = &["xdp", "xdpgeneric", "xdpdrv", "xdpskb"];
    for mode in MODES {
        let output = Command::new("ip")
            .args(["link", "set", "dev", interface, mode, "off"])
            .output()
            .with_context(|| format!("run `ip link set dev {interface} {mode} off`"))?;
        if output.status.success() {
            log::info!("detached {mode} from {interface}");
        }
    }

    if xdp_attached(interface)? {
        anyhow::bail!("XDP program still attached on {interface}");
    }
    Ok(())
}

fn xdp_attached(interface: &str) -> anyhow::Result<bool> {
    let output = Command::new("ip")
        .args(["-d", "link", "show", "dev", interface])
        .output()
        .with_context(|| format!("run `ip -d link show dev {interface}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`ip -d link show dev {interface}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.contains("prog/xdp") || text.contains("xdp:"))
}

pub struct BlacklistEntry {
    pub label: String,
    pub prefix: u8,
    pub range: Ipv4Range,
}

pub struct Blacklist {
    entries: Vec<BlacklistEntry>,
}

impl Blacklist {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[BlacklistEntry] {
        &self.entries
    }

    /// Query the loaded eBPF LPM trie (same logic as XDP). Requires `sync_to_ebpf` first.
    pub fn is_hit_ebpf(&self, ebpf: &mut aya::Ebpf, ip: Ipv4Addr) -> anyhow::Result<bool> {
        Ok(self.matching_entry_ebpf(ebpf, ip)?.is_some())
    }

    /// Returns the blacklist entry selected by the eBPF LPM trie for `ip`, if any.
    pub fn matching_entry_ebpf(
        &self,
        ebpf: &mut aya::Ebpf,
        ip: Ipv4Addr,
    ) -> anyhow::Result<Option<&BlacklistEntry>> {
        let trie: LpmTrie<_, u32, u32> = LpmTrie::try_from(ebpf.map_mut("BLACKLIST").unwrap())?;
        let key = Key::new(32, lpm_ip_word(ip));
        let idx = trie.get(&key, 0)?;
        Ok(self.entries.get(idx as usize))
    }

    /// Returns whether `ip` matches any blacklist CIDR (longest prefix wins on overlap).
    pub fn is_hit(&self, ip: Ipv4Addr) -> bool {
        self.matching_entry(ip).is_some()
    }

    /// Returns the matching blacklist entry for `ip`, if any (longest prefix wins on overlap).
    pub fn matching_entry(&self, ip: Ipv4Addr) -> Option<&BlacklistEntry> {
        let ip = u32::from_be_bytes(ip.octets());
        self.entries
            .iter()
            .filter(|e| ip >= e.range.start && ip <= e.range.end)
            .max_by_key(|e| e.prefix)
    }

    pub fn load_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let text = match crate::util::decrypt(&raw) {
            Ok(plain) => String::from_utf8(plain).context("decrypted blacklist is not utf-8")?,
            Err(_) => String::from_utf8(raw).context("blacklist file is not utf-8")?,
        };
        self.merge(parse_blacklist_text(&text)?);
        Ok(())
    }

    pub fn add_cidr(&mut self, cidr: &str) -> anyhow::Result<()> {
        let (prefix, range) = parse_cidr(cidr)?;
        if self.entries.iter().any(|e| e.range == range) {
            return Ok(());
        }
        self.entries.push(BlacklistEntry {
            label: cidr.to_string(),
            prefix,
            range,
        });
        self.sort_dedup();
        Ok(())
    }

    pub fn remove_cidr(&mut self, cidr: &str) -> anyhow::Result<()> {
        let (_, range) = parse_cidr(cidr)?;
        self.entries.retain(|e| e.range != range);
        Ok(())
    }

    pub fn merge(&mut self, mut more: Vec<BlacklistEntry>) {
        self.entries.append(&mut more);
        self.sort_dedup();
    }

    pub fn sort_dedup(&mut self) {
        self.entries.sort_by_key(|e| e.range.start);
        self.entries.dedup_by_key(|e| e.range);
    }

    pub fn sync_to_ebpf(
        &self,
        ebpf: &mut aya::Ebpf,
        dry_run: bool,
        tcp: bool,
        udp: bool,
    ) -> anyhow::Result<()> {
        if self.entries.len() > MAX_BLACKLIST_RANGES as usize {
            anyhow::bail!(
                "blacklist has {} ranges, max {}",
                self.entries.len(),
                MAX_BLACKLIST_RANGES
            );
        }

        {
            let mut trie: LpmTrie<_, u32, u32> =
                LpmTrie::try_from(ebpf.map_mut("BLACKLIST").unwrap())?;
            for (i, entry) in self.entries.iter().enumerate() {
                let key = Key::new(entry.prefix as u32, entry.range.start.to_be());
                trie.insert(&key, i as u32, 0)?;
            }
        }
        {
            let mut hits: Array<_, u64> = Array::try_from(ebpf.map_mut("BLACKLIST_HITS").unwrap())?;
            for i in 0..self.entries.len() {
                hits.set(i as u32, 0, 0)?;
            }
        }
        {
            let mut dry: Array<_, u8> = Array::try_from(ebpf.map_mut("DRY_RUN").unwrap())?;
            dry.set(0, u8::from(dry_run), 0)?;
        }
        {
            let config = IpBlacklistConfig {
                tcp_enabled: u8::from(tcp),
                udp_enabled: u8::from(udp),
            };
            let mut cfg: Array<_, IpBlacklistConfig> =
                Array::try_from(ebpf.map_mut("BLACKLIST_CONFIG").unwrap())?;
            cfg.set(0, config, 0)?;
        }
        Ok(())
    }

    pub fn dump_hits(&self, ebpf: &mut aya::Ebpf, output: &Path) -> anyhow::Result<()> {
        let counts: Vec<u64> = {
            let hits: Array<_, u64> = Array::try_from(ebpf.map_mut("BLACKLIST_HITS").unwrap())?;
            (0..self.entries.len())
                .map(|i| {
                    let idx = i as u32;
                    hits.get(&idx, 0).unwrap_or(0)
                })
                .collect()
        };
        {
            let mut hits: Array<_, u64> = Array::try_from(ebpf.map_mut("BLACKLIST_HITS").unwrap())?;
            for i in 0..self.entries.len() {
                hits.set(i as u32, 0, 0)?;
            }
        }

        let mut lines: Vec<String> = self
            .entries
            .iter()
            .zip(counts)
            .filter(|(_, count)| *count > 0)
            .map(|(entry, count)| format!("{} {}", entry.label, count))
            .collect();
        lines.sort();
        let body = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        fs::write(output, body).with_context(|| format!("write {}", output.display()))?;
        Ok(())
    }
}

/// IPv4 address encoded for BPF `LPM_TRIE` key `data` (network byte order in memory).
pub fn lpm_ip_word(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets()).to_be()
}

/// IPv4 address encoded for BPF `LPM_TRIE` lookup from a packet field (`read_be_u32`).
pub fn lpm_ip_word_raw(ip: u32) -> u32 {
    ip.to_be()
}

fn parse_blacklist_text(text: &str) -> anyhow::Result<Vec<BlacklistEntry>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let range = parse_cidr(line)?;
        out.push(BlacklistEntry {
            label: line.to_string(),
            prefix: range.0,
            range: range.1,
        });
    }
    out.sort_by_key(|e| e.range.start);
    out.dedup_by_key(|e| e.range);
    Ok(out)
}

fn parse_cidr(cidr: &str) -> anyhow::Result<(u8, Ipv4Range)> {
    let (addr, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("invalid CIDR {cidr}"))?;
    let ip: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid IPv4 in {cidr}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {cidr}"))?;
    if prefix > 32 {
        anyhow::bail!("invalid prefix in {cidr}");
    }
    Ok((prefix, cidr_to_range(ip, prefix)))
}

fn cidr_to_range(ip: Ipv4Addr, prefix: u8) -> Ipv4Range {
    let ip = u32::from_be_bytes(ip.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Range {
        start: ip & mask,
        end: ip | !mask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_slash13() {
        let (prefix, r) = parse_cidr("1.24.0.0/13").unwrap();
        assert_eq!(prefix, 13);
        assert_eq!(r.start, u32::from_be_bytes([1, 24, 0, 0]));
        assert_eq!(r.end, u32::from_be_bytes([1, 31, 255, 255]));
    }

    #[test]
    fn parse_plaintext_file() {
        let text = "1.24.0.0/13\n# comment\n\n1.45.0.0/16\n";
        let ranges = parse_blacklist_text(text).unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(ranges[0].range.start < ranges[1].range.start);
    }

    #[test]
    fn add_remove_cidr() {
        let mut bl = Blacklist::new();
        bl.add_cidr("10.0.0.0/8").unwrap();
        bl.add_cidr("192.168.1.0/24").unwrap();
        assert_eq!(bl.len(), 2);
        bl.remove_cidr("10.0.0.0/8").unwrap();
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn lpm_ip_word_network_byte_order() {
        let ip: Ipv4Addr = "180.130.78.185".parse().unwrap();
        assert_eq!(lpm_ip_word(ip).to_le_bytes(), [180, 130, 78, 185]);
    }

    #[test]
    fn leaked_ips_hit_userspace() {
        let mut bl = Blacklist::new();
        bl.load_file(std::path::Path::new("../unicom_non_sichuan_merged.txt"))
            .unwrap();
        for ip in [
            "180.130.78.185",
            "101.24.105.174",
            "114.247.175.248",
            "112.65.12.14",
        ] {
            assert!(bl.is_hit(ip.parse().unwrap()), "missed {ip}");
        }
    }

    #[test]
    fn stun_binding_request_rfc5389() {
        let mut pkt = vec![0u8; 20];
        pkt[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        assert!(is_stun_binding_request(&pkt, 50000, 3478));
    }

    #[test]
    fn stun_binding_request_rfc3489() {
        let mut pkt = vec![0u8; 20];
        pkt[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&0x01020304u32.to_be_bytes());
        assert!(is_stun_binding_request(&pkt, 3478, 50000));
        assert!(!is_stun_binding_request(&pkt, 50000, 50001));
    }

    #[test]
    fn stun_binding_success_response_rfc5389() {
        let mut pkt = vec![0u8; 20];
        pkt[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        assert!(is_stun_binding_message(&pkt, 3478, 50000));
    }
}

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context as _};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tokio::signal;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0;
const MAX_SNI_LEN: usize = 253;

pub async fn run(args: super::TlsSniCaptureArgs) -> anyhow::Result<()> {
    let interfaces = select_interfaces(args.interface.as_deref())?;
    let names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();
    let local_addrs = local_ipv4_addrs(&interfaces);
    if local_addrs.is_empty() {
        bail!("no IPv4 address on selected interface(s); cannot filter egress traffic");
    }

    let agg = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for iface in interfaces {
        let agg = Arc::clone(&agg);
        let stop = Arc::clone(&stop);
        let addrs = local_addrs.clone();
        handles.push(thread::spawn(move || capture_on_interface(iface, agg, stop, addrs)));
    }

    log::info!(
        "tls-sni-capture on [{}] ({} local IPv4, write {} every {}s); Ctrl+C to stop",
        names.join(", "),
        local_addrs.len(),
        args.output.display(),
        args.duration
    );

    let output = args.output.clone();
    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => write_sni_counts(&agg, &output)?,
            res = signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }

    stop.store(true, Ordering::SeqCst);
    for handle in handles {
        let _ = handle.join();
    }
    write_sni_counts(&agg, &output)?;

    Ok(())
}

fn select_interfaces(name: Option<&str>) -> anyhow::Result<Vec<NetworkInterface>> {
    let all = datalink::interfaces();
    if let Some(name) = name {
        let found: Vec<_> = all.into_iter().filter(|i| i.name == name).collect();
        if found.is_empty() {
            bail!("network interface not found: {name}");
        }
        return Ok(found);
    }

    let selected: Vec<_> = all.into_iter().filter(|i| i.is_up()).collect();
    if selected.is_empty() {
        bail!("no active network interface found; pass --interface");
    }
    Ok(selected)
}

fn local_ipv4_addrs(interfaces: &[NetworkInterface]) -> HashSet<Ipv4Addr> {
    interfaces
        .iter()
        .flat_map(|iface| iface.ips.iter())
        .filter_map(|net| match net.ip() {
            std::net::IpAddr::V4(addr) => Some(addr),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

fn capture_on_interface(
    iface: NetworkInterface,
    agg: Arc<Mutex<HashMap<String, u64>>>,
    stop: Arc<AtomicBool>,
    local_addrs: HashSet<Ipv4Addr>,
) {
    let config = Config {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };

    let Ok(Channel::Ethernet(_tx, mut rx)) = datalink::channel(&iface, config) else {
        log::error!("unsupported datalink channel type on {}", iface.name);
        return;
    };

    while !stop.load(Ordering::SeqCst) {
        let packet = match rx.next() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if let Some(sni) = parse_tls_sni_record(packet, &local_addrs) {
            if let Ok(mut map) = agg.lock() {
                *map.entry(sni).or_insert(0) += 1;
            }
        }
    }
}

fn parse_tls_sni_record(packet: &[u8], local_addrs: &HashSet<Ipv4Addr>) -> Option<String> {
    let eth = EthernetPacket::new(packet)?;
    let (src_ip, tcp_payload) = ipv4_tcp_payload_from_l2(eth.get_ethertype(), eth.payload())?;
    if !local_addrs.contains(&src_ip) {
        return None;
    }
    parse_tls_sni(tcp_payload)
}

fn ipv4_tcp_payload_from_l2(
    mut ethertype: pnet::packet::ethernet::EtherType,
    mut payload: &[u8],
) -> Option<(Ipv4Addr, &[u8])> {
    if ethertype == EtherTypes::Vlan {
        if payload.len() < 4 {
            return None;
        }
        ethertype = pnet::packet::ethernet::EtherType::new(u16::from_be_bytes([
            payload[2],
            payload[3],
        ]));
        payload = &payload[4..];
    }

    if ethertype != EtherTypes::Ipv4 {
        return None;
    }

    let ip = Ipv4Packet::new(payload)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let src_ip = ip.get_source();
    let ip_hdr_len = (ip.get_header_length() as usize) * 4;
    let l4 = &payload[ip_hdr_len..];
    let tcp = TcpPacket::new(l4)?;
    let tcp_hdr_len = (tcp.get_data_offset() as usize) * 4;
    if tcp_hdr_len < 20 || l4.len() < tcp_hdr_len {
        return None;
    }
    Some((src_ip, &l4[tcp_hdr_len..]))
}

fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 43 || payload[0] != TLS_HANDSHAKE || payload[1] != 0x03 {
        return None;
    }

    let hs_off = 5;
    if payload[hs_off] != TLS_CLIENT_HELLO {
        return None;
    }

    let mut off = hs_off + 4 + 34;

    let session_id_len = *payload.get(off)? as usize;
    off += 1;
    if off + session_id_len > payload.len() {
        return None;
    }
    off += session_id_len;

    let cipher_len = u16::from_be_bytes([*payload.get(off)?, *payload.get(off + 1)?]) as usize;
    off += 2;
    if off + cipher_len > payload.len() {
        return None;
    }
    off += cipher_len;

    let comp_len = *payload.get(off)? as usize;
    off += 1;
    if off + comp_len > payload.len() {
        return None;
    }
    off += comp_len;

    let ext_total_len = u16::from_be_bytes([*payload.get(off)?, *payload.get(off + 1)?]) as usize;
    off += 2;
    let ext_end = off + ext_total_len;
    if ext_end > payload.len() {
        return None;
    }

    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[off], payload[off + 1]]);
        let ext_len = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
        off += 4;
        if off + ext_len > ext_end {
            break;
        }
        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_sni_extension(&payload[off..off + ext_len]);
        }
        off += ext_len;
    }
    None
}

fn parse_sni_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if list_len < 3 || list_len > ext.len() {
        return None;
    }
    let mut off = 2;
    let list_end = off + list_len;
    if off + 3 > list_end {
        return None;
    }
    if ext[off] != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([ext[off + 1], ext[off + 2]]) as usize;
    off += 3;
    if name_len == 0 || name_len > MAX_SNI_LEN || off + name_len > list_end {
        return None;
    }
    Some(String::from_utf8_lossy(&ext[off..off + name_len]).into_owned())
}

fn write_sni_counts(agg: &Arc<Mutex<HashMap<String, u64>>>, path: &Path) -> anyhow::Result<()> {
    let map = agg
        .lock()
        .map_err(|_| anyhow::anyhow!("tls-sni-capture aggregation lock poisoned"))?;

    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut out = String::new();
    for (sni, count) in &entries {
        out.push_str(sni);
        out.push(' ');
        out.push_str(&count.to_string());
        out.push('\n');
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create output dir {}", parent.display()))?;
        }
    }
    fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    log::debug!("wrote {} SNI entries to {}", entries.len(), path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        let ext_data_len = 2 + sni_list_len;
        let ext_len = 4 + ext_data_len;
        let comp_len = 1usize;
        let cipher_len = 2usize;
        let session_id_len = 0usize;
        let hs_body_len = 2 + 32 + 1 + session_id_len + 2 + cipher_len + 1 + comp_len + 2 + ext_len;
        let hs_len = 1 + 3 + hs_body_len;
        let record_len = hs_len;

        let mut out = Vec::new();
        out.push(TLS_HANDSHAKE);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&(record_len as u16).to_be_bytes());
        out.push(TLS_CLIENT_HELLO);
        out.extend_from_slice(&(hs_body_len as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&[0u8; 32]);
        out.push(session_id_len as u8);
        out.extend_from_slice(&[0x00, 0x02]);
        out.extend_from_slice(&[0x00, 0x35]);
        out.push(comp_len as u8);
        out.push(0);
        out.extend_from_slice(&(ext_len as u16).to_be_bytes());
        out.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        out.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        out.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        out.push(0);
        out.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(sni_bytes);
        out
    }

    #[test]
    fn parse_tls_sni_from_client_hello() {
        let payload = build_client_hello("example.com");
        assert_eq!(parse_tls_sni(&payload).as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_sni_extension_rejects_empty() {
        assert!(parse_sni_extension(&[0, 3, 0, 0, 0]).is_none());
    }
}

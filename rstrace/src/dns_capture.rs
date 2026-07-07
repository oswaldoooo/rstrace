use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::signal;

const DNS_PORT: u16 = 53;

#[derive(Clone, Hash, Eq, PartialEq)]
struct RecordKey {
    domain: String,
    qtype: u16,
}

pub async fn run(args: super::DnsCaptureArgs) -> anyhow::Result<()> {
    let interfaces = select_interfaces(args.interface.as_deref())?;
    let names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();

    let agg = Arc::new(Mutex::new(HashMap::<RecordKey, u64>::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for iface in interfaces {
        let agg = Arc::clone(&agg);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || capture_on_interface(iface, agg, stop)));
    }

    log::info!(
        "dns_capture on [{}] (sync every {}s); press Ctrl+C to stop",
        names.join(", "),
        args.duration
    );

    let interval = Duration::from_secs(args.duration);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => flush_records(&agg)?,
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
    flush_records(&agg)?;

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

fn capture_on_interface(
    iface: NetworkInterface,
    agg: Arc<Mutex<HashMap<RecordKey, u64>>>,
    stop: Arc<AtomicBool>,
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

        if let Some(record) = parse_dns_record(packet) {
            if let Ok(mut map) = agg.lock() {
                *map.entry(record).or_insert(0) += 1;
            }
        }
    }
}

fn parse_dns_record(packet: &[u8]) -> Option<RecordKey> {
    let eth = EthernetPacket::new(packet)?;
    let l2_payload = eth.payload();
    let ip_payload = ip_payload_from_l2(eth.get_ethertype(), l2_payload)?;
    let udp = UdpPacket::new(ip_payload)?;
    if udp.get_destination() != DNS_PORT {
        return None;
    }
    let udp_payload = udp.payload();
    let dns_start = packet.len().saturating_sub(udp_payload.len());
    let (domain, qtype) = parse_dns_query(&packet[dns_start..])?;
    Some(RecordKey { domain, qtype })
}

fn ip_payload_from_l2(
    mut ethertype: pnet::packet::ethernet::EtherType,
    mut payload: &[u8],
) -> Option<&[u8]> {
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

    match ethertype {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(payload)?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let ip_hdr_len = (ip.get_header_length() as usize) * 4;
            Some(&payload[ip_hdr_len..])
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(payload)?;
            if ip.get_next_header() != IpNextHeaderProtocols::Udp {
                return None;
            }
            Some(&payload[40..])
        }
        _ => None,
    }
}

fn parse_dns_query(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12usize;
    let domain = parse_qname(payload, &mut offset)?;
    if offset + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Some((domain, qtype))
}

fn parse_qname(pkt: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    for _ in 0..32 {
        if *offset >= pkt.len() {
            return None;
        }
        let len = pkt[*offset] as usize;
        *offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 || *offset + len > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[*offset..*offset + len]).into_owned());
        *offset += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn flush_records(agg: &Arc<Mutex<HashMap<RecordKey, u64>>>) -> anyhow::Result<()> {
    let mut map = agg
        .lock()
        .map_err(|_| anyhow::anyhow!("dns_capture aggregation lock poisoned"))?;
    if map.is_empty() {
        return Ok(());
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    let entries: Vec<(RecordKey, u64)> = map.drain().collect();
    for (key, _count) in entries {
        println!("{} {} {ts}", key.domain, qtype_name(key.qtype));
    }
    Ok(())
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        n => format!("TYPE{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_query_a() {
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let (domain, qtype) = parse_dns_query(&pkt).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
        pkt[2] = 0x80;
        assert!(parse_dns_query(&pkt).is_none());
    }
}

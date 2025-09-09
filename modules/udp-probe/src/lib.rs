//! Minimal UDP probes: DNS and NTP.

use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub enum UdpService { Dns, Ntp, Snmp }

pub async fn probe_dns(host: &str, timeout_ms: u64) -> Result<Option<String>> {
    let addr = resolve_first(&(host.to_string() + ":53"))?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let q = build_dns_query();
    timeout(Duration::from_millis(timeout_ms), sock.send_to(&q, addr)).await??;
    let mut buf = [0u8; 512];
    let (n, _) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await??;
    // very light parse: verify QR bit is set in flags
    if n >= 3 && (buf[2] & 0x80) != 0 { Ok(Some(format!("dns: {} bytes", n))) } else { Ok(None) }
}

pub async fn probe_ntp(host: &str, timeout_ms: u64) -> Result<Option<String>> {
    let addr = resolve_first(&(host.to_string() + ":123"))?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut pkt = [0u8; 48];
    pkt[0] = 0b00_100_011; // LI=0, VN=4, Mode=3 (client)
    timeout(Duration::from_millis(timeout_ms), sock.send_to(&pkt, addr)).await??;
    let mut buf = [0u8; 48];
    let (n, _) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await??;
    if n >= 48 { Ok(Some("ntp: reply".into())) } else { Ok(None) }
}

fn resolve_first(addr: &str) -> Result<SocketAddr> {
    let mut it = addr.to_socket_addrs()?;
    it.next().ok_or_else(|| anyhow::anyhow!("failed to resolve: {}", addr))
}

fn build_dns_query() -> Vec<u8> {
    // Simple DNS query for A record of example.com
    let mut q = Vec::new();
    q.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for part in ["example", "com"] {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.push(0); // end name
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q
}

/// Probe SNMP v2c sysDescr.0 with community "public" and return the string if present.
pub async fn probe_snmp_sysdescr(host: &str, community: &str, timeout_ms: u64) -> Result<Option<String>> {
    let addr = resolve_first(&(host.to_string() + ":161"))?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let pkt = build_snmp_get(community, &[1,3,6,1,2,1,1,1,0]);
    timeout(Duration::from_millis(timeout_ms), sock.send_to(&pkt, addr)).await??;
    let mut buf = [0u8; 1500];
    let (n, _) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await??;
    if let Some(s) = parse_snmp_sysdescr(&buf[..n]) { Ok(Some(s)) } else { Ok(None) }
}

fn build_snmp_get(community: &str, oid: &[u32]) -> Vec<u8> {
    // Minimal ASN.1/BER encoding for SNMP v2c GetRequest for one OID.
    // This is a simplistic encoder sufficient for sysDescr.0.
    let mut varbind = Vec::new();
    // Sequence (OID, NULL)
    let mut vb_seq = Vec::new();
    // OID
    vb_seq.push(0x06); // OBJECT IDENTIFIER
    let oid_enc = encode_oid(oid);
    vb_seq.push(oid_enc.len() as u8);
    vb_seq.extend_from_slice(&oid_enc);
    // NULL value
    vb_seq.push(0x05);
    vb_seq.push(0x00);
    // Wrap varbind sequence
    varbind.push(0x30);
    varbind.push(vb_seq.len() as u8);
    varbind.extend_from_slice(&vb_seq);

    // VarBindList sequence
    let mut vbl = Vec::new();
    vbl.push(0x30);
    vbl.push(varbind.len() as u8);
    vbl.extend_from_slice(&varbind);

    // GetRequest-PDU tag = 0xA0
    let mut pdu = Vec::new();
    // request-id INTEGER 1
    pdu.extend_from_slice(&[0x02, 0x01, 0x01]);
    // error-status INTEGER 0
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
    // error-index INTEGER 0
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
    // varbind list
    pdu.extend_from_slice(&vbl);
    let mut pdu_wrap = Vec::new();
    pdu_wrap.push(0xA0);
    pdu_wrap.push(pdu.len() as u8);
    pdu_wrap.extend_from_slice(&pdu);

    // Community string
    let mut comm = Vec::new();
    comm.push(0x04); // OCTET STRING
    comm.push(community.len() as u8);
    comm.extend_from_slice(community.as_bytes());

    // Version (v2c = 1)
    let ver = [0x02, 0x01, 0x01];

    // SNMP message sequence
    let mut msg_inner = Vec::new();
    msg_inner.extend_from_slice(&ver);
    msg_inner.extend_from_slice(&comm);
    msg_inner.extend_from_slice(&pdu_wrap);
    let mut msg = Vec::new();
    msg.push(0x30);
    msg.push(msg_inner.len() as u8);
    msg.extend_from_slice(&msg_inner);
    msg
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if oid.len() >= 2 {
        out.push((oid[0] * 40 + oid[1]) as u8);
        for &arc in &oid[2..] { out.extend_from_slice(&encode_base128(arc)); }
    }
    out
}

fn encode_base128(mut v: u32) -> Vec<u8> {
    let mut tmp = [0u8; 5];
    let mut i = 5;
    tmp[i-1] = (v & 0x7F) as u8; i -= 1; v >>= 7;
    while v > 0 { tmp[i-1] = ((v & 0x7F) as u8) | 0x80; i -= 1; v >>= 7; }
    tmp[i..].to_vec()
}

fn parse_snmp_sysdescr(data: &[u8]) -> Option<String> {
    // Very light parse: look for OCTET STRING after sysDescr OID in the response varbind.
    // A robust parser would use full BER decoding; here we search for 0x04 (OCTET STRING) and collect bytes.
    // This may produce false positives for malformed packets but is fine for a simple probe.
    // Scan for 0x04 and take following length and bytes if plausible.
    let mut i = 0usize;
    while i + 2 < data.len() {
        if data[i] == 0x04 { // OCTET STRING
            let len = data[i+1] as usize;
            if i + 2 + len <= data.len() {
                let s = String::from_utf8_lossy(&data[i+2..i+2+len]).to_string();
                if !s.is_empty() { return Some(s); }
            }
        }
        i += 1;
    }
    None
}

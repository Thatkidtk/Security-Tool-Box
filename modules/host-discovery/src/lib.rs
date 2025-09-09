//! Host discovery via TCP connect sweep with timeouts and pacing.

use anyhow::Result;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, MissedTickBehavior};

/// Expand a CIDR into IP addresses.
pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let net: IpNet = cidr.parse()?;
    let mut ips = Vec::new();
    for ip in net.hosts() {
        ips.push(ip);
    }
    Ok(ips)
}

/// Resolve a hostname to a single IP address (best-effort).
pub fn resolve_host_best_effort(host: &str) -> IpAddr {
    if let Ok(mut it) = (host, 0u16).to_socket_addrs() { if let Some(sa) = it.next() { return sa.ip(); } }
    host.parse().unwrap_or_else(|_| IpAddr::from([0,0,0,0]))
}

/// TCP-based liveness check: attempt to connect to given ports; if any succeed within timeout, host is live.
pub async fn is_host_live(ip: IpAddr, ports: &[u16], per_attempt: Duration) -> bool {
    for &p in ports {
        let addr = SocketAddr::new(ip, p);
        if let Ok(Ok(_)) = timeout(per_attempt, TcpStream::connect(addr)).await { return true; }
    }
    false
}

/// Discover live hosts among a set of IPs using TCP connect attempts with concurrency and QPS pacing.
pub async fn discover_hosts(
    ips: Vec<IpAddr>,
    ports: &[u16],
    timeout_per_attempt: Duration,
    concurrency: usize,
    qps: Option<u32>,
) -> Vec<IpAddr> {
    let (tx, mut rx) = mpsc::channel::<IpAddr>(ips.len());
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut ticker = if let Some(q) = qps { let mut it = interval(Duration::from_millis((1000u32 / q.max(1)) as u64)); it.set_missed_tick_behavior(MissedTickBehavior::Delay); Some(it) } else { None };

    for ip in ips {
        if let Some(t) = ticker.as_mut() { t.tick().await; }
        let txc = tx.clone();
        let permit = sem.clone().acquire_owned().await.unwrap();
        let p = ports.to_vec();
        tokio::spawn(async move {
            if is_host_live(ip, &p, timeout_per_attempt).await { let _ = txc.send(ip).await; }
            drop(permit);
        });
    }
    drop(tx);
    let mut live = Vec::new();
    while let Some(ip) = rx.recv().await { live.push(ip); }
    live
}

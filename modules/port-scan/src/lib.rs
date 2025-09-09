//! TCP connect scan with timeouts and concurrency.

use anyhow::{anyhow, Result};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use toolbox_core::Target;
use toolbox_core::ratelimiter::RateLimiter;
use rand::{thread_rng, Rng};

/// Parse a comma-separated list of ports/ranges (e.g., "22,80,443", "1-1024,8080").
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse()?;
            let e: u16 = end.parse()?;
            if s == 0 || e == 0 || s > e {
                return Err(anyhow!("invalid port range: {}", part));
            }
            ports.extend(s..=e);
        } else {
            let p: u16 = part.parse()?;
            if p == 0 {
                return Err(anyhow!("invalid port: {}", part));
            }
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Default commonly-used ports if none are specified.
pub fn default_top_ports() -> Vec<u16> { top_ports(64) }

/// Return the first N ports from a curated list of commonly-used ports.
pub fn top_ports(n: usize) -> Vec<u16> {
    const CURATED: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 465, 500, 587, 636, 993,
        995, 1080, 1194, 1352, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3128, 3268, 3306, 3389,
        4444, 4500, 5000, 5060, 5432, 5601, 5671, 5672, 5900, 5985, 5986, 6379, 7001, 7002, 8000,
        8080, 8081, 8200, 8443, 8500, 8530, 8888, 9000, 9092, 9200, 9300, 9418, 9999, 10000,
        11211, 15672, 27017,
    ];
    let take = n.min(CURATED.len());
    CURATED[..take].to_vec()
}

/// Asynchronously scan the given ports on a target using TCP connect with a timeout.
/// Returns the list of open ports (sorted ascending).
pub async fn scan_connect_with_limits(
    target: &str,
    ports: &[u16],
    timeout_per_port: Duration,
    per_host_concurrency: usize,
    dns_retries: u32,
    dns_retry_delay: Duration,
    global_qps: Option<Arc<RateLimiter>>,
    retries: u32,
    retry_delay: Duration,
    global_limit: Option<Arc<Semaphore>>,
) -> Vec<u16> {
    let t: Target = target.into();

    let host = resolve_best_effort(&t.0, dns_retries, dns_retry_delay);

    let host_sem = Arc::new(Semaphore::new(per_host_concurrency.max(1)));
    let (tx, mut rx) = mpsc::channel::<u16>(ports.len());

    for &port in ports {
        let tx = tx.clone();
        let host = host.clone();
        let host_sem = host_sem.clone();
        let global = global_limit.clone();
        let qps_rl = global_qps.clone();
        tokio::spawn(async move {
            let _host_permit = host_sem.acquire_owned().await.unwrap();
            let _global_permit = match global {
                Some(g) => Some(g.acquire_owned().await.unwrap()),
                None => None,
            };
            if let Some(q) = qps_rl { q.acquire().await; }
            let addr = (host.as_str(), port);
            let mut attempts = 0;
            let mut opened = false;
            while attempts <= retries {
                let result = timeout(timeout_per_port, TcpStream::connect(addr)).await;
                if let Ok(Ok(_stream)) = result { opened = true; break; }
                attempts += 1;
                if attempts <= retries {
                    let base = retry_delay.as_millis() as u64;
                    let exp = base.saturating_mul(1u64 << (attempts.min(6))); // cap growth
                    let jitter = thread_rng().gen_range(0..(exp / 4 + 1));
                    tokio::time::sleep(Duration::from_millis(exp + jitter)).await;
                }
            }
            if opened { let _ = tx.send(port).await; }
        });
    }
    drop(tx);

    let mut open = Vec::new();
    while let Some(p) = rx.recv().await {
        open.push(p);
    }
    open.sort_unstable();
    open
}

/// Backwards-compatible wrapper: scan with only per-host concurrency, no DNS retries.
pub async fn scan_connect(
    target: &str,
    ports: &[u16],
    timeout_per_port: Duration,
    concurrency: usize,
) -> Vec<u16> {
    scan_connect_with_limits(target, ports, timeout_per_port, concurrency, 0, Duration::from_millis(0), None, 0, Duration::from_millis(0), None).await
}

/// Resolve a host once with limited retries. Returns an IP string on success, or the original
/// input if resolution fails.
pub fn resolve_best_effort(host: &str, dns_retries: u32, retry_delay: Duration) -> String {
    let attempts = dns_retries.saturating_add(1);
    for i in 0..attempts {
        if let Ok(mut iter) = (host, 0u16).to_socket_addrs() {
            if let Some(sock) = iter.next() {
                return sock.ip().to_string();
            }
        }
        if i + 1 < attempts && retry_delay.as_millis() > 0 {
            std::thread::sleep(retry_delay);
        }
    }
    host.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_list() {
        let v = parse_ports("22,80,443").unwrap();
        assert_eq!(v, vec![22, 80, 443]);
    }

    #[test]
    fn parse_ranges_and_list() {
        let v = parse_ports("1-3,5,3").unwrap();
        assert_eq!(v, vec![1, 2, 3, 5]);
    }

    #[test]
    fn reject_invalid() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("10-5").is_err());
    }
}

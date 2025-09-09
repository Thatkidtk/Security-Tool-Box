//! Simple banner grabbing for HTTP, HTTPS (with ALPN), and SSH.

use anyhow::Result;
use rustls::ClientConfig;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Debug, Clone)]
pub struct Banner {
    pub protocol: String,
    pub port: u16,
    pub summary: String,
}

async fn http_head_raw(host: &str, port: u16, path: &str, timeout_ms: u64) -> Result<String> {
    let addr = resolve_first(host, port)?;
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;
    let req = format!("HEAD {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: toolbox/0.1\r\nConnection: close\r\n\r\n", path, host);
    timeout(Duration::from_millis(timeout_ms), stream.write_all(req.as_bytes())).await??;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await??;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

pub async fn grab_http(host: &str, port: u16, timeout_ms: u64) -> Result<Banner> {
    let text = http_head_raw(host, port, "/", timeout_ms).await?;
    let mut first = String::new();
    let mut server = String::new();
    let mut location = String::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { first = line.to_string(); }
        if line.to_lowercase().starts_with("server:") { server = line.to_string(); }
        if line.to_lowercase().starts_with("location:") { location = line[9..].trim().to_string(); }
        if i > 10 { break; }
    }
    let mut summary = if !server.is_empty() { format!("{} | {}", first, server) } else { first };
    if !location.is_empty() { summary = format!("{} | redirect-> {}", summary, location); }
    Ok(Banner { protocol: "http".into(), port, summary })
}

pub async fn grab_http_follow_one(host: &str, port: u16, timeout_ms: u64) -> Result<Banner> {
    let text = http_head_raw(host, port, "/", timeout_ms).await?;
    let mut first = String::new();
    let mut location = String::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { first = line.to_string(); }
        if line.to_lowercase().starts_with("location:") { location = line[9..].trim().to_string(); }
        if i > 10 { break; }
    }
    if !location.is_empty() && first.contains(" 3") {
        if let Ok(url) = Url::parse(&location) {
            let (h, p, https) = match url.scheme() {
                "https" => (url.host_str().unwrap_or(host), url.port().unwrap_or(443), true),
                _ => (url.host_str().unwrap_or(host), url.port().unwrap_or(80), false),
            };
            let b = if https { grab_https(h, p, timeout_ms, true).await? } else { grab_http(h, p, timeout_ms).await? };
            return Ok(Banner { protocol: b.protocol, port: b.port, summary: format!("{} -> {}", first, b.summary) });
        }
    }
    grab_http(host, port, timeout_ms).await
}

pub async fn grab_https(host: &str, port: u16, timeout_ms: u64, cn_only: bool) -> Result<Banner> {
    // Ensure a crypto provider is installed (ring)
    let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let addr = resolve_first(host, port)?;
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| anyhow::anyhow!("invalid server name"))?,
    };
    let mut tls = timeout(Duration::from_millis(timeout_ms), connector.connect(server_name, stream)).await??;

    let req = format!(
        "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: toolbox/0.1\r\nConnection: close\r\n\r\n",
        host
    );
    timeout(Duration::from_millis(timeout_ms), tls.write_all(req.as_bytes())).await??;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_millis(timeout_ms), tls.read(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf[..n]);
    let mut first = String::new();
    let mut server = String::new();
    let mut location = String::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { first = line.to_string(); }
        if line.to_lowercase().starts_with("server:") { server = line.to_string(); }
        if line.to_lowercase().starts_with("location:") { location = line[9..].trim().to_string(); }
        if i > 10 { break; }
    }
    let alpn = tls.get_ref().1.alpn_protocol().map(|v| String::from_utf8_lossy(v).to_string()).unwrap_or_default();
    // Try to extract cert subject/issuer
    let mut cert_info = String::new();
    if let Some(certs) = tls.get_ref().1.peer_certificates() {
        if let Some(end_entity) = certs.first() {
            use x509_parser::prelude::*;
            if let Ok((_, x509)) = X509Certificate::from_der(end_entity.as_ref()) {
                if cn_only {
                    let subj_cn = x509.subject().iter_common_name().next().and_then(|cn| cn.as_str().ok()).unwrap_or("");
                    let iss_cn = x509.issuer().iter_common_name().next().and_then(|cn| cn.as_str().ok()).unwrap_or("");
                    if !subj_cn.is_empty() && !iss_cn.is_empty() {
                        cert_info = format!(" | cert_cn={} / issuer_cn={}", subj_cn, iss_cn);
                    }
                } else {
                    cert_info = format!(" | cert={} / {}", x509.subject(), x509.issuer());
                }
            }
        }
    }
    let mut summary = if !alpn.is_empty() {
        if !server.is_empty() { format!("{} | {} | alpn={}", first, server, alpn) } else { format!("{} | alpn={}", first, alpn) }
    } else if !server.is_empty() { format!("{} | {}", first, server) } else { first };
    if !location.is_empty() { summary = format!("{} | redirect-> {}", summary, location); }
    if !cert_info.is_empty() { summary.push_str(&cert_info); }
    Ok(Banner { protocol: "https".into(), port, summary })
}

pub async fn grab_https_follow_one(host: &str, port: u16, timeout_ms: u64, cn_only: bool) -> Result<Banner> {
    // Reuse https logic, and follow one hop if present
    let b = grab_https(host, port, timeout_ms, cn_only).await?;
    if let Some(loc_start) = b.summary.find("redirect-> ") {
        let loc = b.summary[loc_start + 11..].trim();
        if let Ok(url) = Url::parse(loc) {
            let (h, p, https) = match url.scheme() {
                "https" => (url.host_str().unwrap_or(host), url.port().unwrap_or(443), true),
                _ => (url.host_str().unwrap_or(host), url.port().unwrap_or(80), false),
            };
            let nb = if https { grab_https(h, p, timeout_ms, cn_only).await? } else { grab_http(h, p, timeout_ms).await? };
            return Ok(Banner { protocol: nb.protocol, port: nb.port, summary: format!("{} -> {}", b.summary, nb.summary) });
        }
    }
    Ok(b)
}

pub async fn grab_ssh(host: &str, port: u16, timeout_ms: u64) -> Result<Banner> {
    let addr = resolve_first(host, port)?;
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;
    let mut buf = vec![0u8; 256];
    let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await??;
    let mut line = String::from_utf8_lossy(&buf[..n]).to_string();
    if let Some(idx) = line.find('\n') { line.truncate(idx); }
    Ok(Banner { protocol: "ssh".into(), port, summary: line })
}

fn resolve_first(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    let mut it = (host, port).to_socket_addrs()?;
    it.next().ok_or_else(|| anyhow::anyhow!("failed to resolve: {}", host))
}

/// Extract TLS certificate subject/issuer (best effort) from HTTPS handshake.
pub async fn tls_cert_subject_issuer(host: &str, port: u16, timeout_ms: u64) -> Result<Option<(String, String)>> {
    let addr = resolve_first(host, port)?;
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| anyhow::anyhow!("invalid server name"))?,
    };
    let tls = timeout(Duration::from_millis(timeout_ms), connector.connect(server_name, stream)).await??;
    let conn = tls.get_ref().1;
    if let Some(certs) = conn.peer_certificates() {
        if let Some(end_entity) = certs.first() {
            use x509_parser::prelude::*;
            if let Ok((_, x509)) = X509Certificate::from_der(end_entity.as_ref()) {
                let subj = x509
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .unwrap_or("")
                    .to_string();
                let iss = x509
                    .issuer()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .unwrap_or("")
                    .to_string();
                return Ok(Some((subj, iss)));
            }
        }
    }
    Ok(None)
}

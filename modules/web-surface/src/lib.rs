use anyhow::Result;
use reqwest::{Client, redirect::Policy, header::HeaderMap};
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

#[derive(Debug, Clone)]
pub struct WebProbeOptions {
    pub timeout_ms: u64,
    pub redirects: usize,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct WebResult {
    pub target: String,
    pub url: String,
    pub final_url: String,
    pub status: Option<u16>,
    pub server: Option<String>,
    pub title: Option<String>,
    pub fingerprints: Vec<String>,
    pub error: Option<String>,
}

pub async fn probe_many(targets: Vec<String>, ports: Vec<u16>, opts: WebProbeOptions, concurrency: usize) -> Vec<WebResult> {
    let sem = std::sync::Arc::new(Semaphore::new(concurrency.max(1)));
    let client = Client::builder()
        .redirect(Policy::limited(opts.redirects))
        .timeout(Duration::from_millis(opts.timeout_ms))
        .user_agent(opts.user_agent.clone())
        .brotli(true)
        .gzip(true)
        .deflate(true)
        .build()
        .expect("client");

    let mut handles = Vec::new();
    for t in targets {
        for &p in &ports {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let host = t.clone();
            handles.push(tokio::spawn(async move {
                let r = probe_one(&client, host.clone(), p).await;
                drop(permit);
                r
            }));
        }
    }
    let mut out = Vec::new();
    for h in handles { if let Ok(r) = h.await { out.push(r); } }
    out
}

async fn probe_one(client: &Client, host: String, port: u16) -> WebResult {
    let mut schemes = Vec::new();
    if port == 443 || port == 8443 || port == 9443 { schemes.push("https"); }
    if port == 80 || port == 8080 || port == 8000 { schemes.push("http"); }
    if schemes.is_empty() { schemes = vec!["https", "http"]; }

    for scheme in schemes {
        let url = format!("{}://{}:{}", scheme, host, port);
        match fetch_head(client, &url).await {
            Ok((final_url, status, server)) => {
                // Try small GET for title + fingerprints
                let (title, fps) = match fetch_page_info(client, &final_url).await {
                    Ok((t, f)) => (t, f),
                    Err(_) => (None, Vec::new()),
                };
                return WebResult { target: host, url, final_url, status: Some(status), server, title, fingerprints: fps, error: None };
            }
            Err(e) => {
                // Try next scheme
                if scheme == "http" {
                    return WebResult { target: host, url: url.clone(), final_url: url.clone(), status: None, server: None, title: None, fingerprints: Vec::new(), error: Some(e.to_string()) };
                }
            }
        }
    }
    WebResult { target: host.clone(), url: format!("https://{}:{}", host, port), final_url: format!("https://{}:{}", host, port), status: None, server: None, title: None, fingerprints: Vec::new(), error: Some("unreachable".into()) }
}

async fn fetch_head(client: &Client, url: &str) -> Result<(String, u16, Option<String>)> {
    let resp = client.head(url).send().await?;
    let status = resp.status().as_u16();
    let server = resp.headers().get(reqwest::header::SERVER).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let final_url = resp.url().to_string();
    Ok((final_url, status, server))
}

async fn fetch_page_info(client: &Client, url: &str) -> Result<(Option<String>, Vec<String>)> {
    let resp = client.get(url).send().await?;
    let headers = resp.headers().clone();
    let ct_is_html = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);
    let bytes = resp.bytes().await?;
    if bytes.len() > 128 * 1024 {
        // Still do header-based fingerprinting
        let fps = compute_fingerprints(&headers, None, "");
        return Ok((None, fps));
    }
    let body = String::from_utf8_lossy(&bytes);
    let title = if ct_is_html || body.to_lowercase().contains("<html") {
        extract_title(&body)
    } else { None };
    let fps = compute_fingerprints(&headers, title.as_deref(), &body);
    Ok((title, fps))
}

fn extract_title(body: &str) -> Option<String> {
    let start = body.to_lowercase().find("<title");
    if let Some(s) = start {
        let rest = &body[s..];
        let gt = rest.find('>')?;
        let after = &rest[gt+1..];
        let end = after.to_lowercase().find("</title>")?;
        let t = after[..end].trim();
        if !t.is_empty() { return Some(t.to_string()); }
    }
    None
}

fn compute_fingerprints(headers: &HeaderMap, title: Option<&str>, body: &str) -> Vec<String> {
    let mut fps = Vec::new();
    // Server and tech hints
    if let Some(v) = headers.get(reqwest::header::SERVER).and_then(|v| v.to_str().ok()) {
        let l = v.to_lowercase();
        if l.contains("nginx") { fps.push("server:nginx".into()); }
        if l.contains("apache") { fps.push("server:apache".into()); }
        if l.contains("iis") { fps.push("server:iis".into()); }
        if l.contains("cloudflare") { fps.push("cdn:cloudflare".into()); }
        if l.contains("caddy") { fps.push("server:caddy".into()); }
    }
    if let Some(v) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        let l = v.to_lowercase();
        if l.contains("php") { fps.push("lang:php".into()); }
        if l.contains("express") { fps.push("framework:express".into()); }
        if l.contains("asp.net") { fps.push("framework:aspnet".into()); }
        if l.contains("django") { fps.push("framework:django".into()); }
    }
    if headers.get("x-jenkins").is_some() { fps.push("product:jenkins".into()); }
    if headers.get("x-drupal-cache").is_some() { fps.push("cms:drupal".into()); }

    // Title hints
    if let Some(t) = title.map(|s| s.to_lowercase()) {
        if t.contains("index of /") { fps.push("feature:dir-listing".into()); }
        if t.contains("wordpress") { fps.push("cms:wordpress".into()); }
        if t.contains("grafana") { fps.push("product:grafana".into()); }
        if t.contains("kibana") { fps.push("product:kibana".into()); }
        if t.contains("jenkins") { fps.push("product:jenkins".into()); }
    }
    // Body hints (cheap substring checks)
    let bl = body.to_lowercase();
    if bl.contains("wp-content/") { fps.push("cms:wordpress".into()); }
    if bl.contains("joomla!") { fps.push("cms:joomla".into()); }
    if bl.contains("/sites/default/files") { fps.push("cms:drupal".into()); }
    if bl.contains("ng-app") { fps.push("js:angular".into()); }
    if bl.contains("react-dom") || bl.contains("data-reactroot") { fps.push("js:react".into()); }
    if bl.contains("__next_data__") { fps.push("framework:nextjs".into()); }
    if bl.contains("window._nuxt") { fps.push("framework:nuxt".into()); }
    fps.sort();
    fps.dedup();
    fps
}

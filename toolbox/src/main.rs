use anyhow::Result;
#[cfg(any(feature = "scan", feature = "discover", feature = "udp", feature = "banner"))]
use anyhow::anyhow;
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(any(feature = "scan", feature = "discover"))]
use std::fs::{File, OpenOptions};
#[cfg(any(feature = "scan", feature = "discover"))]
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;
#[cfg(any(feature = "scan", feature = "discover"))]
use tokio::sync::mpsc;
#[cfg(any(feature = "scan", feature = "discover"))]
use time::format_description::well_known::Rfc3339;
#[cfg(any(feature = "scan", feature = "discover"))]
use time::OffsetDateTime;

#[cfg(any(feature = "scan", feature = "discover"))]
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| String::new())
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat { Text, Json, Jsonl }

mod config;
#[cfg(feature = "webscan")]
fn modules_port_parse(spec: &str) -> anyhow::Result<Vec<u16>> { Ok(port_scan::parse_ports(spec)?) }

#[cfg(feature = "forensics")]
#[derive(Debug, Subcommand)]
enum ForensicsCmd {
    /// Compute hashes and basic type info for files (JSON lines)
    Hash { files: Vec<PathBuf> },
    /// Identify file type via magic/mime detection (JSON lines)
    Identify { files: Vec<PathBuf> },
}

#[cfg(feature = "creds")]
#[derive(Debug, Subcommand)]
enum CredsCmd {
    /// Detect hash kinds for input string(s) or a file
    Detect {
        /// Hash string(s)
        #[arg(long)]
        hash: Vec<String>,
        /// File with newline-delimited hashes
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Orchestrate external cracking tool (hashcat/john). Streams tool output.
    Crack {
        /// Tool name (e.g., hashcat or john)
        #[arg(long)]
        tool: String,
        /// Path to hashes file
        #[arg(long)]
        hashes: PathBuf,
        /// Path to wordlist file (optional)
        #[arg(long)]
        wordlist: Option<PathBuf>,
        /// Extra arguments passed to the tool (quoted)
        #[arg(long)]
        args: Option<String>,
    },
    /// Wordlist stats (total and unique)
    Wordlist {
        file: PathBuf,
    },
}

#[derive(Debug, Parser)]
#[command(name = "toolbox", version, about = "Unified Offensive Security Toolbox (scaffold)")]
struct Cli {
    /// Optional config file (YAML). If omitted, loads ./toolbox.yaml if present.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print version information
    Version,
    /// Run a demo port scan (stub)
    #[cfg(feature = "scan")]
    Scan {
        /// Target host or IP
        #[arg(conflicts_with = "targets")]
        target: Option<String>,
        /// File with newline-delimited targets (comments with # and blanks ignored)
        #[arg(long, value_name = "FILE", conflicts_with = "target")]
        targets: Option<PathBuf>,
        /// Ports: comma/range list (e.g., 22,80,443 or 1-1024,8080). Default: common ports.
        #[arg(long)]
        ports: Option<String>,
        /// Select top N common ports (conflicts with --ports)
        #[arg(long, conflicts_with = "ports")]
        top: Option<usize>,
        /// Timeout per port in milliseconds
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        /// Max concurrent connections
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// QPS cap for connection attempts; 0 disables pacing
        #[arg(long, default_value_t = 0)]
        qps: u32,
        /// Retries per port on failure
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Delay between retries in milliseconds
        #[arg(long, default_value_t = 50)]
        retry_delay_ms: u64,
        /// Number of hosts to scan concurrently when using --targets
        #[arg(long, default_value_t = 1)]
        host_concurrency: usize,
        /// Maximum total concurrent connections across all hosts (default: concurrency * host_concurrency)
        #[arg(long)]
        max_connections: Option<usize>,
        /// Output format: text, json, or jsonl
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Output file (overwrites). For multi-target, emits one line per host.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Write CSV instead of text/json when --out is provided (single target only for now)
        #[arg(long, default_value_t = false)]
        csv: bool,
        /// DNS resolve retry attempts (best-effort resolution)
        #[arg(long, default_value_t = 0)]
        dns_retries: u32,
        /// Delay between DNS retries in milliseconds
        #[arg(long, default_value_t = 200)]
        dns_retry_delay_ms: u64,
    },
    /// Discover live hosts via TCP connect sweep
    #[cfg(feature = "discover")]
    Discover {
        /// CIDR (e.g., 192.168.1.0/24) or hostname
        target: String,
        /// Ports to probe for liveness (default: 80,443,22)
        #[arg(long)]
        ports: Option<String>,
        /// Timeout per attempt in milliseconds
        #[arg(long, default_value_t = 300)]
        timeout_ms: u64,
        /// Max concurrent liveness checks
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// QPS cap for probe launches (across hosts); 0 disables pacing
        #[arg(long, default_value_t = 0)]
        qps: u32,
        /// Output format: text, json, or jsonl
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Output file (overwrites). JSONL writes one line per live host.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Grab service banners (HTTP/HTTPS/SSH)
    #[cfg(feature = "banner")]
    Banner {
        /// Target hostname or IP
        target: String,
        /// Port to probe (common: 80, 443, 22)
        #[arg(long)]
        port: Option<u16>,
        /// Force protocol (http, https, ssh). If omitted, inferred from port.
        #[arg(long, value_parser=["http","https","ssh"])]
        protocol: Option<String>,
        /// Follow one redirect hop for HTTP/HTTPS
        #[arg(long, default_value_t = false)]
        follow: bool,
        /// HTTPS cert output: full DN if set (default CN-only)
        #[arg(long, default_value_t = false)]
        cert_full: bool,
        /// Timeout in milliseconds
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Quick HTTP(S) banner scan with one-hop redirect follow
    #[cfg(feature = "web")]
    Web {
        /// Target hostname or IP
        target: String,
        /// Ports to probe (default: 80,443)
        #[arg(long)]
        ports: Option<String>,
        /// Follow one redirect hop
        #[arg(long, default_value_t = false)]
        follow: bool,
        /// HTTPS cert output: full DN if set (default CN-only)
        #[arg(long, default_value_t = false)]
        cert_full: bool,
        /// Timeout per port in milliseconds
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        /// Output format: text, json, or jsonl
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Web surface scan (HTTP(S) status/title) with concurrency and JSONL output
    #[cfg(feature = "webscan")]
    WebScan {
        /// Single host or newline-delimited file via --targets
        #[arg(conflicts_with = "targets")]
        target: Option<String>,
        /// File with newline-delimited targets
        #[arg(long, value_name = "FILE", conflicts_with = "target")]
        targets: Option<PathBuf>,
        /// Ports to scan
        #[arg(long, default_value = "80,443")]
        ports: String,
        /// Timeout per request in ms
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
        /// Max redirects to follow (HEAD + small GET)
        #[arg(long, default_value_t = 3)]
        redirects: usize,
        /// Concurrency
        #[arg(long, default_value_t = 200)]
        concurrency: usize,
        /// Output file (JSONL). Stdout if omitted.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Write CSV instead of JSONL when --out is provided
        #[arg(long, default_value_t = false)]
        csv: bool,
        /// Disable favicon fetching/hash
        #[arg(long, default_value_t = false)]
        no_favicon: bool,
    },
    /// Forensics utilities: hash and identify files
    #[cfg(feature = "forensics")]
    Forensics {
        #[command(subcommand)]
        cmd: ForensicsCmd,
    },
    /// Credentials utilities
    #[cfg(feature = "creds")]
    Creds {
        #[command(subcommand)]
        cmd: CredsCmd,
    },
    /// UDP probe for common services (dns, ntp)
    #[cfg(feature = "udp")]
    UdpProbe {
        /// Target hostname or IP
        target: String,
        /// Service: dns, ntp or snmp
        #[arg(long, value_parser=["dns","ntp","snmp"])]
        service: String,
        /// SNMP community (snmp only)
        #[arg(long, default_value = "public")]
        community: String,
        /// Timeout in milliseconds
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(any(feature = "scan", feature = "discover"))]
    let loaded_cfg = config::load_config(cli.config.as_deref());
    #[cfg(not(any(feature = "scan", feature = "discover")))]
    let _loaded_cfg: Option<config::Config> = None;
    match cli.command {
        Commands::Version => {
            println!("toolbox {} (core {})", env!("CARGO_PKG_VERSION"), toolbox_core::version());
        }
        #[cfg(feature = "creds")]
        Commands::Creds { cmd } => {
            match cmd {
                CredsCmd::Detect { hash, file } => {
                    let mut inputs = hash.clone();
                    if let Some(p) = file {
                        let s = std::fs::read_to_string(&p)?;
                        inputs.extend(s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
                    }
                    for h in inputs {
                        let kind = credentials::detect_hash(&h);
                        let obj = serde_json::json!({ "hash": h, "kind": format!("{:?}", kind) });
                        println!("{}", serde_json::to_string(&obj)?);
                    }
                }
                CredsCmd::Wordlist { file } => {
                    let s = std::fs::read_to_string(&file)?;
                    let (total, unique) = credentials::wordlist_stats(&s);
                    let obj = serde_json::json!({ "file": file, "total": total, "unique": unique });
                    println!("{}", serde_json::to_string(&obj)?);
                }
                CredsCmd::Crack { tool, hashes, wordlist, args } => {
                    use std::process::{Command, Stdio};
                    use std::io::BufRead;
                    let mut cmd = Command::new(&tool);
                    // Basic sensible defaults if none provided
                    if let Some(a) = args {
                        for tok in a.split_whitespace() { cmd.arg(tok); }
                    }
                    cmd.arg(hashes);
                    if let Some(wl) = wordlist { cmd.arg(wl); }
                    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(format!("failed to spawn {}: {}", tool, e)))?;
                    let stdout = child.stdout.take();
                    let stderr = child.stderr.take();
                    // Stream outputs
                    if let Some(out) = stdout {
                        let mut br = std::io::BufReader::new(out);
                        let mut line = String::new();
                        while br.read_line(&mut line).unwrap_or(0) > 0 {
                            print!("{}", line);
                            line.clear();
                        }
                    }
                    if let Some(err) = stderr {
                        let mut br = std::io::BufReader::new(err);
                        let mut line = String::new();
                        while br.read_line(&mut line).unwrap_or(0) > 0 {
                            eprint!("{}", line);
                            line.clear();
                        }
                    }
                    let status = child.wait()?;
                    if !status.success() {
                        return Err(anyhow::anyhow!(format!("{} exited with status {}", tool, status)));
                    }
                }
            }
        }
        #[cfg(feature = "forensics")]
        Commands::Forensics { cmd } => {
            match cmd {
                ForensicsCmd::Hash { files } | ForensicsCmd::Identify { files } => {
                    for p in files {
                        match forensics::hash_file(p.to_string_lossy().as_ref()) {
                            Ok(info) => {
                                let obj = serde_json::json!({
                                    "path": info.path,
                                    "size": info.size,
                                    "sha256": info.sha256,
                                    "blake3": info.blake3,
                                    "mime": info.mime,
                                    "ext": info.ext,
                                });
                                println!("{}", serde_json::to_string(&obj)?);
                            }
                            Err(e) => {
                                let obj = serde_json::json!({ "path": p.to_string_lossy(), "error": e.to_string() });
                                println!("{}", serde_json::to_string(&obj)?);
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "webscan")]
        Commands::WebScan { target, targets, ports, timeout_ms, redirects, concurrency, out, csv, no_favicon } => {
            let targets_list: Vec<String> = if let Some(t) = target {
                vec![t]
            } else if let Some(path) = targets {
                let fh = std::fs::File::open(&path)?;
                let br = std::io::BufReader::new(fh);
                use std::io::BufRead;
                br.lines().filter_map(|l| l.ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !s.starts_with('#')).collect()
            } else { vec![] };
            if targets_list.is_empty() { return Err(anyhow::anyhow!("provide a target or --targets <file>")); }
            let ports_vec = modules_port_parse(&ports)?;
            let opts = web_surface::WebProbeOptions { timeout_ms, redirects, user_agent: format!("toolbox/{}", env!("CARGO_PKG_VERSION")), fetch_favicon: !no_favicon };
            let rt = tokio::runtime::Runtime::new()?;
            let results = rt.block_on(async move { web_surface::probe_many(targets_list, ports_vec, opts, concurrency).await });
            if let Some(path) = out.clone() {
                if csv {
                    let mut wtr = csv::Writer::from_writer(std::fs::File::create(&path)?);
                    wtr.write_record(["target","url","final_url","status","server","title","fingerprints","favicon_mmh3","duration_ms","started_at","ended_at","error"]) ?;
                    for r in results {
                        let fps = if r.fingerprints.is_empty() { String::new() } else { r.fingerprints.join("|") };
                        wtr.write_record([
                            r.target,
                            r.url,
                            r.final_url,
                            r.status.map(|v| v.to_string()).unwrap_or_default(),
                            r.server.unwrap_or_default(),
                            r.title.unwrap_or_default(),
                            fps,
                            r.favicon_mmh3.map(|v| v.to_string()).unwrap_or_default(),
                            r.duration_ms.to_string(),
                            r.started_at,
                            r.ended_at,
                            r.error.unwrap_or_default(),
                        ])?;
                    }
                    wtr.flush()?;
                } else {
                    let mut w = std::io::BufWriter::new(std::fs::File::create(&path)?);
                    for r in results {
                        let obj = serde_json::json!({
                            "target": r.target,
                            "url": r.url,
                            "final_url": r.final_url,
                            "status": r.status,
                            "server": r.server,
                            "title": r.title,
                            "fingerprints": r.fingerprints,
                            "started_at": r.started_at,
                            "ended_at": r.ended_at,
                            "duration_ms": r.duration_ms,
                            "favicon_url": r.favicon_url,
                            "favicon_mmh3": r.favicon_mmh3,
                            "error": r.error,
                        });
                        use std::io::Write;
                        writeln!(w, "{}", serde_json::to_string(&obj)?)?;
                    }
                }
            } else {
                for r in results {
                    let obj = serde_json::json!({
                        "target": r.target,
                        "url": r.url,
                        "final_url": r.final_url,
                        "status": r.status,
                        "server": r.server,
                        "title": r.title,
                        "fingerprints": r.fingerprints,
                        "started_at": r.started_at,
                        "ended_at": r.ended_at,
                        "duration_ms": r.duration_ms,
                        "favicon_url": r.favicon_url,
                        "favicon_mmh3": r.favicon_mmh3,
                        "error": r.error,
                    });
                    println!("{}", serde_json::to_string(&obj)?);
                }
            }
        }
        #[cfg(feature = "banner")]
        Commands::Banner { target, port, protocol, follow, cert_full, timeout_ms, format } => {
            let p = port.unwrap_or_else(|| match protocol.as_deref() { Some("https") => 443, Some("ssh") => 22, _ => 80 });
            let proto = protocol.unwrap_or_else(|| match p { 443 => "https".into(), 22 => "ssh".into(), _ => "http".into() });
            let rt = tokio::runtime::Runtime::new()?;
            let started = Instant::now();
            let banner = rt.block_on(async {
                match proto.as_str() {
                    "https" => if follow { banners::grab_https_follow_one(&target, p, timeout_ms, !cert_full).await } else { banners::grab_https(&target, p, timeout_ms, !cert_full).await },
                    "ssh" => banners::grab_ssh(&target, p, timeout_ms).await,
                    _ => if follow { banners::grab_http_follow_one(&target, p, timeout_ms).await } else { banners::grab_http(&target, p, timeout_ms).await },
                }
            });
            let duration_ms = started.elapsed().as_millis();
            match (format, banner) {
                (OutputFormat::Text, Ok(b)) => println!("{}:{} {} ({} ms)", target, p, b.summary, duration_ms),
                (OutputFormat::Json | OutputFormat::Jsonl, Ok(b)) => {
                    let obj = serde_json::json!({
                        "target": target,
                        "port": p,
                        "protocol": b.protocol,
                        "summary": b.summary,
                        "duration_ms": duration_ms,
                    });
                    println!("{}", serde_json::to_string(&obj)?);
                }
                (_, Err(e)) => return Err(anyhow!(e.to_string())),
            }
        }
        #[cfg(feature = "web")]
        Commands::Web { target, ports, follow, cert_full, timeout_ms, format } => {
            let ports_vec = if let Some(spec) = ports { port_scan::parse_ports(&spec)? } else { vec![80,443] };
            let rt = tokio::runtime::Runtime::new()?;
            let started = Instant::now();
            let target_for_print = target.clone();
            let results = rt.block_on(async move {
                let mut handles = Vec::new();
                let f = follow;
                let cn_only = !cert_full;
                for p in ports_vec.clone() {
                    let t = target.clone();
                    handles.push(tokio::spawn(async move {
                        let res = match p {
                            443 => if f { banners::grab_https_follow_one(&t, p, timeout_ms, cn_only).await } else { banners::grab_https(&t, p, timeout_ms, cn_only).await },
                            _ => if f { banners::grab_http_follow_one(&t, p, timeout_ms).await } else { banners::grab_http(&t, p, timeout_ms).await },
                        };
                        (p, res)
                    }));
                }
                let mut out = Vec::new();
                for h in handles { if let Ok(v) = h.await { out.push(v); } }
                out
            });
            let duration_ms = started.elapsed().as_millis();
            match format {
                OutputFormat::Text => {
                    for (p, res) in results {
                        match res {
                            Ok(b) => println!("{}:{} {} ({} ms)", target_for_print, p, b.summary, duration_ms),
                            Err(e) => println!("{}:{} error: {}", target_for_print, p, e),
                        }
                    }
                }
                OutputFormat::Json | OutputFormat::Jsonl => {
                    for (p, res) in results {
                        match res {
                            Ok(b) => {
                                let obj = serde_json::json!({
                                    "target": target_for_print,
                                    "port": p,
                                    "protocol": b.protocol,
                                    "summary": b.summary,
                                    "duration_ms": duration_ms,
                                });
                                println!("{}", serde_json::to_string(&obj)?);
                            }
                            Err(e) => {
                                let obj = serde_json::json!({
                                    "target": target_for_print,
                                    "port": p,
                                    "error": e.to_string(),
                                });
                                println!("{}", serde_json::to_string(&obj)?);
                            }
                        }
                    }
                }
            }
        }
        #[cfg(feature = "udp")]
        Commands::UdpProbe { target, service, community, timeout_ms, format } => {
            let rt = tokio::runtime::Runtime::new()?;
            let started = Instant::now();
            let target_c = target.clone();
            let service_for_task = service.clone();
            let res = rt.block_on(async move {
                match service_for_task.as_str() {
                    "dns" => udp_probe::probe_dns(&target_c, timeout_ms).await,
                    "ntp" => udp_probe::probe_ntp(&target_c, timeout_ms).await,
                    _ => udp_probe::probe_snmp_sysdescr(&target_c, &community, timeout_ms).await,
                }
            });
            let duration_ms = started.elapsed().as_millis();
            match res {
                Ok(Some(info)) => match format {
                    OutputFormat::Text => println!("{} {} ok ({}, {} ms)", target, service, info, duration_ms),
                    OutputFormat::Json | OutputFormat::Jsonl => {
                        let obj = serde_json::json!({ "target": target, "service": service, "status": "ok", "info": info, "duration_ms": duration_ms });
                        println!("{}", serde_json::to_string(&obj)?);
                    }
                },
                Ok(None) => match format {
                    OutputFormat::Text => println!("{} {} no-response ({} ms)", target, service, duration_ms),
                    OutputFormat::Json | OutputFormat::Jsonl => {
                        let obj = serde_json::json!({ "target": target, "service": service, "status": "no-response", "duration_ms": duration_ms });
                        println!("{}", serde_json::to_string(&obj)?);
                    }
                },
                Err(e) => return Err(anyhow!(e.to_string())),
            }
        }
        #[cfg(feature = "scan")]
        Commands::Scan { target, targets, mut ports, mut top, mut timeout_ms, mut concurrency, mut qps, mut retries, mut retry_delay_ms, mut host_concurrency, max_connections, mut format, out, csv, mut dns_retries, mut dns_retry_delay_ms } => {
            if let Some(cfg) = &loaded_cfg { if let Some(s) = &cfg.scan {
                if ports.is_none() { ports = s.ports.clone(); }
                if top.is_none() { top = s.top; }
                if s.timeout_ms.is_some() { timeout_ms = s.timeout_ms.unwrap(); }
                if s.concurrency.is_some() { concurrency = s.concurrency.unwrap(); }
                if s.host_concurrency.is_some() { host_concurrency = s.host_concurrency.unwrap(); }
                if s.qps.is_some() { qps = s.qps.unwrap(); }
                if s.retries.is_some() { retries = s.retries.unwrap(); }
                if s.retry_delay_ms.is_some() { retry_delay_ms = s.retry_delay_ms.unwrap(); }
                if let Some(f) = &s.format { format = match f.as_str() { "json" => OutputFormat::Json, "jsonl" => OutputFormat::Jsonl, _ => OutputFormat::Text }; }
            }}
            let ports_vec = match (ports, top) {
                (Some(spec), _) => port_scan::parse_ports(&spec)?,
                (None, Some(n)) => {
                    if n == 0 { return Err(anyhow!("--top must be > 0")); }
                    port_scan::top_ports(n)
                }
                _ => port_scan::default_top_ports(),
            };
            let rt = tokio::runtime::Runtime::new()?;

            // Single target mode
            if let Some(target) = target {
                let target_for_scan = target.clone();
                let ports_for_scan = ports_vec.clone();
                let start = Instant::now();
                let started_at = now_rfc3339();
                let open = rt.block_on(async move {
                    let global_qps = if qps == 0 { None } else { Some(std::sync::Arc::new(toolbox_core::ratelimiter::RateLimiter::new(qps))) };
                    port_scan::scan_connect_with_limits(
                        &target_for_scan,
                        &ports_for_scan,
                        std::time::Duration::from_millis(timeout_ms),
                        concurrency,
                        dns_retries,
                        std::time::Duration::from_millis(dns_retry_delay_ms),
                        global_qps,
                        retries,
                        std::time::Duration::from_millis(retry_delay_ms),
                        None,
                    ).await
                });
                let duration_ms = start.elapsed().as_millis();
                let ended_at = now_rfc3339();
                if csv {
                    if let Some(path) = out {
                        let mut wtr = csv::Writer::from_writer(std::fs::File::create(&path)?);
                        wtr.write_record(["target","port","started_at","ended_at","duration_ms"]) ?;
                        for p in open { wtr.write_record([&target, &p.to_string(), &started_at, &ended_at, &duration_ms.to_string()])?; }
                        wtr.flush()?;
                        return Ok(());
                    } else {
                        println!("--csv requires --out <file>");
                    }
                }
                let line = match format {
                    OutputFormat::Text => {
                        if open.is_empty() {
                            format!("{}: no open ports found ({} scanned)", target, ports_vec.len())
                        } else {
                            let list = open.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                            format!("{}: open ports [{}] ({} scanned, {} ms)", target, list, ports_vec.len(), duration_ms)
                        }
                    }
                    OutputFormat::Json | OutputFormat::Jsonl => {
                        let obj = serde_json::json!({
                            "target": target,
                            "scanned": ports_vec.len(),
                            "open": open,
                            "timeout_ms": timeout_ms,
                            "concurrency": concurrency,
                            "duration_ms": duration_ms,
                            "started_at": started_at,
                            "ended_at": ended_at,
                        });
                        serde_json::to_string(&obj)?
                    }
                };
                if let Some(path) = out {
                    let file = OpenOptions::new().create(true).truncate(true).write(true).open(&path)?;
                    let mut w = BufWriter::new(file);
                    writeln!(w, "{}", line)?;
                } else {
                    println!("{}", line);
                }
                return Ok(());
            }

            // Multi-target mode: concurrent hosts with global connection limit; outputs one line per target
            if let Some(file) = targets {
                let fh = File::open(&file)?;
                let br = BufReader::new(fh);
                let mut targets_vec = Vec::new();
                for line in br.lines() {
                    let line = line?;
                    let t = line.trim();
                    if t.is_empty() || t.starts_with('#') { continue; }
                    targets_vec.push(t.to_string());
                }

                // Prepare writer (stdout or file)
                let mut writer_file = if let Some(path) = out.clone() {
                    Some(BufWriter::new(OpenOptions::new().create(true).truncate(true).write(true).open(&path)?))
                } else { None };

                let total_connections = max_connections.unwrap_or_else(|| concurrency.saturating_mul(host_concurrency.max(1)));
                let total_connections = total_connections.max(1);
                let host_conc = host_concurrency.max(1);
                let timeout = std::time::Duration::from_millis(timeout_ms);
                let dns_delay = std::time::Duration::from_millis(dns_retry_delay_ms);
                // Global QPS token bucket (shared across all hosts)
                let global_qps = if qps == 0 { None } else { Some(std::sync::Arc::new(toolbox_core::ratelimiter::RateLimiter::new(qps))) };

                // Channel for lines
                let (tx, rx) = mpsc::unbounded_channel::<String>();
                // Writer thread to serialize output
                let writer_handle = std::thread::spawn(move || {
                    let mut rx = rx;
                    while let Some(line) = rx.blocking_recv() {
                        if let Some(wf) = writer_file.as_mut() {
                            let _ = writeln!(wf, "{}", line);
                            let _ = wf.flush();
                        } else {
                            println!("{}", line);
                        }
                    }
                });

                rt.block_on(async move {
                    let global = std::sync::Arc::new(tokio::sync::Semaphore::new(total_connections));
                    let host_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(host_conc));
                    let global_qps_shared = global_qps.clone();
                    let mut handles = Vec::with_capacity(targets_vec.len());
                    for t in targets_vec {
                        let host_sem_p = host_sem.clone().acquire_owned().await.unwrap();
                        let txc = tx.clone();
                        let ports_for_scan = ports_vec.clone();
                        let global_c = global.clone();
                        let gq = global_qps_shared.clone();
                        let target_s = t.clone();
                        let h = tokio::spawn(async move {
                            let start = Instant::now();
                            let open = port_scan::scan_connect_with_limits(
                                &target_s,
                                &ports_for_scan,
                                timeout,
                                concurrency,
                                dns_retries,
                                dns_delay,
                                gq,
                                retries,
                                std::time::Duration::from_millis(retry_delay_ms),
                                Some(global_c),
                            ).await;
                            let duration_ms = start.elapsed().as_millis();
                            let line = match format {
                                OutputFormat::Text => {
                                    if open.is_empty() {
                                        format!("{}: no open ports found ({} scanned)", target_s, ports_for_scan.len())
                                    } else {
                                        let list = open.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                                        format!("{}: open ports [{}] ({} scanned, {} ms)", target_s, list, ports_for_scan.len(), duration_ms)
                                    }
                                }
                                OutputFormat::Json | OutputFormat::Jsonl => {
                                    let obj = serde_json::json!({
                                        "target": target_s,
                                        "scanned": ports_for_scan.len(),
                                        "open": open,
                                        "timeout_ms": timeout_ms,
                                        "concurrency": concurrency,
                                        "duration_ms": duration_ms,
                                    });
                                    serde_json::to_string(&obj).unwrap()
                                }
                            };
                            let _ = txc.send(line);
                            drop(host_sem_p);
                        });
                        handles.push(h);
                    }
                    drop(tx);
                    for h in handles { let _ = h.await; }
                });

                let _ = writer_handle.join();
                return Ok(());
            }

            return Err(anyhow!("provide a target or --targets <file>"));
        }
        #[cfg(feature = "discover")]
        Commands::Discover { target, mut ports, mut timeout_ms, mut concurrency, mut qps, mut format, out } => {
            if let Some(cfg) = &loaded_cfg { if let Some(d) = &cfg.discover {
                if ports.is_none() { ports = d.ports.clone(); }
                if d.timeout_ms.is_some() { timeout_ms = d.timeout_ms.unwrap(); }
                if d.concurrency.is_some() { concurrency = d.concurrency.unwrap(); }
                if d.qps.is_some() { qps = d.qps.unwrap(); }
                if let Some(f) = &d.format { format = match f.as_str() { "json" => OutputFormat::Json, "jsonl" => OutputFormat::Jsonl, _ => OutputFormat::Text }; }
            }}
            let ports_vec = if let Some(spec) = ports { port_scan::parse_ports(&spec)? } else { vec![80,443,22] };
            let rt = tokio::runtime::Runtime::new()?;
            let started = Instant::now();
            // Expand target into IPs
            let ips = if target.contains('/') {
                host_discovery::expand_cidr(&target)?
            } else {
                let ip = host_discovery::resolve_host_best_effort(&target);
                if ip.is_unspecified() { return Err(anyhow!("failed to resolve target: {}", target)); }
                vec![ip]
            };
            let ports_for_display = ports_vec.clone();
            let live = rt.block_on(async move {
                let q = if qps == 0 { None } else { Some(qps) };
                host_discovery::discover_hosts(ips, &ports_vec, std::time::Duration::from_millis(timeout_ms), concurrency, q).await
            });
            let duration_ms = started.elapsed().as_millis();

            match format {
                OutputFormat::Text => {
                    println!("live hosts ({}):", live.len());
                    for ip in &live { println!("{}", ip); }
                    println!("(probed on ports {}, took {} ms)", ports_for_display.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","), duration_ms);
                }
                OutputFormat::Json => {
                    let obj = serde_json::json!({
                        "target": target,
                        "live": live,
                        "ports": ports_for_display,
                        "duration_ms": duration_ms,
                    });
                    if let Some(path) = out {
                        let file = OpenOptions::new().create(true).truncate(true).write(true).open(&path)?;
                        let mut w = BufWriter::new(file);
                        writeln!(w, "{}", serde_json::to_string(&obj)?)?;
                    } else {
                        println!("{}", serde_json::to_string(&obj)?);
                    }
                }
                OutputFormat::Jsonl => {
                    if let Some(path) = out {
                        let file = OpenOptions::new().create(true).truncate(true).write(true).open(&path)?;
                        let mut w = BufWriter::new(file);
                        for ip in &live { writeln!(w, "{}", serde_json::json!({"host": ip}).to_string())?; }
                    } else {
                        for ip in &live { println!("{}", serde_json::json!({"host": ip})); }
                    }
                }
            }
        }
    }
    Ok(())
}

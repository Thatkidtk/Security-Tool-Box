# Unified Security Toolbox (Scaffold)

This repo hosts a cross‑platform Rust workspace for fast, safe network tooling.

Quick start
- Build: `cargo build --workspace`
- Lint/format: `cargo clippy -- -D warnings` and `cargo fmt --all`
- Run CLI: `cargo run -p toolbox --features '<feat>' -- <cmd> ...`

Features and commands
- scan (TCP connect)
  - `toolbox scan <target> [--ports LIST|--top N] [--timeout-ms N] [--concurrency M] [--qps Q] [--retries R] [--retry-delay-ms D] [--format text|json|jsonl]`
  - Multi-target: `toolbox scan --targets HOSTS.txt [...]` (supports `--host-concurrency`, `--max-connections`).
  - CSV (single target): `--csv --out results.csv` writes `target,port,started_at,ended_at,duration_ms`.
  - QPS is global across all hosts/ports (token bucket).
- discover (host liveness)
  - `toolbox discover <CIDR|host> [--ports LIST] [--timeout-ms N] [--concurrency M] [--qps Q] [--format text|json|jsonl]`
- banner (single service banner)
  - `toolbox banner <host> [--protocol http|https|ssh] [--port P] [--follow] [--cert-full] [--timeout-ms N] [--format text|json|jsonl]`
  - HTTPS shows ALPN and TLS cert details (CN-only by default; `--cert-full` prints full DNs).
- web (HTTP(S) banners for common ports 80/443)
  - `toolbox web <host> [--ports LIST] [--follow] [--cert-full] [--timeout-ms N] [--format text|json|jsonl]`
- udp (DNS/NTP/SNMP probes)
  - `toolbox udp-probe <host> --service dns|ntp|snmp [--community public] [--timeout-ms N]`

Config
- Optional `toolbox.yaml` can set defaults for scan/discover (ports, timeouts, QPS, format). Use `--config <path>` to specify a file.

Notes
- All scans use TCP connect (no raw sockets). SNMP/DNS/NTP probes use UDP.
- Redirect follow (web/banner) performs one HEAD hop at most.
- SNMP probe queries v2c `sysDescr.0` (community default: `public`).

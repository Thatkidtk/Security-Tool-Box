# Repository Guidelines

## Project Structure
- `core/`: Shared types/utilities.
- `modules/`: Feature crates (`port-scan`, `host-discovery`, `banners`, `udp-probe`).
- `toolbox/`: CLI binary wiring modules behind feature flags.
- `.github/`, `ops/`, `docs/`: CI, packaging, and guides.

## Build, Test, Develop
- `cargo build --workspace`: Compile all crates.
- `cargo test --workspace --all-features`: Run unit tests.
- `cargo fmt --all` and `cargo clippy -- -D warnings`: Format + lint.
- Run CLI: `cargo run -p toolbox --features '<feat>' -- <cmd> ...` (see below).

## CLI Overview (examples)
- Scan TCP ports: `--features scan`
  - `toolbox scan 192.168.1.10 --ports 1-1024,8080 --qps 400 --retries 1`
  - Multi-host: `toolbox scan --targets hosts.txt --top 100 --format jsonl`
  - CSV (single host): `toolbox scan 10.0.0.5 --ports 22,80 --csv --out result.csv`
- Discover hosts: `--features discover`
  - `toolbox discover 10.0.0.0/24 --ports 80,443,22 --qps 200`
- Banners: `--features banner`
  - `toolbox banner example.com --protocol https --format json`
- UDP probes: `--features udp`
  - `toolbox udp-probe 1.1.1.1 --service dns --timeout-ms 500`
  - `toolbox udp-probe 192.168.1.1 --service snmp --community public`

## Style & Conventions
- Rust 2021; enforce with `rustfmt`/`clippy`.
- Crates: kebab-case; modules: snake_case; types/traits: PascalCase.
- Prefer explicit feature gates (`scan`, `discover`, `banner`, `udp`).

## Testing
- Unit tests colocated with code; integration tests under `tests/` per crate.
- Keep network tests deterministic; gate slow/real-network with features.

## Commits & PRs
- Conventional Commits (e.g., `feat(scan): add global QPS bucket`).
- PRs include: scope, behavior, flags, examples, and validation steps.

## Config & Security
- Config file: `toolbox.yaml` can set defaults (ports, timeouts, QPS, format).
- Default to least-privilege; no secrets in repo; document elevated paths.

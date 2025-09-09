# Unified Offensive Security Toolbox — Enhanced Roadmap

## Vision

Rebuild the fragmented CLI tools of Kali Linux into a single, user-friendly, high-performance toolbox that **runs on any device, any OS**.  
Core principles: **speed, safety, modularity, extensibility, cross-platform compatibility, and exceptional UX.**

---

## Cross-Platform Architecture

### Universal Runtime Targets

- **Primary:** Linux (x86_64, ARM64, RISC-V)
- **Secondary:** macOS (Intel + Apple Silicon), Windows (x86_64, ARM64)
- **Mobile:** Android (via Termux), iOS (iSH, jailbroken/sideloaded)
- **Embedded:** Raspberry Pi, OpenWrt routers, USB-bootable live systems
- **Cloud:** AWS Lambda, Google Cloud Run, container orchestrators

### Deployment Strategies

1. **Static Binaries** - Zero dependencies, universal compatibility
2. **Container-First** - Docker/Podman for consistent environments
3. **Progressive Web App** - Browser-based interface for any device
4. **Mobile Wrappers** - Native apps wrapping core engine

---

## Core Architecture

### Engine

- **Language:** Rust (memory safety, performance, cross-platform)
- **Concurrency:** `tokio` (async I/O) + `rayon` (CPU parallelism)
- **CLI/TUI:** `clap` for subcommands; `ratatui` + `crossterm` for terminal UI
- **Networking:** raw sockets via `pnet`/`smoltcp`, TLS via `rustls`, HTTP/2 via `hyper`
- **Packet Capture:** `libpcap` bindings + `libbpf-rs` for eBPF filters (Linux), fallbacks for other OS
- **Crypto & Hashing:** `ring`, `RustCrypto`, `blake3`, `sha2`, `sha3`
- **Storage:** SQLite + Parquet/Arrow for fast analysis; DuckDB optional
- **Telemetry:** structured JSON logs, OpenTelemetry traces

### Cross-Platform Abstraction Layer

```rust
// Platform-specific implementations
#[cfg(target_os = "linux")]
use platform::linux::*;
#[cfg(target_os = "windows")]
use platform::windows::*;
#[cfg(target_os = "macos")]
use platform::macos::*;
#[cfg(target_os = "ios")]
use platform::ios::*;

// Graceful capability degradation
if has_raw_sockets() {
    // Full SYN scanning
} else {
    // Fall back to connect() scanning
}
```

### Plugins

- **WASM plugins** with WASI (`wasmtime`) for sandboxed exploits/parsers
- **Native plugins** (signed, versioned) for high-performance needs
- **Scripting SDKs:** Python (`pyo3`) + JavaScript (via WASM)
- **Browser WASM build** for reconnaissance in web contexts

### Privilege & Safety

- **Linux:** Privileged helpers with capabilities (drop privileges quickly)
- **macOS/iOS:** XPC services and entitlements
- **Windows:** UAC elevation helpers
- **Android:** Root detection and su integration
- Per-tool seccomp profiles + namespaces where supported
- SBOMs (CycloneDX), signed releases (Sigstore), reproducible builds (Nix)

### Acceleration

- **GPU:** OpenCL + CUDA bindings for hashing and wordlist transforms
- **eBPF offload** for hot packet filters (Linux)
- **SIMD** (`std::simd`) where beneficial across all platforms
- **Apple Metal** acceleration on macOS/iOS
- **Windows DirectCompute** for GPU tasks

---

## Universal Deployment Matrix

### Binary Distribution

- **Static Binaries:** MUSL + Zig cross-compilation for zero dependencies
- **Universal Installer:** Detects platform and downloads appropriate binary
- **Package Managers:** Homebrew, Chocolatey, APT, Pacman, Cargo
- **App Stores:** Microsoft Store, Mac App Store (sandboxed versions)

### Container Strategy

```bash
# Identical experience across all Docker hosts
toolbox scan --target 192.168.1.0/24
# OR
docker run --rm --net=host ghcr.io/toolbox:latest scan --target 192.168.1.0/24
```

### Platform-Specific Packaging

- **Linux:** AppImage, Flatpak, Snap for distribution flexibility
- **macOS:** .app bundles with proper codesigning
- **Windows:** MSI installers with Windows Defender allowlisting
- **iOS:** IPA for sideloading, works in iSH environment
- **Android:** APK with Termux integration

---

## UX Layers

- **Daemon:** Rust service with gRPC/Unix socket API
- **TUI:** unified CLI with panes for tasks, results, logs
- **Desktop/Web UI:** Tauri + React/Next.js hitting the daemon API
- **Progressive Web App:** Offline-capable browser interface
- **Mobile Apps:** Native wrappers for iOS/Android
- **Playbooks:** YAML/JSON task graphs (scans → exploits → reports)

---

## Key Modules

### Port Scanning

- Async SYN scanning (Masscan speed + Nmap accuracy) on supporting platforms
- Connect() fallback for restricted environments
- Service fingerprinting (TLS JA3/JA4, HTTP/2 ALPN, SSH banners, etc.)
- SQLite + Parquet outputs, resumable scans
- IPv6 support across all platforms

### Web Surface

- Fast HTTP(S) probing, HTTP/2 support
- Passive tech fingerprinting (Wappalyzer rules in WASM)
- Lightweight crawler + ML endpoint classifier (optional)
- CORS and CSP analysis
- Certificate chain validation

### Wi-Fi Suite

- **Linux:** Radiotap/nl80211 capture, full monitor mode
- **macOS:** CoreWLAN framework integration
- **Windows:** Native WiFi API integration
- **Mobile:** Platform-appropriate WiFi scanning APIs
- Adaptive channel hopping
- GPU-accelerated WPA cracking
- Clean TUI for handshakes, PMKIDs, deauth attempts

### Sniffing/Forensics

- **Linux:** eBPF + pcap capture, full packet inspection
- **Other platforms:** pcap fallbacks with reduced capabilities
- Cross-platform parsers via `nom`
- Disk imaging with integrity manifests, resumable
- Artifact carving (MFT, Ext4, APFS, HFS+) → Parquet exports
- Memory dump analysis where permitted

### Credential Tools

- Hashcat orchestration across platforms
- Built-in GPU kernels for fallback
- Platform-specific password store integration
- Cross-platform keychain/credential manager access

### Exploit Framework

- Exploits/payloads as WASM modules (universal compatibility)
- Session management over gRPC
- Transcript & artifact logging for chain of custody
- Platform-specific privilege escalation techniques

---

## Platform-Specific Optimizations

### Linux

- Full eBPF integration for packet filtering and system monitoring
- Netlink socket integration for network interface management
- cgroups integration for resource limiting
- systemd service integration

### macOS/iOS

- Metal performance shaders for GPU acceleration
- Network Extension framework integration
- XPC service architecture for privilege separation
- CoreFoundation integration for system APIs

### Windows

- Windows Filtering Platform (WFP) integration
- ETW (Event Tracing for Windows) for system monitoring
- Windows Service architecture
- UAC-aware elevation flows

### Mobile Platforms

- Battery-aware scanning algorithms
- Network permission handling
- Background processing limitations
- Touch-optimized interfaces

---

## Packaging & Ops

### Build System

- **Cross-compilation:** Zig + Nix for reproducible builds
- **CI/CD:** GitHub Actions with matrix builds for all platforms
- **Testing:** Platform-specific test suites in emulated environments
- **Signing:** Platform-appropriate code signing (Apple Developer, Windows certificates)

### Distribution

- **Single Binary:** `toolboxd` daemon + `toolbox` CLI/TUI
- **Universal Installer:** Auto-detects platform and installs appropriately
- **Container Registry:** Multi-arch images for all supported platforms
- **Package Repositories:** Platform-specific package manager integration

### Configuration

- **Lab Mode:** Full capabilities for authorized testing environments
- **Restricted Mode:** Limited capabilities for compliance-sensitive environments
- **Policies:** YAML-defined capability restrictions per environment

---

## Repository Layout

```
/core                # Rust engine crates
/modules            # scanning, wifi, web, forensics
/plugins            # WASM samples + SDKs
/ui-tui             # terminal UI
/ui-desktop         # Tauri app
/ui-web             # Progressive Web App
/ui-mobile          # iOS/Android native wrappers
/platform           # OS-specific implementations
  /linux            # Linux-specific code
  /macos            # macOS/iOS-specific code
  /windows          # Windows-specific code
  /mobile           # Mobile platform abstractions
/schemas            # Arrow/Parquet + SQLite schemas
/ops                # Nix, CI, SBOMs, cosign, installers
/examples           # playbooks, lab configs
/docs               # cross-platform setup guides
```

---

## Installation Examples

### Universal Quick Start

```bash
# Auto-detecting installer
curl -sSL https://install.toolbox.sh | sh

# Or manual download
wget https://releases.toolbox.sh/latest/toolbox-$(uname -s)-$(uname -m)
chmod +x toolbox-* && sudo mv toolbox-* /usr/local/bin/toolbox
```

### Platform-Specific

```bash
# macOS via Homebrew
brew install toolbox-security

# Windows via Chocolatey
choco install toolbox-security

# iOS via iSH
git clone https://github.com/toolbox-security/toolbox
cd toolbox && ./install-ish.sh

# Android via Termux
pkg install toolbox-security
```

### Container

```bash
# Universal container experience
docker pull ghcr.io/toolbox-security/toolbox:latest
docker run --rm -it --net=host toolbox:latest
```

---

## Deliverables (Month 1)

1. **Fast Port Scanner**: SYN/CONNECT with platform fallbacks, fingerprinting, Parquet export
2. **Capture/Filter Engine**: Platform-appropriate packet capture, live decode, PCAP + Parquet output
3. **Plugin SDKs**: WASM + Python SDK with "Hello World" banner grabber
4. **Cross-Platform Installer**: Auto-detecting installation script
5. **iOS/iSH Compatibility**: Verified operation in iSH environment

---

## Mobile/Restricted Environment Strategy

### iOS (iSH/Jailbroken)

- Compiled for x86_64 (iSH emulation)
- No raw socket requirements in default mode
- File-based result sharing
- Battery-conscious scanning algorithms

### Android (Termux)

- Native ARM64 compilation
- Termux API integration
- Root detection and privilege escalation
- Intent-based result sharing

### Restricted Corporate Networks

- Connect()-only scanning modes
- Proxy-aware HTTP clients
- Certificate store integration
- Audit log compliance features

---

## Benchmarks

- Built-in reproducible harness: same targets, same wordlists, same network conditions
- Cross-platform performance comparison matrix
- Metrics: packets per second, missed-open rate, false positives, CPU/RAM usage per platform
- Flamegraphs + profiles published alongside results
- Mobile battery usage profiling

---

## Guardrails

- **Passive-first defaults** across all platforms
- **Explicit `--active` flag** for intrusive steps
- **Consent banners** and signed audit logs (hash-chained)
- **Platform capability detection** with graceful degradation
- **Compliance modes** for different regulatory environments
- **Network-aware** throttling and detection avoidance

---

## Success Metrics

- ✅ Single binary runs identically on Linux, macOS, Windows, iOS (iSH), Android (Termux)
- ✅ Container works across Docker Desktop, Kubernetes, cloud platforms
- ✅ Progressive Web App provides core functionality on any browser
- ✅ Performance matches or exceeds specialized tools on each platform
- ✅ Zero external dependencies for core functionality
- ✅ Consistent command-line interface and data formats everywhere

---

_Ready to build the universal security toolbox that works everywhere, from enterprise Linux servers to iOS devices running in iSH. One codebase, infinite deployment possibilities._

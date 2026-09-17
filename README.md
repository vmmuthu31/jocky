# JOCKY — Enterprise Digital Forensics Platform

**NTRO Hackathon 26148 · Smart India Hackathon · Blockchain & Cybersecurity Track**

[![CI](https://github.com/vmmuthu31/jocky/actions/workflows/release.yml/badge.svg)](https://github.com/vmmuthu31/jocky/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/vmmuthu31/jocky)](https://github.com/vmmuthu31/jocky/releases/latest)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)

JOCKY is an enterprise-grade digital forensics command-and-control platform built for authorized law-enforcement and intelligence operations under the IT Act 2000 §69.

## Install

**Homebrew (macOS / Linux)**
```bash
brew tap vmmuthu31/jocky
brew install jocky
```

**Debian / Ubuntu**
```bash
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky_amd64.deb
sudo dpkg -i jocky_amd64.deb
```

**RHEL / Fedora / CentOS**
```bash
sudo rpm -i https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-x86_64.rpm
```

**Windows — Installer .exe**
Download [`jocky-setup-x86_64.exe`](https://github.com/vmmuthu31/jocky/releases/latest) from Releases and run it. Installs to `Program Files\JOCKY` and adds to system PATH.

**Windows — PowerShell (no installer)**
```powershell
irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex
```

**macOS / Linux — curl**
```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

**Build from source**
```bash
git clone https://github.com/vmmuthu31/jocky.git && cd jocky && make install
```

→ [Full installation guide](docs/installation.md) · [Getting started](docs/getting-started.md) · [CLI reference](docs/cli-reference.md)

---

## Architecture

```
┌─────────────────────┐    LLVM IR     ┌──────────────────────┐
│  JOCKY DSL (.jocky) │ ──────────────▶│  Rust Compiler       │
│  Warrant-gated DSL  │                │  7-pass poly engine  │
└─────────────────────┘                └──────────┬───────────┘
                                                  │ binary
                                       ┌──────────▼───────────┐
┌─────────────────────┐   mTLS/WSS     │  Field Agent         │
│  Go Server          │ ◀──────────────│  (Windows / Linux)   │
│  Gin + WebSocket    │                └──────────────────────┘
│  Blockchain ledger  │
└──────────┬──────────┘
           │  HTTP API
┌──────────▼──────────┐
│  Web Dashboard      │
│  (plain HTML/JS)    │
└─────────────────────┘
```

### Components

| Component | Language | Description |
|-----------|----------|-------------|
| `compiler/` | Rust | JOCKY DSL → LLVM IR compiler, 7-pass polymorphic pipeline, runtime modules |
| `server/` | Go | REST + WebSocket server, multi-officer approval, blockchain audit ledger |
| `web/` | HTML/JS | Operator dashboard — compile, dispatch, approve, monitor |

---

## Security & Compliance

- **IT Act 2000 §69** warrant required on every forensic session
- **Dual-control approval** — creating officer ≠ approving officer (NTRO Act 2004)
- **AES-256-GCM / ChaCha20-Poly1305 / ML-KEM-768** (FIPS 140-2 / FIPS 203)
- **SHA-256 hash chain** audit ledger — ISO 27037 / Indian Evidence Act §65B
- **mTLS 1.3** agent transport with `RequireAndVerifyClientCert`
- All sessions require IT Act 2000 §69 Warrant IDs

---

## Quick Start

### Prerequisites

- Rust ≥ 1.75 (`rustup`)
- Go ≥ 1.22
- OpenSSL (for mTLS cert generation)

### 1. One-command demo

```bash
./demo.sh
```

This builds the compiler, runs a dry-run smoke test, starts the server, and opens the dashboard at `http://localhost:8080/dashboard/`.

### 2. Manual setup

```bash
# Build compiler
cd compiler && cargo build --release

# Generate mTLS certificates (optional for local dev)
./scripts/gen-certs.sh certs/

# Start server
cd server
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=../compiler/target/release/jocky-compile \
go run . --port 8080

# Open dashboard
open http://localhost:8080/dashboard/
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JOCKY_HSM_MASTER_KEY` | Production | 64-hex-char HSM master key for HKDF |
| `JOCKY_ALLOW_DEV_KEY` | Dev only | Set to `1` to use a deterministic dev key |
| `JOCKY_COMPILER_PATH` | Yes | Path to `jocky-compile` binary |
| `JOCKY_WEB_DIR` | Optional | Web assets directory (default: `../web`) |
| `JOCKY_TLS_CERT` | mTLS | Server certificate path |
| `JOCKY_TLS_KEY` | mTLS | Server private key path |
| `JOCKY_TLS_CA` | mTLS | CA certificate for client verification |
| `JOCKY_TEST_HIVE` | Dev only | Path to test registry hive for dry-run |
| `JOCKY_TEST_MFT` | Dev only | Path to test MFT image for dry-run |

---

## JOCKY DSL

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";   // IT Act §69 warrant ID — mandatory
    collect {
        proc: all_processes,
        auditd: execve | connect,
        network: active_sockets,
        registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
        disk: mft_scan
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

Compile to LLVM IR:

```bash
jocky-compile compile --target linux triage.jocky
jocky-compile compile --target windows windows_session.jocky
```

---

## Testing

```bash
# Rust unit + integration tests (109 tests)
cd compiler
JOCKY_ALLOW_DEV_KEY=1 cargo test

# Go unit tests (24 tests)
cd server
go test ./...
```

---

## mTLS Certificate Generation

```bash
./scripts/gen-certs.sh certs/
# Produces: certs/ca.crt, server.{crt,key}, client.{crt,key}
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/compile` | Compile DSL to LLVM IR |
| `POST` | `/api/v1/sessions` | Create forensic session |
| `POST` | `/api/v1/sessions/:id/approve` | Countersign session (dual-control) |
| `POST` | `/api/v1/sessions/:id/domain-front` | Configure CDN covert transport |
| `GET`  | `/api/v1/sessions/:id` | Get session status |
| `GET`  | `/api/v1/audit/ledger` | Read blockchain audit ledger |
| `GET`  | `/api/v1/audit/verify` | Verify chain integrity |
| `WS`   | `/ws` | Live agent telemetry feed |

---

## Problem Statement Coverage

| Requirement | Implementation |
|-------------|----------------|
| Independent Programming Language | JOCKY DSL → LLVM IR frontend (`compiler/src/`) |
| CFG alteration / token generation | `CfgRandomizer` pass, `TokenShifter` pass |
| Polymorphic scripts | 7-pass pipeline: TokenShifter → VarEncryptor → CfgRandomizer → IatMasker → MetadataStripper → PolyEngine → BuildHashValidator |
| In-Memory Execution | `reflective_loader.rs` (no LoadLibrary), `thread_hijack.rs` |
| API Unhooking / Direct Syscalls | `syscall.rs` SSN resolver, fresh ntdll mapping |
| Process Hollowing | Emitted LLVM IR stubs in `codegen` |
| BYOVD Kernel Subversion | `kernel_driver.rs` — RTCore64 + DBUtil IOCTL primitives |
| Blockchain Audit Ledger | SHA-256 hash chain, §65B compliant |
| Post-Quantum Crypto | ML-KEM-768 (FIPS 203) in `ml_kem.rs` |
| Domain Fronting / CDN Routing | `domain_front.go` — SNI masking, TLS 1.3 |

---

*Strictly for authorized forensic operations. All sessions require IT Act 2000 §69 warrant authorization.*

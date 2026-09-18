# Installation

JOCKY runs on macOS, Linux, and Windows. Choose the method that fits your setup.

---

## One-line Install (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

This downloads the latest release binary for your platform and installs it to `/usr/local/bin/jocky-compile`.

## One-line Install (Windows PowerShell)

```powershell
irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex
```

Installs to `%USERPROFILE%\.jocky\bin\` and adds it to your PATH.

---

## Manual Download

Download the binary for your platform from the [latest release](https://github.com/vmmuthu31/jocky/releases/latest):

| Platform                       | File                         |
| ------------------------------ | ---------------------------- |
| macOS (Apple Silicon M1/M2/M3) | `jocky-macos-arm64`        |
| macOS (Intel)                  | `jocky-macos-x86_64`       |
| Linux x86_64                   | `jocky-linux-x86_64`       |
| Linux ARM64                    | `jocky-linux-arm64`        |
| Windows x86_64                 | `jocky-windows-x86_64.exe` |

**macOS / Linux** — make executable and move to PATH:

```bash
chmod +x jocky-macos-arm64
sudo mv jocky-macos-arm64 /usr/local/bin/jocky-compile
```

**Windows** — rename and add to PATH:

```powershell
Rename-Item jocky-windows-x86_64.exe jocky-compile.exe
Move-Item jocky-compile.exe "$env:USERPROFILE\.jocky\bin\"
# Add $env:USERPROFILE\.jocky\bin to your System PATH
```

---

## Build from Source

Requires: **Rust ≥ 1.75** (`rustup`) and **Go ≥ 1.22**

```bash
git clone https://github.com/vmmuthu31/jocky.git
cd jocky
make build        # builds jocky-compile
make install      # copies to /usr/local/bin (Unix)
```

Or directly with cargo:

```bash
cd compiler
cargo build --release
# binary at: target/release/jocky-compile
```

---

## Verify Installation

```bash
jocky-compile --help
```

Expected output:

```
JOCKY forensic DSL compiler — NTRO Hackathon 26148

Usage: jocky-compile <COMMAND>

Commands:
  compile   Compile a .jocky DSL script to LLVM IR
  parse     Parse a .jocky script and display the AST
  test      Run diagnostics on forensic artifact parsers
  new       Scaffold a ready-to-run .jocky script from templates
  run       Execute forensic scan from JOCKY script and generate reports
  help      Print this message or the help of the given subcommand(s)
```

---

## VSCode Extension

Install the JOCKY language extension for syntax highlighting, snippets, and one-click compile:

1. Open VSCode
2. Press `Ctrl+Shift+X` (Extensions)
3. Search **"JOCKY Forensic DSL"**
4. Click Install

Or install from the `.vsix` file:

```bash
cd jocky/vscode-extension
npm install
npx vsce package        # produces jocky-language-0.1.0.vsix
code --install-extension jocky-language-0.1.0.vsix
```

---

## Server Setup

The JOCKY server provides the web dashboard and REST API. Requires Go ≥ 1.22.

```bash
cd server
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=$(which jocky-compile) \
go run . --port 8080
```

Then open: http://localhost:8080/dashboard/

See [Server Configuration](./server-config.md) for production setup with mTLS.

---

## Environment Variables

| Variable                 | Required   | Default           | Description                                            |
| ------------------------ | ---------- | ----------------- | ------------------------------------------------------ |
| `JOCKY_HSM_MASTER_KEY` | Production | —                | 64-hex-char master key for HKDF key derivation         |
| `JOCKY_ALLOW_DEV_KEY`  | Dev only   | —                | Set`1` to use built-in dev key (never in production) |
| `JOCKY_COMPILER_PATH`  | Server     | `jocky-compile` | Path to compiler binary                                |
| `JOCKY_WEB_DIR`        | Server     | `../web`        | Web dashboard assets directory                         |
| `JOCKY_TLS_CERT`       | mTLS       | —                | Server TLS certificate path                            |
| `JOCKY_TLS_KEY`        | mTLS       | —                | Server private key path                                |
| `JOCKY_TLS_CA`         | mTLS       | —                | CA certificate for client verification                 |

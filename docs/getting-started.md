# Getting Started

This guide walks you from zero to running your first forensic scan in under 5 minutes.

---

## Step 1 — Install

**macOS / Linux** — one command, auto-detects your platform:
```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

**macOS (Homebrew):**
```bash
brew install vmmuthu31/jocky/jocky
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex
```

Verify:
```bash
jocky-compile --help
```

---

## Step 2 — Write your first script

Create a file called `my_scan.jocky`:

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";   // required — IT Act §69
    collect {
        proc: all_processes,
        network: active_sockets
    };
    encrypt chacha20(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

Or use a built-in template:
```bash
jocky-compile new linux-ebpf --output my_scan.jocky
```

---

## Step 3 — Compile to LLVM IR

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile \
  --input my_scan.jocky \
  --output my_scan.ll \
  --target linux
```

Output:
```
✓ Compiled  my_scan.jocky → my_scan.ll
  build-id  : jocky-4a7f3c9e12b08d21
  digest    : e3b2f1a9...
  junk-blks : 55
  apis-masked: 1
```

Every build produces a **unique** binary — different hash, renamed identifiers, obfuscated control flow.

---

## Step 4 — Run a local dry-run

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile run my_scan.jocky \
  --target linux --dry-run
```

This shows what the agent *would* collect. On a Linux machine it actually reads `/proc` and `/proc/net/tcp` live.

---

## Step 5 — Start the web dashboard

```bash
cd server
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=$(which jocky-compile) \
go run . --port 8080
```

Open: **http://localhost:8080/dashboard/**

From the dashboard you can:
- Write and compile `.jocky` scripts in the browser
- Dispatch sessions to field agents
- Countersign sessions (dual-control approval)
- Configure CDN domain-fronting covert transport
- Watch live agent telemetry
- Verify the blockchain audit ledger (IT Act §65B)

---

## Quick reference

```bash
# Scaffold templates
jocky-compile new triage
jocky-compile new windows-persistence
jocky-compile new linux-ebpf
jocky-compile new pqc-vault

# Compile
jocky-compile compile -i scan.jocky -o scan.ll --target linux
jocky-compile compile -i scan.jocky -o scan.ll --target windows

# Parse / validate only
jocky-compile parse -i scan.jocky

# Run live forensic scan
jocky-compile run scan.jocky --target linux --host prod-01 --scan-id JCK-001

# Test individual parsers
jocky-compile test --test-type proc
jocky-compile test --test-type ebpf
jocky-compile test --test-type registry --file /path/to/hive

# Full demo (builds + starts server + opens browser)
./demo.sh
```

---

## Next steps

- [Language Reference](./language-reference.md) — full DSL syntax
- [CLI Reference](./cli-reference.md) — every flag and command
- [Installation](./installation.md) — all install methods, VSCode extension, mTLS setup

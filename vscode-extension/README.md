# JOCKY Forensic DSL — VSCode Extension

Syntax highlighting, snippets, and one-click compile for `.jocky` forensic scripts.

---

## Features

### Syntax Highlighting
Open any `.jocky` file and get instant colour-coded highlighting for:
- Keywords: `forensic`, `session`, `collect`, `encrypt`, `transmit`
- Artifact types: `registry`, `memory`, `proc`, `auditd`, `network`, `disk`, `ext4`
- Encryption algorithms: `aes256`, `chacha20`, `ml_kem`
- Warrant IDs (`NTRO-YYYY-TYPE-NNNN`) highlighted as strings
- Comments (`//`)

### Snippets
Type a prefix and press `Tab` to scaffold a full session:

| Prefix | Inserts |
|--------|---------|
| `jocky` | Full forensic session template |
| `win` | Windows session (registry + memory + disk) |
| `linux` | Linux session (proc + auditd + network) |
| `pqc` | Post-quantum (ML-KEM-768) session |

### One-Click Compile Button
When a `.jocky` file is open, a **▶ JOCKY Compile** button appears in the editor title bar (top-right). Click it to compile to LLVM IR in the integrated terminal:

```
JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile --input <file> --output <file>.ll --target linux
```

### New Session Command
Press `Cmd+Shift+P` → **JOCKY: New Forensic Session** to pick a template:
- `triage` — quick incident triage
- `windows-persistence` — registry + startup + memory
- `linux-ebpf` — proc + auditd + ext4 journal
- `pqc-vault` — post-quantum encrypted exfil

---

## Requirements

Install the JOCKY compiler first:

**macOS (Homebrew):**
```bash
brew install vmmuthu31/jocky/jocky
```

**macOS / Linux (curl):**
```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
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

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `jocky.compilerPath` | `jocky-compile` | Path to the `jocky-compile` binary |
| `jocky.defaultTarget` | `linux` | Default compile target (`linux` or `windows`) |

Change via `Cmd+,` → search **JOCKY**.

---

## Quick Start

1. Open VSCode in your project folder
2. Create a file: `scan.jocky`
3. Type `jocky` + `Tab` — a full template is inserted
4. Fill in your warrant ID and target IP
5. Click **▶ JOCKY Compile** in the title bar
6. The compiled LLVM IR appears as `scan.ll`

### Example script

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";   // IT Act §69 — required
    collect {
        proc: all_processes,
        network: active_connections,
        auditd: execve | open
    };
    encrypt chacha20(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| JOCKY: Compile to LLVM IR | Title bar ▶ button | Compile active `.jocky` file |
| JOCKY: New Forensic Session | `Cmd+Shift+P` | Scaffold a new session from template |

---

## Platform Support

This extension works on **macOS**, **Windows**, and **Linux** — any platform VSCode runs on.
The `jocky-compile` binary is available for:
- macOS Apple Silicon (arm64)
- macOS Intel (x86_64)
- Linux x86_64 / arm64
- Windows x86_64

---

## More

- [GitHub](https://github.com/vmmuthu31/jocky)
- [Full DSL Spec](https://github.com/vmmuthu31/jocky/blob/main/docs/jocky-dsl-spec.md)
- [Installation Guide](https://github.com/vmmuthu31/jocky/blob/main/docs/installation.md)

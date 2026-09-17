# CLI Reference

`jocky-compile` is the JOCKY command-line tool. It compiles `.jocky` scripts, scaffolds new sessions, runs forensic scans, and tests forensic parsers.

---

## Global Usage

```
jocky-compile <COMMAND> [OPTIONS]
```

---

## Commands

### `compile` — Compile a script to LLVM IR

Parses and validates a `.jocky` script, then emits a polymorphic LLVM IR file. The 7-pass obfuscation pipeline runs automatically — every build has a unique hash, renamed identifiers, and obfuscated control flow.

```bash
jocky-compile compile \
  --input  <FILE.jocky> \
  --output <FILE.ll> \
  --target <linux|windows>
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | required | Path to `.jocky` source script |
| `-o, --output` | required | Output `.ll` LLVM IR file |
| `-t, --target` | `windows` | Target OS: `linux` or `windows` |

**Example:**
```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile \
  --input scan.jocky --output scan.ll --target linux
```

**Output:**
```
✓ Compiled  scan.jocky → scan.ll
  build-id  : jocky-18d6078148ec1188
  digest    : af77da1e...
  junk-blks : 55
  apis-masked: 1
```

---

### `run` — Execute a forensic scan

Compiles and executes a `.jocky` script. On a live Linux/Windows agent host this runs real forensic collection. On a dev machine it runs what's available locally and reports honestly what requires the target host.

```bash
jocky-compile run <SCRIPT.jocky> \
  --target <linux|windows|ubuntu> \
  --host   <HOSTNAME> \
  --scan-id <ID> \
  --reports-dir <DIR> \
  [--dry-run]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `<SCRIPT>` | required | Path to `.jocky` script (positional) |
| `-t, --target` | `linux` | Target OS |
| `--host` | `WORKSTATION-01` | Target host identifier for reports |
| `--scan-id` | `JCK-2026-001` | Forensic scan ID |
| `--reports-dir` | `reports/` | Output directory for JSON + HTML reports |
| `--dry-run` | false | Validate and describe without executing |

**Example — dry-run:**
```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile run scan.jocky --target linux --dry-run
```

**Example — live scan:**
```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile run scan.jocky \
  --target linux --host prod-server-01 --scan-id JCK-2026-042
```

**Dry-run env vars (for local parser testing):**
```bash
JOCKY_TEST_HIVE=/path/to/NTUSER.DAT   # test registry parser
JOCKY_TEST_MFT=/path/to/mft.bin       # test MFT parser
```

---

### `new` — Scaffold a new script from template

Generates a ready-to-edit `.jocky` script using one of the built-in templates.

```bash
jocky-compile new <TEMPLATE> [--output <FILE.jocky>]
```

**Templates:**

| Template | Description |
|----------|-------------|
| `triage` | Minimal profile-based scan (fastest) |
| `windows-persistence` | Registry Run keys + UserAssist + MFT scan |
| `linux-ebpf` | eBPF probes + auditd + /proc + network |
| `pqc-vault` | ML-KEM-768 post-quantum encrypted evidence |

**Example:**
```bash
jocky-compile new linux-ebpf --output my_scan.jocky
```

---

### `parse` — Parse and display the AST

Validates syntax and prints the parsed AST without generating any output.

```bash
jocky-compile parse --input <FILE.jocky>
```

**Example:**
```bash
jocky-compile parse --input scan.jocky
# Parsed 1 forensic session(s):
#   Session 1:
#     target   = 10.0.5.42
#     warrant  = NTRO-2026-LINUX-0089
#     collect  = 4 item(s)
#     encrypt  = ChaCha20
#     transmit = wss://forensics-gw.ntro.gov.in/telemetry
```

---

### `test` — Test forensic parsers

Runs a specific parser against a file to validate it works correctly.

```bash
jocky-compile test --test-type <TYPE> [--file <PATH>]
```

**Types:**

| Type | What it tests |
|------|--------------|
| `registry` | Windows registry hive parser (REGF format) |
| `mft` | NTFS MFT record parser |
| `proc` | Linux /proc process enumeration (runs live on Linux) |
| `evtx` | Windows Event Log (.evtx) parser |
| `auditd` | Linux auditd log parser |
| `ebpf` | eBPF probe emitter (prints BPF C source) |

**Example:**
```bash
jocky-compile test --test-type proc
jocky-compile test --test-type registry --file /path/to/NTUSER.DAT
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Parse error in `.jocky` script |
| `2` | Validation error (e.g. registry directive on Linux target) |
| `3` | Obfuscation pipeline rejected duplicate build digest |
| `1` | I/O error reading/writing files |

---

## Shell Completion

```bash
# bash
jocky-compile completions bash >> ~/.bashrc

# zsh
jocky-compile completions zsh >> ~/.zshrc

# fish
jocky-compile completions fish > ~/.config/fish/completions/jocky-compile.fish
```

*(Completion generation requires clap feature — coming in v0.2)*

---

## Environment Variables

```bash
JOCKY_ALLOW_DEV_KEY=1        # Use dev key (no HSM required)
JOCKY_HSM_MASTER_KEY=<hex>   # 64-hex production HSM master key
JOCKY_TEST_HIVE=<path>       # Registry hive for dry-run testing
JOCKY_TEST_MFT=<path>        # MFT image for dry-run testing
```

# jocky-compile — CLI Reference

## Synopsis

```
jocky-compile <COMMAND> [OPTIONS] [ARGS]
```

---

## Commands

### `compile` — Compile a .jocky file to LLVM IR

```bash
jocky-compile compile [OPTIONS] <INPUT>
```

**Options:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target <platform>` | `-t` | `linux` | Target platform: `linux` or `windows` |
| `--output <file>` | `-o` | `<input>.ll` | Output file path |
| `--seed <hex>` | | (random) | Build seed for reproducible compilation (v1.1.0) |
| `--verbose` | `-v` | off | Print detailed compilation steps |

**Example:**
```bash
jocky-compile compile --target linux triage.jocky
jocky-compile compile --target windows -o agent.ll windows-scan.jocky
jocky-compile compile -t linux -v triage.jocky
```

**Output:**
```
✓ Compiled  triage.jocky → triage.ll
  build-id  : jocky-17d43a8b2f001c44
  digest    : sha256:a1b2c3...
  junk-blks : 55
  apis-masked: 12
```

---

### `validate` — Validate a .jocky file without compiling

```bash
jocky-compile validate <INPUT>
```

Parses the file and checks:
- Syntax correctness
- Warrant format
- Target format
- Collect directive types
- Encryption algorithm validity
- Transmit endpoint format

Exits 0 on success, 1 on validation error. No IR is produced.

```bash
jocky-compile validate triage.jocky
# ✓ Validation passed.
```

---

### `dry-run` — Simulate collection without writing to disk

```bash
jocky-compile dry-run [--warrant <id>]
```

Simulates a full collection run using the local machine as the target. No data is exfiltrated or written to disk. Useful for installation verification.

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile dry-run
```

---

### `version` — Print version information

```bash
jocky-compile version
# JOCKY compiler v1.0.0
# Build: 2026-09-17
# Rust: 1.75.0
# LLVM: 17.0.0
```

---

## Global Options

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Print help for the current command |
| `--version`, `-V` | Print version and exit |

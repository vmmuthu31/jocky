# JOCKY DSL — Language Overview

The JOCKY Domain-Specific Language is a purpose-built forensic scripting language. It compiles to LLVM Intermediate Representation (IR) through a 7-pass polymorphic obfuscation pipeline.

---

## Design Goals

| Goal | How JOCKY Achieves It |
|------|----------------------|
| Legal compliance by design | `warrant:` is required at the grammar level — not enforced by a runtime check that can be skipped |
| Minimal footprint | Compiles to LLVM IR; no interpreter, no bytecode VM |
| Operational security | Every build is unique — no two `.ll` files share function names or CFG structure |
| Cross-platform | Single source compiles to `x86_64-unknown-linux-gnu` or `x86_64-pc-windows-msvc` |
| Analyst-friendly | Simple, declarative syntax readable by forensic analysts who are not programmers |

---

## File Extension

JOCKY source files use the `.jocky` extension:
```
triage.jocky
windows-persistence.jocky
linux-network-scan.jocky
```

---

## Compilation Lifecycle

```
triage.jocky
    │  jocky-compile compile --target linux triage.jocky
    ▼
triage.ll   (polymorphic LLVM IR)
    │  clang triage.ll -o triage-agent   (optional)
    ▼
triage-agent  (native binary)
```

The `.ll` file is the primary output. It can be dispatched to a target machine and compiled there with any LLVM toolchain, or it can be compiled locally and the resulting binary deployed.

---

## Reserved Keywords

| Keyword | Role |
|---------|------|
| `forensic` | Opens a session block |
| `session` | Part of `forensic session { }` |
| `target` | Specifies the forensic target |
| `warrant` | IT Act §69 warrant ID (mandatory) |
| `collect` | Opens the collection directive block |
| `encrypt` | Specifies encryption algorithm |
| `transmit` | Specifies C2 endpoint |
| `via` | Used with `transmit` |
| `key` | Parameter for encryption key source |
| `aes256` | AES-256-GCM encryption |
| `chacha20` | ChaCha20-Poly1305 encryption |
| `ml_kem` | ML-KEM-768 post-quantum encryption |
| `hsm_derived` | Key derived from HSM |
| `all_processes` | Collect all running processes |
| `active_sockets` | Collect active network connections |
| `execve` | auditd execve events |
| `connect` | auditd connect events |
| `mft_scan` | NTFS MFT scan |

---

## Comment Syntax

```jocky
// This is a single-line comment

forensic session {
    target: "10.0.5.42";    // inline comment
    warrant: "NTRO-2026-LINUX-0089";   // IT Act §69 warrant ID
    ...
}
```

Block comments are not supported. Use `//` for all comments.

---

## String Literals

Strings are enclosed in double quotes:
```jocky
target: "192.168.1.105";
warrant: "NTRO-2026-CYBER-0421";
transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
```

Single quotes are not supported.

---

## Statement Terminator

Each field in the session body ends with a semicolon `;`. Items inside `collect {}` are separated by commas.

```jocky
forensic session {
    target: "...";
    warrant: "...";
    collect {
        proc: all_processes,     // comma, not semicolon
        network: active_sockets  // last item — no trailing comma
    };                           // semicolon after closing brace
    encrypt aes256(key: hsm_derived);
    transmit via: "...";
}
```

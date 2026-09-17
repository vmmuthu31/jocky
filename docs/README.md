# JOCKY — Enterprise Digital Forensics Platform

> **NTRO Hackathon 26148 · Smart India Hackathon · Blockchain & Cybersecurity Track**

JOCKY is an enterprise-grade digital forensics command-and-control platform for authorized law-enforcement and intelligence operations under the **IT Act 2000 Section 69**.

---

## What Makes JOCKY Different

| Feature | JOCKY | Traditional Tools |
|---------|-------|-------------------|
| Custom DSL with warrant enforcement | ✓ | ✗ |
| Polymorphic LLVM IR compilation | ✓ | ✗ |
| Post-quantum cryptography (ML-KEM-768) | ✓ | Rare |
| Blockchain audit ledger (IT Act §65B) | ✓ | ✗ |
| In-memory execution (no disk artifacts) | ✓ | Partial |
| BYOVD kernel-level forensics | ✓ | ✗ |
| Dual-officer approval workflow | ✓ | ✗ |
| Cross-platform (Windows + Linux agents) | ✓ | Partial |

---

## Quick Start

```bash
# Install (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh

# Write your first forensic session
cat > triage.jocky << 'EOF'
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        network: active_sockets
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
EOF

# Compile
jocky-compile compile --target linux triage.jocky
```

---

## Legal Notice

JOCKY is **strictly for authorized forensic operations**. Every session requires a valid IT Act 2000 §69 warrant ID. Unauthorized use violates the Information Technology Act 2000 and the NTRO Act 2004.

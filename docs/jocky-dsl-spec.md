# JOCKY DSL Language Specification

## 1. Syntax Overview

```
forensic session {
    target: "<IP_or_hostname>";
    warrant: "<NTRO-YYYY-TYPE-NNNN>";
    collect {
        <artifact_type>: <expression>,
        <artifact_type>: <expression>
    };
    encrypt <algo>(key: <key_source>);
    transmit via: "<endpoint>";
}
```

## 2. Required Fields (in order)

| Field | Description |
|-------|-------------|
| `target` | IP address or hostname of the forensic target |
| `warrant` | IT Act 2000 Section 69 warrant ID (NTRO-YYYY-TYPE-NNNN format) |
| `collect` | Block of artifact collection directives |
| `encrypt` | Encryption algorithm and key source |
| `transmit` | Central server endpoint |

## 3. Artifact Types

| Type | Platform | Description |
|------|----------|-------------|
| `registry` | Windows | Registry hives (HKLM, HKCU) |
| `memory` | Windows | Process memory dumps |
| `disk` | Windows | MFT, USN journal, Prefetch |
| `network` | Both | Active TCP/UDP connections |
| `proc` | Linux | /proc filesystem enumeration |
| `auditd` | Linux | auditd syscall logs |
| `ext4` | Linux | ext4 journal analysis |

## 4. Encryption Algorithms

| Keyword | Standard | Notes |
|---------|----------|-------|
| `aes256` | AES-256-GCM (FIPS 140-2) | Default |
| `chacha20` | ChaCha20-Poly1305 | Lightweight alternative |
| `ml_kem` | NIST FIPS 203 | Post-quantum (planned Q1 2027) |

## 5. Key Sources

| Source | Description |
|--------|-------------|
| `hsm_derived` | Key derived from Hardware Security Module (FIPS 140-2 Level 3) |

## 6. Sample Scripts

### Windows — Basic Forensics
```
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,
        memory: process "lsass.exe",
        disk: mft_parse
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "forensics.ntro.gov.in";
}
```

### Linux — eBPF Probe Session
```
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        auditd: execve | open,
        network: active_connections,
        ext4: journal_parse
    };
    encrypt ml_kem(key: hsm_derived); // Post-quantum secure
    transmit via: "cloudfront.ntro.gov.in";
}
```

## 7. Compliance Notes

- Every `warrant` value must correspond to a valid IT Act 2000 Section 69 order
- Sessions are cryptographically logged to the blockchain audit ledger
- Multi-signature authorization (2-3 officers) required before session execution
- All sessions auto-terminate after 4 hours unless renewed via Operations Commander

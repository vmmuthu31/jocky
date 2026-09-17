# Multiple Artifact Types

Real forensic investigations rarely need just one artifact type. This chapter shows how to combine multiple directives for comprehensive collection.

---

## Combining Artifacts

Any number of artifacts can appear in a single `collect { }` block, separated by commas:

```jocky
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        proc: all_processes,
        network: active_sockets,
        registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
        disk: mft_scan,
        disk: prefetch
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## Investigation Patterns

### 1. Lateral Movement Triage (Windows)

```jocky
forensic session {
    target: "10.0.0.25";
    warrant: "NTRO-2026-CYBER-0088";
    collect {
        proc: all_processes,
        network: active_sockets,
        registry: HKLM\SYSTEM\CurrentControlSet\Services,
        registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
        disk: prefetch
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

**What this reveals:**
- Active connections to C2 servers
- Newly installed services (persistence mechanisms)
- Autorun entries
- Recently executed binaries (Prefetch)

---

### 2. Privilege Escalation Investigation (Linux)

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        network: active_sockets,
        auditd: execve | connect
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

**What this reveals:**
- Processes running as root/SYSTEM unexpectedly
- Outbound connections to unusual destinations
- Execution of `/bin/bash`, `chmod +s`, `sudo`, etc.

---

### 3. Data Exfiltration Hunt (Windows)

```jocky
forensic session {
    target: "192.168.50.12";
    warrant: "NTRO-2026-WIN-0003";
    collect {
        proc: all_processes,
        network: active_sockets,
        disk: mft_scan,
        disk: usn_journal,
        memory: all
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

**What this reveals:**
- Unusual large file transfers
- Recently created/deleted files (MFT + USN journal)
- In-memory malware or injected code

---

### 4. Full-Spectrum Triage (Both Platforms)

```jocky
forensic session {
    target: "172.16.0.50";
    warrant: "NTRO-2026-TRIAGE-0001";
    collect {
        proc: all_processes,
        network: active_sockets,
        auditd: execve | connect,
        ext4: journal
    };
    encrypt chacha20(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## Collection Order

Artifacts are collected in the order they appear in the `collect { }` block. For volatile data (memory, network connections) that can change or disappear, list them first:

```jocky
collect {
    // Volatile first
    network: active_sockets,
    proc: all_processes,
    memory: all,
    // Non-volatile last
    disk: mft_scan,
    registry: HKLM\Software\...
};
```

# Collect Block

The `collect { }` block specifies which forensic artifacts to gather from the target. It contains one or more comma-separated collection directives.

---

## Syntax

```jocky
collect {
    <artifact_type>: <expression>,
    <artifact_type>: <expression>
};
```

- Items are separated by **commas**.
- No trailing comma after the last item.
- The block itself ends with a **semicolon** after the closing `}`.

---

## All Artifact Types

### Cross-Platform

| Directive | Platforms | What It Collects |
|-----------|-----------|-----------------|
| `proc: all_processes` | Both | All running processes: PID, name, path, command line, parent PID |
| `network: active_sockets` | Both | Active TCP/UDP connections: local addr, remote addr, state, PID |

### Linux-Specific

| Directive | What It Collects |
|-----------|-----------------|
| `proc: all_processes` | /proc enumeration: stat, status, cmdline, fd, maps |
| `auditd: execve` | auditd EXECVE records (process execution logs) |
| `auditd: connect` | auditd CONNECT records (network connection logs) |
| `auditd: execve \| connect` | Both execve and connect events |
| `ext4: journal` | ext4 filesystem journal (deleted file recovery) |

### Windows-Specific

| Directive | What It Collects |
|-----------|-----------------|
| `registry: <path>` | Registry hive or key (any HKLM/HKCU path) |
| `disk: mft_scan` | Full NTFS Master File Table (MFT) scan |
| `disk: usn_journal` | USN (Update Sequence Number) change journal |
| `disk: prefetch` | Windows Prefetch files (execution history) |
| `memory: <pid>` | Dump memory of a specific process (by PID) |
| `memory: all` | Dump all process memory |

---

## Examples

### Minimum (one artifact)

```jocky
collect {
    proc: all_processes
};
```

### Linux triage (multiple artifacts)

```jocky
collect {
    proc: all_processes,
    auditd: execve | connect,
    network: active_sockets
};
```

### Windows persistence check

```jocky
collect {
    registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
    registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run,
    disk: prefetch,
    proc: all_processes
};
```

### Full Windows forensics

```jocky
collect {
    proc: all_processes,
    network: active_sockets,
    registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
    registry: HKLM\SYSTEM\CurrentControlSet\Services,
    disk: mft_scan,
    disk: usn_journal,
    disk: prefetch,
    memory: all
};
```

### Full Linux forensics

```jocky
collect {
    proc: all_processes,
    network: active_sockets,
    auditd: execve | connect,
    ext4: journal
};
```

---

## Registry Path Syntax

Registry paths use Windows backslash notation without quotes:

```jocky
registry: HKLM\Software\Microsoft\Windows NT\CurrentVersion,
registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run,
registry: HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

Supported hive prefixes: `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`

---

## What Happens at Runtime

For each directive in `collect { }`, the compiler emits the corresponding LLVM IR stub that will execute on the target:

- `proc: all_processes` → emits `collect_processes_linux()` or `collect_processes_windows()`
- `auditd: execve` → emits `collect_auditd_execve()` which reads `/var/log/audit/audit.log`
- `registry: HKLM\...` → emits `collect_registry()` with the path encoded as an IR constant
- `disk: mft_scan` → emits `collect_mft()` using raw volume handle `\\.\C:`

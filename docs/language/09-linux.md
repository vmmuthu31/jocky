# Linux-Specific Collection

Linux forensics in JOCKY uses the `/proc` filesystem, `auditd` log analysis, and ext4 journal parsing.

---

## Process Collection — Linux

```jocky
collect {
    proc: all_processes
};
```

On Linux, this walks `/proc/[pid]/` for every running process and collects:

| File | Data Collected |
|------|---------------|
| `/proc/[pid]/stat` | PID, name, state, PPID, CPU stats |
| `/proc/[pid]/status` | UID/GID, memory usage, capability sets |
| `/proc/[pid]/cmdline` | Full command line (null-separated) |
| `/proc/[pid]/exe` | Symlink to the executable path |
| `/proc/[pid]/maps` | Memory maps — loaded libraries, heap, stack |
| `/proc/[pid]/fd/` | Open file descriptors |
| `/proc/[pid]/net/tcp` | Per-process TCP connections |

---

## auditd Collection

**Prerequisite:** `auditd` must be running on the target. If it is not running, JOCKY falls back to reading `/var/log/auth.log` and `/var/log/syslog`.

### execve events

```jocky
collect {
    auditd: execve
};
```

Collects all EXECVE syscall records from `/var/log/audit/audit.log`. Each record contains:
- Timestamp
- PID / parent PID
- UID / GID of the executing user
- Full command line (including all arguments)
- Working directory

**Useful for:** detecting malicious script execution, privilege escalation (`sudo`, `su`), shells spawned from unusual parents.

### connect events

```jocky
collect {
    auditd: connect
};
```

Collects all CONNECT syscall records. Each record contains:
- Timestamp
- PID making the connection
- Local and remote IP:port
- Socket type (TCP / UDP)

**Useful for:** detecting C2 beaconing, DNS queries to unusual domains, unexpected outbound traffic.

### Both execve and connect

```jocky
collect {
    auditd: execve | connect
};
```

The `|` operator combines multiple auditd event types in a single directive. This is the most common pattern for Linux incident response.

---

## ext4 Journal Analysis

```jocky
collect {
    ext4: journal
};
```

Reads the ext4 filesystem journal from the root partition (`/dev/sda1` or auto-detected). Recovers:
- Recently deleted files (file name, inode, size, timestamps)
- Recently created files
- Metadata changes

**Requires:** root privileges on the target.

---

## Complete Linux Session Example

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        network: active_sockets,
        auditd: execve | connect,
        ext4: journal
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## Target Compilation

For a Linux target, compile with `--target linux`:

```bash
jocky-compile compile --target linux linux-session.jocky
```

The compiler emits LLVM IR with target triple `x86_64-unknown-linux-gnu`.

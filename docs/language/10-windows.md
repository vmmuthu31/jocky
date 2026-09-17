# Windows-Specific Collection

Windows forensics in JOCKY covers the registry, NTFS filesystem structures, process memory, and Prefetch files.

---

## Process Collection — Windows

```jocky
collect {
    proc: all_processes
};
```

On Windows, this uses `NtQuerySystemInformation(SystemProcessInformation)` to enumerate all processes and for each collects:
- Process name, PID, parent PID
- Full image path
- Command line
- Session ID
- Token privileges (admin, SYSTEM, etc.)
- Loaded modules (DLL list)

---

## Registry Collection

```jocky
collect {
    registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
};
```

Collects all values under the specified registry key. Multiple registry directives are supported:

```jocky
collect {
    registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
    registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run,
    registry: HKLM\SYSTEM\CurrentControlSet\Services,
    registry: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
};
```

### Supported Hive Prefixes

| Prefix | Full Name |
|--------|-----------|
| `HKLM` | HKEY_LOCAL_MACHINE |
| `HKCU` | HKEY_CURRENT_USER |
| `HKCR` | HKEY_CLASSES_ROOT |
| `HKU` | HKEY_USERS |
| `HKCC` | HKEY_CURRENT_CONFIG |

### Common Forensic Registry Paths

| Path | Purpose |
|------|---------|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Autorun on login |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Per-user autorun |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Installed services |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | Winlogon hooks |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | Boot-time executables |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently opened files |

---

## Disk — MFT Scan

```jocky
collect {
    disk: mft_scan
};
```

Reads the NTFS Master File Table (MFT) directly via a raw volume handle (`\\.\C:`). Collects for every file entry:
- File name (including alternate names)
- Full path
- File size
- Creation, modification, access, MFT-modified timestamps ($STANDARD_INFORMATION + $FILE_NAME)
- Attributes (hidden, system, compressed, encrypted)
- Is-deleted flag

**Useful for:** finding deleted files, timestomping detection (timestamp discrepancy between $STANDARD_INFORMATION and $FILE_NAME), identifying malware left in non-obvious locations.

---

## Disk — USN Journal

```jocky
collect {
    disk: usn_journal
};
```

Reads the NTFS Update Sequence Number (USN) change journal. This is a circular log maintained by NTFS of all file system changes (create, modify, rename, delete, extended-attribute change).

**Useful for:** reconstructing file activity even after files are deleted, detecting anti-forensic renaming/deletion.

---

## Disk — Prefetch

```jocky
collect {
    disk: prefetch
};
```

Reads all `.pf` files from `C:\Windows\Prefetch\`. Each Prefetch file records:
- Executable name
- Last execution timestamp
- Execution count
- Files and directories accessed during execution

**Useful for:** proving that a program was executed even after it is deleted, detecting "living-off-the-land" binaries.

---

## Memory Dump

```jocky
// Dump a specific process by PID
collect {
    memory: 1337
};

// Dump all process memory
collect {
    memory: all
};
```

Uses `NtReadVirtualMemory` (or `MiniDumpWriteDump` for full dumps). Useful for:
- Extracting injected shellcode
- Finding plaintext credentials in memory
- Recovering in-memory-only malware

---

## Complete Windows Session Example

```jocky
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-WIN-0042";
    collect {
        proc: all_processes,
        network: active_sockets,
        registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
        registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run,
        registry: HKLM\SYSTEM\CurrentControlSet\Services,
        disk: mft_scan,
        disk: usn_journal,
        disk: prefetch
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## Target Compilation

For a Windows target, compile with `--target windows`:

```bash
jocky-compile compile --target windows windows-session.jocky
```

The compiler emits LLVM IR with target triple `x86_64-pc-windows-msvc`.

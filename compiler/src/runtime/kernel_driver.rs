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

    /// Emit LLVM IR stubs for the BYOVD loader.
    /// The actual vulnerable driver + exploit code is deliberately omitted —
    /// only the interface stubs are generated here.
    pub fn emit_byovd_ir_stubs() -> String {
        r#"; BYOVD loader interface stubs
; Actual exploit primitives are compiled separately from a classified payload.
declare i32 @jocky_byovd_load_vuln_driver(i8* %driver_path)
declare i32 @jocky_byovd_get_kernel_write_primitive()
declare i32 @jocky_byovd_load_unsigned_driver(i8* %unsigned_driver_path)
declare void @jocky_byovd_cleanup()
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
        assert!(stubs.contains("jocky_byovd_load_vuln_driver"), "BYOVD load stub required");
        assert!(stubs.contains("jocky_byovd_cleanup"), "cleanup stub required");
    }

    #[test]
    fn test_kernel_init_uses_byovd() {
        let ir = KernelDriverEmitter::emit_kernel_init_ir();
        assert!(ir.contains("jocky_byovd_load_vuln_driver"), "must use BYOVD path");
        assert!(ir.contains("ret i32"), "must return");
    }
}

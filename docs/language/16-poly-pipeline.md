# 7-Pass Obfuscation Pipeline

Every compiled JOCKY session passes through the `PolyBuilder` — a 7-stage LLVM IR transformation pipeline. Each pass applies a different obfuscation technique, and the combined effect makes static analysis and signature detection unreliable.

---

## Pipeline Overview

```
Raw LLVM IR
    │
    ▼
Pass 1: TokenShifter         rename all @function and %variable names to hex
    │
    ▼
Pass 2: VarEncryptor         XOR-encrypt string and integer constants
    │
    ▼
Pass 3: CfgRandomizer        shuffle basic block ordering within functions
    │
    ▼
Pass 4: IatMasker            obfuscate external function import names
    │
    ▼
Pass 5: MetadataStripper     remove !dbg, !tbaa, source filenames, DISubprogram
    │
    ▼
Pass 6: PolyEngine           inject unreachable junk basic blocks
    │
    ▼
Pass 7: BuildHashValidator   compute SHA-256 digest of final IR
    │
    ▼
Obfuscated LLVM IR (.ll)
```

---

## Pass 1 — TokenShifter

**What it does:** Renames every function and variable to a deterministic but unguessable hex identifier.

**Input:**
```llvm
define void @collect_processes() {
  %proc_count = alloca i32
  ...
}
```

**Output:**
```llvm
define void @x3f7a1c2b() {
  %x8d4e9f01 = alloca i32
  ...
}
```

The hex names are derived from `HMAC-SHA256(build_seed, original_name)`, truncated to 8 hex chars. Same seed → same names (deterministic); different seed → completely different names.

---

## Pass 2 — VarEncryptor

**What it does:** XOR-encrypts all string constants and integer literals. Decryption is inlined at the use site.

**Input:**
```llvm
%key_str = global [20 x i8] c"jocky-session-key-v1"
```

**Output:**
```llvm
; Encrypted bytes with XOR key 0x4A
%x9c1e77 = global [20 x i8] c"\x21\x25\x29\x2d\x3a..."
; Decryption stub inlined at every use:
; @x3f7a1c2b() { xor [20 x i8]* %x9c1e77, 0x4A → use result }
```

---

## Pass 3 — CfgRandomizer

**What it does:** Shuffles the ordering of basic blocks within each function. The control-flow logic is identical, but the layout in the IR file is randomized.

This defeats pattern matching that relies on basic block position (e.g. "the decryption routine is always the third basic block").

---

## Pass 4 — IatMasker

**What it does:** Obfuscates external API import names (the LLVM `declare` stubs for Windows API calls).

**Input:**
```llvm
declare i64 @NtOpenProcess(...)
declare i64 @NtReadVirtualMemory(...)
```

**Output:**
```llvm
declare i64 @x7b3c9e12(...)
declare i64 @xa4f201de(...)
```

A runtime lookup table (also obfuscated) maps the hex name to the real API name, resolved dynamically via PEB Ldr walk.

---

## Pass 5 — MetadataStripper

**What it does:** Removes all LLVM debug metadata, DWARF sections, source file paths, and DISubprogram nodes.

Without this pass, the `.ll` file would contain:
```llvm
!0 = !DISubprogram(name: "collect_processes", file: !1, line: 42, ...)
!1 = !DIFile(filename: "compiler/src/codegen.rs", directory: "/Users/barfi/...")
```

After stripping, none of this is present. A reverse engineer cannot determine the source language, file structure, or original function names from the IR alone.

---

## Pass 6 — PolyEngine

**What it does:** Injects unreachable junk basic blocks into each function. These blocks contain random but syntactically valid LLVM IR instructions that are never executed.

```llvm
define void @x3f7a1c2b() {
entry:
  br label %x_real_1

x_junk_0:                              ; dead block — never reached
  %xa = add i64 0, 123456789
  %xb = mul i64 %xa, 987654321
  br label %x_junk_1

x_junk_1:                              ; dead block
  ...

x_real_1:                              ; actual code starts here
  ...
}
```

Junk block count per compilation is randomly between 40 and 80. This increases the binary size modestly (~15%) but makes automated analysis significantly harder.

---

## Pass 7 — BuildHashValidator

**What it does:** Computes `SHA-256(obfuscated IR text)` and writes it to the compile output. This hash is also written to the blockchain audit ledger.

```
digest: sha256:a1b2c3d4e5f60001...64chars
```

The digest allows verification that the exact compiled artifact associated with a session has not been tampered with. Any bit-flip in the `.ll` file will produce a different digest.

---

## Pipeline Report

After compilation, `jocky-compile` prints a summary:

```
✓ Compiled  triage.jocky → triage.ll
  build-id  : jocky-17d43a8b2f001c44
  digest    : sha256:a1b2c3...
  junk-blks : 55
  apis-masked: 12
```

| Metric | Meaning |
|--------|---------|
| `build-id` | `jocky-<build_seed_hex>` — unique per compilation |
| `digest` | SHA-256 of the final obfuscated IR |
| `junk-blks` | Total dead blocks injected by PolyEngine |
| `apis-masked` | Number of `declare` stubs renamed by IatMasker |

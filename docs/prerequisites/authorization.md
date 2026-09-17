# Authorization Setup

Before using JOCKY operationally, the following authorizations must be in place.

---

## Step 1 — Obtain a §69 Warrant

A valid **IT Act 2000 Section 69** authorisation order must be issued by the competent authority before any forensic session begins. The warrant ID embedded in every `.jocky` file must match this order.

**Warrant ID format:** `NTRO-YYYY-TYPE-NNNN`

| Component | Meaning | Example |
|-----------|---------|---------|
| `NTRO` | Issuing agency | `NTRO` |
| `YYYY` | Calendar year | `2026` |
| `TYPE` | Case type (`CYBER`, `LINUX`, `WIN`, `TRIAGE`) | `CYBER` |
| `NNNN` | Zero-padded sequence number | `0089` |

**Example:** `NTRO-2026-CYBER-0089`

---

## Step 2 — Enrol at Least Two Officers

JOCKY enforces dual-control: the officer who **creates** a session cannot **approve** it. You need at least two enrolled officers before any session can be dispatched.

Officer accounts are managed via the JOCKY server API:

```bash
# Create officer A (admin)
curl -X POST http://localhost:8080/api/v1/officers \
  -H "Content-Type: application/json" \
  -d '{"officer_id":"NTRO-OFF-001","name":"Officer Alpha","role":"ADMIN"}'

# Create officer B (approver)
curl -X POST http://localhost:8080/api/v1/officers \
  -H "Content-Type: application/json" \
  -d '{"officer_id":"NTRO-OFF-002","name":"Officer Beta","role":"APPROVER"}'
```

---

## Step 3 — Configure HSM Master Key

Production sessions use an HSM-derived key. Set the master key via environment variable:

```bash
# 64 hex characters = 32 bytes = 256-bit key
export JOCKY_HSM_MASTER_KEY="a0b1c2d3e4f5...64hexchars"
```

For development and testing:
```bash
export JOCKY_ALLOW_DEV_KEY=1
```

> **Warning:** Never use `JOCKY_ALLOW_DEV_KEY=1` in production. The dev key is deterministic and provides no real security.

---

## Step 4 — Verify Setup

Run the dry-run smoke test to confirm all components are configured:

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile dry-run
```

Expected output:
```
✓ Warrant check      NTRO-2026-DRYRUN-0001
✓ Compiler check     v1.0.0
✓ Network scan       127.0.0.1:8080 (server)
✓ Audit log          /var/log/audit/audit.log
✓ Crypto             AES-256-GCM / HKDF-SHA-256
✓ Blockchain         genesis block OK
All checks passed.
```

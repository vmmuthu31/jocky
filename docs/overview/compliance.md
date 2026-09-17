# Compliance & Legal Framework

## Statutory Basis

JOCKY operations are governed by the following Indian law:

| Statute | Relevance |
|---------|-----------|
| **IT Act 2000 §69** | Authorises interception, monitoring, and decryption of information by designated agencies |
| **NTRO Act 2004** | Governs NTRO officer authorisation and chain-of-command approval |
| **Indian Evidence Act §65B** | Sets admissibility standards for electronic records in court proceedings |
| **ISO/IEC 27037:2012** | International guidelines for digital evidence identification, collection, acquisition, and preservation |

---

## Mandatory Controls

### 1. Warrant Enforcement (Compile-Time)

Every `.jocky` file **must** contain a `warrant:` field with a valid NTRO warrant ID in the format `NTRO-YYYY-TYPE-NNNN`. The parser treats a missing or malformed warrant as a **hard error** — the compile command exits with code 2 and no IR is produced.

```
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";   ← MANDATORY
    ...
}
```

### 2. Dual-Control Approval

The officer who **creates** a session cannot **approve** it. The server enforces this at the API level: `POST /sessions/:id/approve` returns HTTP 403 if the approving officer matches the creating officer.

```
Creating officer  →  session status: PENDING_APPROVAL
Approving officer →  session status: APPROVED  (must be a different officer)
```

### 3. Immutable Audit Trail

Every session event is appended to a SHA-256 hash chain. The chain cannot be altered without invalidating all subsequent block hashes. This satisfies the **IT Act §65B** requirement that electronic records be authentic, unaltered, and accompanied by a certificate from a responsible official.

### 4. Encryption in Transit and at Rest

All telemetry is encrypted with AES-256-GCM (FIPS 140-2) before transmission. The agent-to-server channel uses **mutual TLS 1.3** with `RequireAndVerifyClientCert` — both sides present certificates signed by the same CA.

---

## Evidence Admissibility Checklist

Before submitting collected evidence to a court or tribunal, verify:

- [ ] Warrant ID matches a valid §69 authorisation order
- [ ] Session was approved by a different officer (dual-control log)
- [ ] Blockchain ledger integrity check passes (`GET /api/v1/audit/verify`)
- [ ] Encryption key provenance is documented (HSM serial + HKDF parameters)
- [ ] Chain-of-custody log is complete (creation → approval → collection → transmission)
- [ ] §65B certificate prepared by the responsible NTRO officer

---

## Disclaimer

JOCKY is a tool for **authorized forensic analysis only**. Operators are responsible for:

1. Obtaining valid §69 authorisation before initiating any session.
2. Ensuring the approving officer is not the creating officer.
3. Storing and protecting the audit ledger as part of the case file.
4. Complying with all applicable data protection regulations.

Unauthorized use constitutes an offence under the IT Act 2000 and NTRO Act 2004.

# REST API Reference

Base URL: `http://localhost:8080/api/v1`

All request and response bodies are JSON. All timestamps are RFC3339.

---

## POST /compile

Compile a JOCKY DSL string to LLVM IR.

**Request:**
```json
{
  "source": "forensic session { ... }",
  "target": "linux"
}
```

**Response 200:**
```json
{
  "ir": "target triple = \"x86_64-unknown-linux-gnu\"\n...",
  "build_id": "jocky-17d43a8b2f001c44",
  "digest": "sha256:a1b2c3...",
  "junk_blocks": 55,
  "apis_masked": 12
}
```

**Response 400:**
```json
{ "error": "missing mandatory field `warrant`" }
```

---

## POST /sessions

Create a new forensic session.

**Request:**
```json
{
  "officer_id": "NTRO-OFF-001",
  "target": "10.0.5.42",
  "warrant": "NTRO-2026-LINUX-0089",
  "platform": "linux",
  "notes": "Lateral movement investigation"
}
```

**Response 201:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_APPROVAL",
  "created_at": "2026-09-17T10:00:00Z",
  "created_by": "NTRO-OFF-001",
  "target": "10.0.5.42",
  "warrant": "NTRO-2026-LINUX-0089"
}
```

---

## POST /sessions/:id/approve

Countersign a session (dual-control). The approving officer must differ from the creating officer.

**Request:**
```json
{
  "officer_id": "NTRO-OFF-002"
}
```

**Response 200:**
```json
{
  "session_id": "550e8400...",
  "status": "APPROVED",
  "approved_at": "2026-09-17T10:05:00Z",
  "approved_by": "NTRO-OFF-002"
}
```

**Response 403:**
```json
{ "error": "approving officer must differ from creating officer" }
```

---

## POST /sessions/:id/domain-front

Configure CDN domain fronting for a session.

**Request:**
```json
{
  "enabled": true,
  "front_domain": "d1234.cloudfront.net",
  "real_host": "forensics-gw.ntro.gov.in",
  "backend_url": "https://origin.ntro.gov.in"
}
```

**Response 200:**
```json
{
  "session_id": "550e8400...",
  "dial_url": "https://d1234.cloudfront.net/telemetry",
  "sni": "d1234.cloudfront.net",
  "host_header": "forensics-gw.ntro.gov.in",
  "tls_fingerprint": "SHA256:..."
}
```

---

## GET /sessions/:id

Get session status and metadata.

**Response 200:**
```json
{
  "session_id": "550e8400...",
  "status": "APPROVED",
  "target": "10.0.5.42",
  "warrant": "NTRO-2026-LINUX-0089",
  "created_at": "2026-09-17T10:00:00Z",
  "created_by": "NTRO-OFF-001",
  "approved_at": "2026-09-17T10:05:00Z",
  "approved_by": "NTRO-OFF-002",
  "telemetry_packets": 0
}
```

---

## GET /audit/ledger

Return the full blockchain audit ledger.

**Response 200:**
```json
{
  "chain": [
    {
      "index": 0,
      "timestamp": "2026-09-17T09:00:00Z",
      "event_type": "GENESIS",
      "session_id": "",
      "data": "",
      "hash": "0000000000...64chars",
      "prev_hash": "0000000000...64zeros"
    },
    {
      "index": 1,
      "timestamp": "2026-09-17T10:00:00Z",
      "event_type": "SESSION_CREATED",
      "session_id": "550e8400...",
      "data": "base64...",
      "hash": "a1b2c3...64chars",
      "prev_hash": "0000000000...64chars"
    }
  ]
}
```

---

## GET /audit/verify

Verify blockchain chain integrity.

**Response 200 (intact):**
```json
{ "valid": true, "block_count": 5, "message": "Chain integrity verified." }
```

**Response 200 (tampered):**
```json
{
  "valid": false,
  "block_count": 5,
  "message": "Hash mismatch at block 3: expected a1b2..., got ff00..."
}
```

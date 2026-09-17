# Architecture

## Compiler Pipeline

```
.jocky source
    │
    ▼
┌─────────────┐
│   Lexer     │  Tokenizes source into keyword / ident / string / punct tokens
└──────┬──────┘
       │
    ▼
┌─────────────┐
│   Parser    │  Builds AST: ForensicSession { target, warrant, collect[], encrypt, transmit }
│             │  Hard error if warrant field is absent
└──────┬──────┘
       │
    ▼
┌─────────────┐
│  Validator  │  Warrant format check (NTRO-YYYY-TYPE-NNNN), target IP/hostname, collect types
└──────┬──────┘
       │
    ▼
┌─────────────┐
│  Codegen    │  Emits LLVM IR: session setup, collect stubs, runtime module bodies
│             │  Stitches in: NtdllUnhooker, ProcessHollow, ReflectiveInject,
│             │               ReflectiveLoader, ThreadHijackEmitter, KernelDriverEmitter
└──────┬──────┘
       │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  PolyBuilder — 7-Pass Obfuscation Pipeline                  │
│                                                             │
│  Pass 1  TokenShifter        rename all identifiers         │
│  Pass 2  VarEncryptor        encrypt string/int constants   │
│  Pass 3  CfgRandomizer       shuffle basic-block order      │
│  Pass 4  IatMasker           obfuscate API import names     │
│  Pass 5  MetadataStripper    remove debug/DWARF sections    │
│  Pass 6  PolyEngine          inject junk basic blocks       │
│  Pass 7  BuildHashValidator  compute deterministic digest   │
└──────┬──────────────────────────────────────────────────────┘
       │
    ▼
Obfuscated LLVM IR (.ll)   →  llc / clang  →  binary
```

---

## Server Architecture

The Go server uses **Gin** for HTTP routing and **nhooyr.io/websocket** for the agent channel.

```
HTTP :8080
  │
  ├─ /dashboard/          ← static web assets
  ├─ /api/v1/
  │   ├─ POST /compile                ← compile DSL → IR
  │   ├─ POST /sessions               ← create session (officer A)
  │   ├─ POST /sessions/:id/approve   ← countersign (officer B ≠ A)
  │   ├─ POST /sessions/:id/domain-front ← configure CDN fronting
  │   ├─ GET  /sessions/:id           ← session status
  │   ├─ GET  /audit/ledger           ← blockchain ledger dump
  │   └─ GET  /audit/verify           ← chain integrity check
  └─ /ws                              ← WebSocket agent telemetry
```

### Dual-Control Flow

```
Officer A  ──POST /sessions──▶  Server creates session (status: PENDING_APPROVAL)
Officer B  ──POST /approve───▶  Server validates B ≠ A, signs block, status: APPROVED
Agent      ──connects /ws────▶  Receives approved session payload
Agent      ──streams data────▶  Server writes telemetry → blockchain ledger
```

---

## Blockchain Audit Ledger

Every significant event — session created, approved, telemetry received, domain-front configured — is appended to a SHA-256 hash chain:

```
Block N:
  index      : N
  timestamp  : RFC3339
  session_id : uuid
  event_type : "SESSION_CREATED" | "SESSION_APPROVED" | "TELEMETRY" | ...
  data       : base64(payload)
  hash       : SHA256(prev_hash + index + timestamp + data)
  prev_hash  : hash of block N-1 (genesis block uses "0"*64)
```

The chain is verified by recomputing every hash and checking linkage. Any tampering causes an immediate mismatch, satisfying IT Act §65B electronic evidence requirements.

---

## Cryptography Stack

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| Symmetric encryption | AES-256-GCM | FIPS 140-2 |
| Alternate symmetric | ChaCha20-Poly1305 | RFC 8439 |
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203 |
| Key derivation | HKDF-SHA-256 | RFC 5869 |
| Transport | mTLS 1.3 | RFC 8446 |
| Audit hash | SHA-256 | FIPS 180-4 |

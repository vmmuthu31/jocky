# Encryption Directives

All collected forensic data is encrypted before transmission. The `encrypt` field selects the algorithm and key source.

---

## Syntax

```jocky
encrypt <algorithm>(key: <key_source>);
```

---

## Algorithms

### `aes256` — AES-256-GCM

The standard algorithm. FIPS 140-2 compliant. Use this for all production operations.

```jocky
encrypt aes256(key: hsm_derived);
```

- **Block size:** 128-bit
- **Key size:** 256-bit
- **Mode:** GCM (Galois/Counter Mode) — authenticated encryption
- **Nonce:** 96-bit random per-message nonce
- **Authentication tag:** 128-bit GCM tag

---

### `chacha20` — ChaCha20-Poly1305

Lightweight alternative. Preferred on embedded/low-power targets.

```jocky
encrypt chacha20(key: hsm_derived);
```

- **Key size:** 256-bit
- **Mode:** ChaCha20-Poly1305 AEAD (RFC 8439)
- **Nonce:** 96-bit
- **Authentication tag:** 128-bit Poly1305 tag

---

### `ml_kem` — ML-KEM-768 (Post-Quantum)

NIST FIPS 203 post-quantum key encapsulation mechanism. Provides quantum-resistant key exchange.

```jocky
encrypt ml_kem(key: hsm_derived);
```

- **Security level:** NIST Level 3 (~AES-192 equivalent)
- **Algorithm:** CRYSTALS-Kyber (ML-KEM-768)
- **Key encapsulation:** 1184-byte public key, 2400-byte ciphertext
- **Usage:** Encapsulates a 256-bit symmetric key, then encrypts data with AES-256-GCM

> **Note:** Post-quantum is the default target for NTRO operations from 2027 onwards, per internal security directive.

---

## Key Sources

### `hsm_derived`

The production key source. Derives a per-session encryption key using **HKDF-SHA-256** from the HSM master key.

```
HKDF-SHA-256(
    salt     = session_id (UUID, 16 bytes),
    ikm      = JOCKY_HSM_MASTER_KEY (32 bytes),
    info     = "jocky-session-key-v1",
    length   = 32 bytes
)
```

This means each session uses a unique encryption key even if two sessions share the same master key.

**Requires:** `JOCKY_HSM_MASTER_KEY` environment variable (64 hex chars) or `JOCKY_ALLOW_DEV_KEY=1`.

---

## Algorithm Comparison

| Algorithm | Key Size | AEAD | Quantum-Resistant | FIPS |
|-----------|----------|------|------------------|------|
| `aes256` | 256-bit | Yes (GCM) | No | 140-2 |
| `chacha20` | 256-bit | Yes (Poly1305) | No | No |
| `ml_kem` | 768-bit lattice | Yes (hybrid) | Yes | 203 |

---

## Choosing an Algorithm

- **Standard forensic operations:** `aes256` — maximum compatibility, FIPS compliant
- **Resource-constrained targets:** `chacha20` — faster on CPUs without AES-NI
- **Long-lived evidence (10+ year retention):** `ml_kem` — future-proof against quantum decryption

---

## Examples

```jocky
// Standard
encrypt aes256(key: hsm_derived);

// Lightweight
encrypt chacha20(key: hsm_derived);

// Post-quantum
encrypt ml_kem(key: hsm_derived);
```

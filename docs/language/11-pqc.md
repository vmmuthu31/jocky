# Post-Quantum Cryptography

JOCKY implements **ML-KEM-768** (CRYSTALS-Kyber), the NIST FIPS 203 post-quantum key encapsulation mechanism standardized in August 2024.

---

## Why Post-Quantum?

Current forensic evidence may be subject to a "harvest now, decrypt later" attack: an adversary captures encrypted telemetry today and stores it, intending to decrypt it once a large-scale quantum computer is available (estimated 10–15 years).

For evidence with a long retention period (court cases, national security archives), the encryption must be quantum-resistant. ML-KEM-768 provides this.

---

## Using PQC in JOCKY

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-PQC-0001";
    collect {
        proc: all_processes,
        network: active_sockets,
        disk: mft_scan
    };
    encrypt ml_kem(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
```

---

## How ML-KEM-768 Works in JOCKY

The `ml_kem` encrypt directive uses a hybrid encryption scheme:

```
1. Server generates ML-KEM-768 key pair:
   (ek_server, dk_server) = ML-KEM.KeyGen()

2. Agent encapsulates a shared secret:
   (K, c) = ML-KEM.Encaps(ek_server)
   where K = 32-byte shared secret
         c = 1088-byte ciphertext

3. Agent derives session key:
   session_key = HKDF-SHA-256(K, session_id, "jocky-pqc-v1")

4. Agent encrypts telemetry:
   ciphertext = AES-256-GCM(session_key, plaintext)

5. Agent transmits:
   { ml_kem_ciphertext: c, aes_ciphertext: ciphertext, aes_tag: tag }

6. Server decapsulates:
   K = ML-KEM.Decaps(dk_server, c)
   session_key = HKDF-SHA-256(K, session_id, "jocky-pqc-v1")
   plaintext = AES-256-GCM-Decrypt(session_key, ciphertext, tag)
```

This is a **hybrid KEM** — the actual data encryption is AES-256-GCM (fast, hardware-accelerated), but the key exchange is quantum-resistant.

---

## ML-KEM-768 Parameters

| Parameter | Value |
|-----------|-------|
| NIST standard | FIPS 203 |
| Security level | Level 3 (~AES-192) |
| Public key size | 1184 bytes |
| Ciphertext size | 1088 bytes |
| Shared secret | 32 bytes |
| Decapsulation key | 2400 bytes |

---

## When to Use PQC

| Scenario | Recommendation |
|----------|---------------|
| Standard incident response | `aes256` — simpler, faster, sufficient |
| High-value targets / critical infrastructure | `ml_kem` — future-proof |
| Long-term evidence archives (10+ years) | `ml_kem` — mandatory |
| Resource-constrained embedded targets | `chacha20` — lightweight |
| NTRO Directive 2027 compliance | `ml_kem` |

---

## PQC Session Example

```jocky
forensic session {
    target: "172.16.1.100";
    warrant: "NTRO-2026-INT-0099";
    collect {
        proc: all_processes,
        network: active_sockets,
        memory: all,
        disk: mft_scan
    };
    encrypt ml_kem(key: hsm_derived);
    transmit via: "wss://forensics-pqc.ntro.gov.in/telemetry";
}
```

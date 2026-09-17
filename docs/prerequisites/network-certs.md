# Network & Certificate Setup

## Network Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 8080 | HTTP | Inbound | Web dashboard + REST API |
| 8443 | HTTPS/mTLS | Inbound | Production mTLS agent transport |
| 443 | HTTPS | Outbound | CDN domain-fronting (if enabled) |

For production deployments, place the server behind a reverse proxy (nginx, Caddy) and use port 443 with a valid TLS certificate.

---

## mTLS Certificate Generation

JOCKY uses mutual TLS so both the server and the field agent verify each other's identity. The included helper script creates a self-signed CA and issues server + client certificates from it.

```bash
./scripts/gen-certs.sh certs/
```

This produces:

```
certs/
├── ca.crt          ← CA certificate (distribute to both server and agent)
├── ca.key          ← CA private key (keep secret)
├── server.crt      ← Server TLS certificate
├── server.key      ← Server TLS private key
├── client.crt      ← Agent/client certificate
└── client.key      ← Agent/client private key
```

### Using the Certificates with the Server

```bash
JOCKY_TLS_CERT=certs/server.crt \
JOCKY_TLS_KEY=certs/server.key \
JOCKY_TLS_CA=certs/ca.crt \
./server/jocky-server --port 8443
```

### Agent Certificate Distribution

Copy `client.crt`, `client.key`, and `ca.crt` to the target machine alongside the agent binary. The agent loads them at startup via environment variables or command-line flags.

---

## Production CA Considerations

For production deployments:

1. Use a real CA (internal PKI or a private CA from a trusted provider).
2. Issue short-lived certificates (90 days or less).
3. Implement certificate revocation (CRL or OCSP).
4. Store private keys in an HSM where possible.

The `gen-certs.sh` script is for development and testing only.

# Environment Variables

## Compiler (`jocky-compile`)

| Variable | Required | Description |
|----------|----------|-------------|
| `JOCKY_HSM_MASTER_KEY` | Production | 64 hex chars (32 bytes) — HSM master key for HKDF key derivation |
| `JOCKY_ALLOW_DEV_KEY` | Dev only | Set to `1` to use a deterministic dev key; never use in production |
| `JOCKY_TEST_HIVE` | Dev only | Path to a test registry hive file for dry-run registry parsing |
| `JOCKY_TEST_MFT` | Dev only | Path to a test MFT image for dry-run MFT parsing |
| `RUST_LOG` | Optional | Logging level: `error`, `warn`, `info`, `debug`, `trace` |

## Server (`jocky-server`)

| Variable | Required | Description |
|----------|----------|-------------|
| `JOCKY_HSM_MASTER_KEY` | Production | Same 64-hex-char master key as compiler |
| `JOCKY_ALLOW_DEV_KEY` | Dev only | Set to `1` for dev key |
| `JOCKY_COMPILER_PATH` | Yes | Absolute path to the `jocky-compile` binary |
| `JOCKY_WEB_DIR` | Optional | Path to web assets directory (default: `../web`) |
| `JOCKY_TLS_CERT` | mTLS | Path to server TLS certificate |
| `JOCKY_TLS_KEY` | mTLS | Path to server TLS private key |
| `JOCKY_TLS_CA` | mTLS | Path to CA certificate for client verification |
| `PORT` | Optional | Override listen port (alternative to `--port` flag) |

## Example `.env` File (Development)

```bash
JOCKY_ALLOW_DEV_KEY=1
JOCKY_COMPILER_PATH=/usr/local/bin/jocky-compile
JOCKY_WEB_DIR=/opt/jocky/web
RUST_LOG=info
```

## Example `.env` File (Production)

```bash
JOCKY_HSM_MASTER_KEY=a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1
JOCKY_COMPILER_PATH=/usr/bin/jocky-compile
JOCKY_WEB_DIR=/usr/share/jocky/web
JOCKY_TLS_CERT=/etc/jocky/tls/server.crt
JOCKY_TLS_KEY=/etc/jocky/tls/server.key
JOCKY_TLS_CA=/etc/jocky/tls/ca.crt
```

Load with:
```bash
set -a; source .env; set +a
jocky-server --port 8443
```

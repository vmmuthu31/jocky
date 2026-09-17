# System Requirements

## Operator Workstation (Compiler + Server)

These are the machines that run `jocky-compile` and the JOCKY server.

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / macOS 12 / Windows 10 | Ubuntu 22.04 / macOS 14 / Windows 11 |
| CPU | x86_64 or ARM64, 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB free | 10 GB SSD |
| Network | Outbound HTTPS (443) | Dedicated forensics VLAN |

## Field Agent Target

The agent binary runs on the forensic target. JOCKY supports:

| Platform | Architecture | Notes |
|----------|-------------|-------|
| Windows 10 / 11 | x86_64 | Requires admin/SYSTEM privileges for BYOVD |
| Windows Server 2016–2022 | x86_64 | Same |
| Ubuntu / Debian Linux | x86_64, ARM64 | Root required for auditd and MFT |
| RHEL / CentOS / Fedora | x86_64 | Same |

## JOCKY Server

| Component | Minimum |
|-----------|---------|
| OS | Ubuntu 20.04+ or any Linux x86_64 |
| RAM | 2 GB |
| Disk | 20 GB (audit ledger grows over time) |
| Ports | TCP 8080 (HTTP), TCP 8443 (mTLS, optional) |
| TLS certificates | Required for production mTLS |

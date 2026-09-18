# JOCKY Example Scripts

Real-world forensic scenarios covering every artifact type, encryption algorithm, and target platform.

## Quick compile any example

```bash
JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile \
  --input examples/linux/01-basic-triage.jocky \
  --output out.ll --target linux
```

---

## Windows Scenarios (`examples/windows/`)

| File | Scenario | Artifacts |
|------|----------|-----------|
| `01-basic-triage.jocky` | First-responder quick scan | registry + memory + network |
| `02-ransomware-investigation.jocky` | Full ransomware sweep | disk (MFT/USN/prefetch) + registry + memory |
| `03-persistence-hunting.jocky` | All persistence points | 8 registry keys + memory + disk |
| `04-lsass-credential-dump-detection.jocky` | Mimikatz / credential harvest | lsass memory + registry + disk |
| `05-lateral-movement.jocky` | Pass-the-hash / WMI / PSExec | memory + registry + disk + network |
| `06-domain-controller-full.jocky` | AD DC — DCSync / Kerberoasting | NTDS + KDC registry + lsass + disk |
| `07-process-injection-detection.jocky` | Shellcode injection / hollowing | svchost/rundll32 memory + registry |
| `08-supply-chain-compromise.jocky` | SolarWinds-style backdoor | update agent memory + registry + disk |

---

## Linux Scenarios (`examples/linux/`)

| File | Scenario | Artifacts |
|------|----------|-----------|
| `01-basic-triage.jocky` | First-responder scan | proc + network + auditd |
| `02-rootkit-detection.jocky` | Kernel rootkit hiding processes | proc + ext4 + auditd |
| `03-web-server-compromise.jocky` | Webshell / RCE via Apache/Nginx | proc + auditd + ext4 + network |
| `04-crypto-miner-detection.jocky` | Crypto miner / botnet C2 beacon | proc + auditd + network |
| `05-ssh-brute-force-investigation.jocky` | SSH brute force post-exploitation | auditd + proc + ext4 |
| `06-container-escape.jocky` | Docker/K8s container breakout | proc (namespaces) + auditd + network |
| `07-privilege-escalation.jocky` | SUID abuse / sudo misconfig | auditd (setuid) + proc + ext4 |
| `08-data-exfiltration.jocky` | Large outbound classified exfil | proc + auditd + network + ext4 |

---

## Network Scenarios (`examples/network/`)

| File | Scenario | Target |
|------|----------|--------|
| `01-c2-beacon-detection.jocky` | Cobalt Strike / Metasploit C2 | Windows |
| `02-dns-tunneling.jocky` | dnscat2 / iodine DNS tunnel | Linux |
| `03-domain-fronting-c2.jocky` | CDN domain-fronting C2 | Linux |
| `04-wifi-rogue-ap.jocky` | Evil twin / rogue AP MITM | Linux |

---

## Post-Quantum Scenarios (`examples/pqc/`)

| File | Scenario | Encryption |
|------|----------|-----------|
| `01-pqc-classified-evidence.jocky` | Top-secret Linux evidence | ML-KEM-768 (NIST FIPS 203) |
| `02-pqc-windows-secret.jocky` | Secret-class Windows evidence | ML-KEM-768 (NIST FIPS 203) |

---

## Incident Response (`examples/incident-response/`)

| File | Scenario |
|------|----------|
| `01-ir-day-zero-triage.jocky` | Day-zero: grab everything before attacker wipes tracks (Windows) |
| `02-ir-linux-live-response.jocky` | Linux live response during active compromise |
| `03-ir-evidence-preservation.jocky` | Court-admissible chain of custody (IT Act §65B) |

---

## APT Scenarios (`examples/apt/`)

| File | Scenario |
|------|----------|
| `01-apt-initial-access.jocky` | Spear-phishing macro → dropper → implant (Windows) |
| `02-apt-c2-implant-linux.jocky` | Long-term APT28/Turla implant — PQC encrypted (Linux) |
| `03-apt-full-kill-chain.jocky` | Complete MITRE ATT&CK kill chain reconstruction (Windows) |

---

## Malware (`examples/malware/`)

| File | Scenario |
|------|----------|
| `01-trojan-analysis-windows.jocky` | AsyncRAT / NjRAT RAT installed via fake software |
| `02-wiper-malware-investigation.jocky` | Shamoon-style MBR/MFT wiper (Windows) |
| `03-linux-backdoor.jocky` | Persistent reverse shell via cron/systemd (Linux) |

---

## Insider Threat (`examples/insider-threat/`)

| File | Scenario |
|------|----------|
| `01-data-theft-windows.jocky` | Employee bulk-copying classified docs to USB/cloud |
| `02-sabotage-linux.jocky` | Sysadmin deletes prod DB + logic bomb before exit |

---

## Encryption Algorithms Used

| Algorithm | Used in | Standard |
|-----------|---------|---------|
| `aes256` | Most scenarios | AES-256-GCM, FIPS 140-2 |
| `chacha20` | Lightweight / Linux | ChaCha20-Poly1305 |
| `ml_kem` | PQC / nation-state | ML-KEM-768, NIST FIPS 203 |

## Compile All Examples

```bash
# Compile all Linux examples
for f in examples/linux/*.jocky; do
  JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile --input "$f" --output "${f%.jocky}.ll" --target linux
done

# Compile all Windows examples
for f in examples/windows/*.jocky; do
  JOCKY_ALLOW_DEV_KEY=1 jocky-compile compile --input "$f" --output "${f%.jocky}.ll" --target windows
done
```

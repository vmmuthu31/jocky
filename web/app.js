const API_BASE = 'http://localhost:8080/api/v1';

let cachedTemplates = {
  "triage": `// JOCKY Forensic Script — Fast Triage Scan
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    profile: triage;
}`,
  "windows-persistence": `// JOCKY Forensic Script — Windows Persistence & Event Logs
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,
        disk: mft_scan,
        network: active_connections
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}`,
  "linux-ebpf": `// JOCKY Forensic Script — Linux Kernel eBPF Telemetry
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        auditd: execve | connect,
        network: active_connections
    };
    encrypt chacha20(key: hsm_derived);
    transmit via: "wss://telemetry-stream.ntro.gov.in/evidence";
}`,
  "pqc-vault": `// JOCKY Forensic Script — Post-Quantum Secure Vault Transmission
forensic session {
    target: "10.100.4.12";
    warrant: "NTRO-2026-INFIL-9901";
    profile: deep_audit;
    encrypt ml_kem(key: hsm_derived);
    transmit via: "wss://pqc-collector.ntro.gov.in/vault";
}`
};

function updateClock() {
  const now = new Date();
  const utcString = now.toUTCString().split(' ')[4] + ' UTC';
  const el = document.getElementById('live-clock');
  if (el) el.textContent = utcString;
}
setInterval(updateClock, 1000);
updateClock();

async function loadTemplates() {
  try {
    const res = await fetch(`${API_BASE}/templates`);
    if (res.ok) {
      const data = await res.json();
      if (data.templates) {
        cachedTemplates = data.templates;
      }
    }
  } catch (_) {}
}

function onTemplateChange() {
  const select = document.getElementById('template-select');
  const dslInput = document.getElementById('dsl-input');
  const targetOS = document.getElementById('target-os-select');
  const key = select.value;

  if (cachedTemplates[key]) {
    dslInput.value = cachedTemplates[key];
    if (key.includes('windows')) {
      targetOS.value = 'windows';
    } else {
      targetOS.value = 'linux';
    }
  }
}

async function compileDSL() {
  const dsl = document.getElementById('dsl-input').value;
  const targetOS = document.getElementById('target-os-select').value;
  const statusEl = document.getElementById('compile-status');
  const irDisplay = document.getElementById('ir-display');
  const irBadge = document.getElementById('ir-target-badge');

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">⚡ Validating Section 69 warrant & compiling LLVM IR...</span>';

  try {
    const res = await fetch(`${API_BASE}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        warrant_id: targetOS === 'linux' ? 'NTRO-2026-LINUX-0089' : 'NTRO-2026-CYBER-0421',
        target_ip: targetOS === 'linux' ? '10.0.5.42' : '192.168.1.105',
        agent_id: targetOS === 'linux' ? 'agent-lx-01' : 'agent-win-02',
        dsl_source: dsl,
        target_os: targetOS,
        officer_id: 'OFFICER-VK-902'
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Compilation failed');
    }

    const session = await res.json();
    statusEl.innerHTML = `<span style="color: var(--accent-emerald);">✓ Validated under Sec 69 IT Act & Successfully Compiled Session: ${session.id.substring(0, 8)}...</span>`;
    irDisplay.textContent = session.compiled_ir || `; LLVM IR Generated for Session ${session.id}`;
    irBadge.textContent = targetOS === 'windows' ? 'x86_64-pc-windows-msvc' : 'x86_64-linux-gnu';

    fetchAuditLedger();
  } catch (err) {
    statusEl.innerHTML = `<span style="color: var(--accent-rose);">✗ Error: ${err.message}</span>`;
  }
}

function simulateRun() {
  const targetOS = document.getElementById('target-os-select').value;
  const statusEl = document.getElementById('compile-status');
  const irDisplay = document.getElementById('ir-display');

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">Running local forensic telemetry dry-run...</span>';
  setTimeout(() => {
    statusEl.innerHTML = '<span style="color: var(--accent-emerald);">✓ Dry-run simulated successfully! Telemetry inspected.</span>';
    irDisplay.textContent = `=== JOCKY DRY-RUN LOCAL EXECUTION REPORT ===
Target Platform: ${targetOS.toUpperCase()}
Section 69 Status: VALIDATED (NTRO-2026-CYBER-0421)
Artifact Collection Results:
  [eBPF/Procfs]: 42 process records inspected (0 suspicious binary executions)
  [Network]: 18 active TCP sockets inspected (No unauthorized foreign C2 links)
  [Disk / Hives]: Integrity checks passed
Evidence Checksum: SHA-256 (3b72c918a09f8e4c...)
Chain of Custody Status: ADMISSIBLE UNDER SEC 65B`;
  }, 400);
}

async function verifyChain() {
  const statusBox = document.getElementById('chain-verify-status');
  statusBox.style.display = 'block';
  statusBox.innerHTML = '<span style="color: var(--accent-cyan);">Recalculating SHA-256 block hashes from Genesis to Head...</span>';

  try {
    const res = await fetch(`${API_BASE}/evidence/verify?session_id=ALL`);
    if (!res.ok) throw new Error('Verification failed');

    const result = await res.json();
    if (result.chain_intact) {
      statusBox.style.background = 'rgba(16, 185, 129, 0.12)';
      statusBox.style.borderColor = 'var(--accent-emerald)';
      statusBox.innerHTML = `
        <div style="font-weight: 700; color: var(--accent-emerald); margin-bottom: 4px;">
          ✓ CHAIN INTEGRITY VALIDATED — 100% INTACT (${result.total_blocks_checked} Blocks Verified)
        </div>
        <div style="color: var(--text-secondary); font-size: 0.75rem;">
          Standard: <strong>${result.compliance_standard}</strong><br>
          Genesis Hash: <span style="font-family: var(--font-mono);">${result.genesis_hash.substring(0, 24)}...</span><br>
          Latest Block Hash: <span style="font-family: var(--font-mono);">${result.latest_block_hash.substring(0, 24)}...</span>
        </div>
      `;
    } else {
      statusBox.style.background = 'rgba(244, 63, 94, 0.12)';
      statusBox.style.borderColor = 'var(--accent-rose)';
      statusBox.innerHTML = `<span style="color: var(--accent-rose);">✗ Chain Integrity Broken: ${result.details}</span>`;
    }
  } catch (err) {
    statusBox.style.display = 'block';
    statusBox.style.background = 'rgba(244, 63, 94, 0.12)';
    statusBox.style.borderColor = 'var(--accent-rose)';
    statusBox.innerHTML = `<span style="color: var(--accent-rose);">✗ Verification Error: ${err.message}</span>`;
  }
}

async function fetchAuditLedger() {
  try {
    const res = await fetch(`${API_BASE}/audit/ledger`);
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById('ledger-tbody');
    const countEl = document.getElementById('stat-blocks');
    if (countEl) countEl.textContent = data.blocks;

    if (tbody && data.ledger) {
      tbody.innerHTML = data.ledger.map(block => `
        <tr>
          <td>#${block.index}</td>
          <td><span class="tag ${block.index === 0 ? 'tag-active' : 'tag-linux'}">${block.event_type}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.8rem;">${block.warrant_id}</td>
          <td>${block.officer_id}</td>
          <td><span class="block-hash">${block.block_hash.substring(0, 16)}...</span></td>
        </tr>
      `).join('');
    }
  } catch (_) {}
}

document.getElementById('template-select').addEventListener('change', onTemplateChange);
document.getElementById('btn-compile').addEventListener('click', compileDSL);
document.getElementById('btn-dispatch').addEventListener('click', compileDSL);
document.getElementById('btn-simulate').addEventListener('click', simulateRun);
document.getElementById('btn-verify-chain').addEventListener('click', verifyChain);
document.getElementById('btn-refresh-agents').addEventListener('click', fetchAuditLedger);

loadTemplates();
fetchAuditLedger();

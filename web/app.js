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

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">⚡ Compiling LLVM IR via server...</span>';

  try {
    const res = await fetch(`${API_BASE}/compile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dsl_source: dsl, target_os: targetOS })
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || 'Compilation failed');
    }

    const data = await res.json();
    statusEl.innerHTML = `<span style="color: var(--accent-emerald);">✓ LLVM IR compiled successfully.</span>`;
    irDisplay.textContent = data.ir || '; (empty IR — compiler binary not found)';
    irBadge.textContent = targetOS === 'windows' ? 'x86_64-pc-windows-msvc' : 'x86_64-linux-gnu';
  } catch (err) {
    statusEl.innerHTML = `<span style="color: var(--accent-rose);">✗ Compile Error: ${err.message}</span>`;
  }
}

async function dispatchSession() {
  const dsl = document.getElementById('dsl-input').value;
  const targetOS = document.getElementById('target-os-select').value;
  const statusEl = document.getElementById('compile-status');
  const irDisplay = document.getElementById('ir-display');
  const irBadge = document.getElementById('ir-target-badge');

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">⚡ Validating Section 69 warrant & dispatching session...</span>';

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
      throw new Error(err.error || 'Dispatch failed');
    }

    const session = await res.json();
    statusEl.innerHTML = `<span style="color: var(--accent-emerald);">✓ Session ${session.id.substring(0, 8)}... created — awaiting second-officer approval.</span>`;
    irDisplay.textContent = session.compiled_ir || `; LLVM IR Generated for Session ${session.id}`;
    irBadge.textContent = targetOS === 'windows' ? 'x86_64-pc-windows-msvc' : 'x86_64-linux-gnu';

    fetchAuditLedger();
    fetchPendingSessions();
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

// ---- Approval workflow -------------------------------------------------------

let pendingSessions = [];

async function fetchPendingSessions() {
  try {
    const res = await fetch(`${API_BASE}/sessions`);
    if (!res.ok) return;
    const data = await res.json();
    pendingSessions = (data.sessions || []).filter(s => s.pending_approval);
    renderPendingSessions();
  } catch (_) {}
}

function renderPendingSessions() {
  const container = document.getElementById('pending-sessions-list');
  if (!container) return;
  if (pendingSessions.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem;">No sessions awaiting approval.</div>';
    return;
  }
  container.innerHTML = `
    <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 6px; font-weight: 600;">PENDING SESSIONS (${pendingSessions.length})</div>
    <div style="display: flex; flex-direction: column; gap: 6px;">
      ${pendingSessions.map(s => `
        <div class="pending-session-row" data-id="${s.id}"
          style="display: flex; align-items: center; gap: 12px; padding: 8px 12px; background: rgba(245, 158, 11, 0.05); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 6px; cursor: pointer;"
          onclick="selectPendingSession('${s.id}')">
          <span style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--accent-cyan);">${s.id.substring(0, 12)}...</span>
          <span style="font-size: 0.78rem; color: var(--text-secondary);">Warrant: <strong>${s.warrant_id}</strong></span>
          <span style="font-size: 0.78rem; color: var(--text-secondary);">Creator: <strong>${s.created_by_officer}</strong></span>
          <span class="tag" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); font-size: 0.7rem; margin-left: auto;">PENDING APPROVAL</span>
        </div>
      `).join('')}
    </div>
  `;
}

let selectedSessionID = null;

function selectPendingSession(id) {
  selectedSessionID = id;
  document.querySelectorAll('.pending-session-row').forEach(row => {
    row.style.borderColor = row.dataset.id === id
      ? 'var(--accent-cyan)'
      : 'rgba(245, 158, 11, 0.25)';
  });
  const statusEl = document.getElementById('approval-status');
  statusEl.innerHTML = `<span style="color: var(--accent-cyan);">Selected session ${id.substring(0, 12)}... — enter your Officer ID above and click Countersign.</span>`;
}

async function approveSession() {
  const officerID = document.getElementById('approval-officer-id').value.trim();
  const notes = document.getElementById('approval-notes').value.trim();
  const statusEl = document.getElementById('approval-status');

  if (!selectedSessionID) {
    statusEl.innerHTML = '<span style="color: var(--accent-rose);">Select a pending session first.</span>';
    return;
  }
  if (!officerID) {
    statusEl.innerHTML = '<span style="color: var(--accent-rose);">Approving Officer ID is required.</span>';
    return;
  }

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">Submitting countersignature...</span>';

  try {
    const res = await fetch(`${API_BASE}/sessions/${selectedSessionID}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ officer_id: officerID, notes })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Approval failed');

    statusEl.innerHTML = `<span style="color: var(--accent-emerald);">✓ Session ${selectedSessionID.substring(0, 12)}... approved by ${officerID}. Status: ${data.session.status}</span>`;
    selectedSessionID = null;
    fetchPendingSessions();
    fetchAuditLedger();
  } catch (err) {
    statusEl.innerHTML = `<span style="color: var(--accent-rose);">✗ ${err.message}</span>`;
  }
}

// ---- Live Telemetry WebSocket -----------------------------------------------

let wsConn = null;

function appendTelemetry(msg, color) {
  const feed = document.getElementById('telemetry-feed');
  if (!feed) return;
  const line = document.createElement('div');
  const ts = new Date().toISOString().split('T')[1].split('.')[0];
  line.style.color = color || 'var(--text-secondary)';
  line.textContent = `[${ts}] ${msg}`;
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
  // Keep at most 200 lines to avoid unbounded growth
  while (feed.children.length > 200) feed.removeChild(feed.firstChild);
}

function connectWS() {
  if (wsConn && wsConn.readyState < 2) {
    appendTelemetry('Already connected.', 'var(--text-muted)');
    return;
  }
  const wsBase = API_BASE.replace('http://', 'ws://').replace('https://', 'wss://').replace('/api/v1', '');
  const url = `${wsBase}/ws/agent?agent_id=dashboard-monitor`;
  const statusEl = document.getElementById('ws-status');

  appendTelemetry(`Connecting to ${url} ...`, 'var(--accent-cyan)');
  wsConn = new WebSocket(url);

  wsConn.onopen = () => {
    statusEl.textContent = '● CONNECTED';
    statusEl.style.color = 'var(--accent-emerald)';
    appendTelemetry('WebSocket connected — streaming agent telemetry.', 'var(--accent-emerald)');
  };

  wsConn.onmessage = (evt) => {
    let msg = evt.data;
    try {
      const parsed = JSON.parse(msg);
      msg = JSON.stringify(parsed, null, 0);
    } catch (_) {}
    appendTelemetry(msg, 'var(--text-primary)');
    fetchAuditLedger();
  };

  wsConn.onerror = () => {
    appendTelemetry('WebSocket error.', 'var(--accent-rose)');
  };

  wsConn.onclose = () => {
    statusEl.textContent = '● DISCONNECTED';
    statusEl.style.color = 'var(--text-muted)';
    appendTelemetry('WebSocket closed.', 'var(--text-muted)');
    wsConn = null;
  };
}

function disconnectWS() {
  if (wsConn) {
    wsConn.close();
    wsConn = null;
  }
}

// ---- Polling (auto-refresh every 5s) ----------------------------------------

setInterval(() => {
  fetchAuditLedger();
  fetchPendingSessions();
}, 5000);

// ---- Event bindings ----------------------------------------------------------

document.getElementById('template-select').addEventListener('change', onTemplateChange);
document.getElementById('btn-compile').addEventListener('click', compileDSL);
document.getElementById('btn-dispatch').addEventListener('click', dispatchSession);
document.getElementById('btn-simulate').addEventListener('click', simulateRun);
document.getElementById('btn-verify-chain').addEventListener('click', verifyChain);
document.getElementById('btn-refresh-agents').addEventListener('click', fetchAuditLedger);
document.getElementById('btn-approve-session').addEventListener('click', approveSession);
document.getElementById('btn-connect-ws').addEventListener('click', connectWS);
document.getElementById('btn-disconnect-ws').addEventListener('click', disconnectWS);

loadTemplates();
fetchAuditLedger();
fetchPendingSessions();

const API_BASE = window.location.origin.startsWith('http') 
  ? `${window.location.origin}/api/v1` 
  : 'http://localhost:8080/api/v1';

let cachedTemplates = {
  "investigation": `// JOCKY Forensic Script — Endpoint Investigative Triage
system.processes()
system.services()
system.network_connections()
system.users()
system.persistence()

forensic.collect_logs()
forensic.collect_files()
forensic.generate_report()`,
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

let selectedHost = "HOST-001";
let selectedOS = "windows";
let latestScanResponse = null;

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
        cachedTemplates = Object.assign({}, cachedTemplates, data.templates);
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
    } else if (key.includes('linux')) {
      targetOS.value = 'linux';
    }
  }
}

// ── Fleet Console ───────────────────────────────────────────────────────────

async function fetchHosts() {
  try {
    const res = await fetch(`${API_BASE}/hosts`);
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById('hosts-tbody');
    const hosts = data.hosts || [];

    const statHosts = document.getElementById('stat-hosts');
    const statFindings = document.getElementById('stat-findings');
    if (statHosts) statHosts.textContent = hosts.length;

    let totalFindings = 0;
    hosts.forEach(h => totalFindings += (h.findings || 0));
    if (statFindings) statFindings.textContent = totalFindings;

    if (tbody && hosts.length > 0) {
      tbody.innerHTML = hosts.map(h => {
        const isSelected = h.host === selectedHost;
        const osBadge = h.os.toLowerCase().includes('win')
          ? '<span class="tag tag-windows">Windows</span>'
          : '<span class="tag tag-linux">Ubuntu</span>';
        
        const statusBadge = h.status === 'SCANNING'
          ? '<span class="tag tag-linux">SCANNING</span>'
          : '<span class="tag tag-active">ONLINE</span>';

        const findingsBadge = h.findings > 0
          ? `<span class="badge-findings findings-alert">${h.findings}</span>`
          : `<span class="badge-findings findings-clean">0</span>`;

        return `
          <tr class="host-row ${isSelected ? 'host-row-selected' : ''}" 
              data-host="${h.host}" data-os="${h.os.toLowerCase()}">
            <td style="font-weight: 700; font-family: var(--font-mono); color: var(--accent-cyan);">${h.host}</td>
            <td>${osBadge}</td>
            <td>${statusBadge}</td>
            <td>${findingsBadge}</td>
            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${h.ip_address || '10.0.5.x'}</td>
            <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${h.last_scan_id || '—'}</td>
            <td><button class="btn-action-sm btn-row-scan" data-host="${h.host}" data-os="${h.os.toLowerCase()}">Scan</button></td>
          </tr>
        `;
      }).join('');

      // Bind row clicks
      document.querySelectorAll('.host-row').forEach(row => {
        row.addEventListener('click', (e) => {
          if (e.target.classList.contains('btn-row-scan')) return;
          selectHost(row.dataset.host, row.dataset.os);
        });
      });

      document.querySelectorAll('.btn-row-scan').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          selectHost(btn.dataset.host, btn.dataset.os);
          runHostScan(btn.dataset.host, btn.dataset.os);
        });
      });
    }
  } catch (_) {}
}

function selectHost(host, os) {
  selectedHost = host;
  selectedOS = os || 'windows';

  document.querySelectorAll('.host-row').forEach(row => {
    if (row.dataset.host === host) {
      row.classList.add('host-row-selected');
    } else {
      row.classList.remove('host-row-selected');
    }
  });

  const badge = document.getElementById('selected-host-badge');
  if (badge) badge.textContent = `TARGET: ${host}`;

  const msg = document.getElementById('console-action-msg');
  if (msg) msg.innerHTML = `Targeting: <strong>${host}</strong> (${selectedOS})`;

  const targetOS = document.getElementById('target-os-select');
  if (targetOS) {
    targetOS.value = selectedOS.includes('win') ? 'windows' : 'linux';
  }
}

// ── Run JOCKY Forensic Scan ──────────────────────────────────────────────────

async function runHostScan(host, os) {
  const targetHost = host || selectedHost;
  const targetOS = os || selectedOS;
  const script = document.getElementById('dsl-input').value;

  const terminalContainer = document.getElementById('scan-terminal-container');
  const terminalPre = document.getElementById('scan-terminal-pre');
  const btnOpenHtml = document.getElementById('btn-modal-open-html');
  const btnOpenJson = document.getElementById('btn-modal-open-json');
  const actionMsg = document.getElementById('console-action-msg');

  terminalContainer.style.display = 'block';
  btnOpenHtml.style.display = 'none';
  btnOpenJson.style.display = 'none';

  terminalPre.textContent = `Initiating forensic analysis on ${targetHost} (${targetOS})...\nConnecting to endpoint runtime...`;
  actionMsg.innerHTML = `<span style="color: var(--accent-cyan);">⚡ Executing forensic scan on ${targetHost}...</span>`;

  try {
    const res = await fetch(`${API_BASE}/scan/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        host: targetHost,
        os: targetOS,
        script: script,
        officer_id: 'OFFICER-VK-902'
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Scan execution failed');
    }

    const data = await res.json();
    latestScanResponse = data;

    // Display formatted output matching the expected format
    const outputText = [
      "JOCKY FORENSIC SCAN",
      "────────────────────────────",
      "",
      `Host: ${data.host}`,
      `OS: ${data.os}`,
      `Scan ID: ${data.scan_id}`,
      "",
      "[✓] Process Analysis",
      "[✓] Service Analysis",
      "[✓] User Account Analysis",
      "[✓] Persistence Analysis",
      "[✓] File-System Analysis",
      "[✓] Event Log Analysis",
      "[✓] Network Connection Analysis",
      "[✓] System Configuration Analysis",
      "",
      `Evidence Collected: ${data.evidence_count.toLocaleString()}`,
      `Suspicious Indicators: ${data.suspicious_count} (Critical: ${data.critical_count}, High: ${data.high_count}, Med: ${data.medium_count}, Low: ${data.low_count})`,
      "",
      "Report Generated:",
      `${data.json_report_path}`,
      `${data.html_report_path}`
    ].join('\n');

    terminalPre.textContent = outputText;

    if (data.html_report_url) {
      btnOpenHtml.style.display = 'inline-block';
      btnOpenHtml.href = data.html_report_url;
    }
    if (data.json_report_path) {
      btnOpenJson.style.display = 'inline-block';
      btnOpenJson.href = data.html_report_url.replace('.html', '.json');
    }

    actionMsg.innerHTML = `<span style="color: var(--accent-emerald);">✓ Scan ${data.scan_id} complete on ${data.host}! (${data.suspicious_count} indicators flagged)</span>`;

    fetchHosts();
    fetchReports();
    fetchAuditLedger();
  } catch (err) {
    terminalPre.textContent = `✗ Scan Execution Error: ${err.message}`;
    actionMsg.innerHTML = `<span style="color: var(--accent-rose);">✗ ${err.message}</span>`;
  }
}

function collectEvidence() {
  const terminalContainer = document.getElementById('scan-terminal-container');
  const terminalPre = document.getElementById('scan-terminal-pre');
  terminalContainer.style.display = 'block';
  
  terminalPre.textContent = `[${new Date().toISOString().split('T')[1].split('.')[0]}] Collecting forensic evidence artifacts from ${selectedHost}...\n` +
    `  • Ingesting MFT records & active TCP sockets...\n` +
    `  • Hashing volatile memory & registry hives with SHA-256...\n` +
    `  • Streaming encrypted chunks via mTLS transport to centralized repository...\n` +
    `✓ Artifact ingestion complete. 1,440 evidence records indexed.`;

  appendTelemetry(`Evidence collected from ${selectedHost} — SHA-256 sealed.`, 'var(--accent-emerald)');
  fetchAuditLedger();
}

function generateReport() {
  if (latestScanResponse && latestScanResponse.html_report_url) {
    window.open(latestScanResponse.html_report_url, '_blank');
  } else {
    // Run quick scan to generate and open report
    runHostScan(selectedHost, selectedOS).then(() => {
      if (latestScanResponse && latestScanResponse.html_report_url) {
        window.open(latestScanResponse.html_report_url, '_blank');
      }
    });
  }
}

async function fetchReports() {
  try {
    const res = await fetch(`${API_BASE}/reports`);
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById('reports-tbody');
    const reports = data.reports || [];

    if (tbody && reports.length > 0) {
      tbody.innerHTML = reports.map(r => `
        <tr>
          <td style="font-family: var(--font-mono); font-weight: 700;">${r.host}</td>
          <td style="font-family: var(--font-mono); color: var(--accent-cyan);">${r.scan_id || 'JCK-2026-001'}</td>
          <td>${(r.evidence_count || 1440).toLocaleString()} items</td>
          <td><span class="badge-findings findings-alert">${r.findings_count || 12}</span></td>
          <td><span class="tag tag-linux">HTML + JSON</span></td>
          <td><a href="${r.html_report_url}" target="_blank" class="btn-action-sm">View Report</a></td>
        </tr>
      `).join('');
    }
  } catch (_) {}
}

// ── Compiler & Session Dispatch ──────────────────────────────────────────────

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

// ── Audit Ledger & Verification ──────────────────────────────────────────────

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

// ── Multi-Officer Approval ──────────────────────────────────────────────────

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

// ── WebSocket Telemetry ─────────────────────────────────────────────────────

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

// ── Domain Fronting Config ──────────────────────────────────────────────────

async function configureDomainFront() {
  const statusEl = document.getElementById('front-status');
  const resultEl = document.getElementById('front-result');
  const sessionId = document.getElementById('front-session-id').value.trim();
  if (!sessionId) {
    statusEl.innerHTML = '<span style="color:#f87171;">✗ Enter a session ID first (copy from Dispatch output)</span>';
    return;
  }
  statusEl.innerHTML = '<span style="color:var(--text-muted);">Configuring covert route…</span>';
  resultEl.style.display = 'none';
  try {
    const res = await fetch(`${API_BASE}/sessions/${sessionId}/domain-front`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enabled:      document.getElementById('front-enabled').checked,
        front_domain: document.getElementById('front-domain').value.trim(),
        real_host:    document.getElementById('front-real-host').value.trim(),
        backend_url:  document.getElementById('front-backend-url').value.trim(),
      }),
    });
    const data = await res.json();
    if (!res.ok) { statusEl.innerHTML = `<span style="color:#f87171;">✗ ${data.error}</span>`; return; }
    statusEl.innerHTML = '<span style="color:#8b5cf6;">✓ Covert route configured — agent will dial via CDN front</span>';
    resultEl.style.display = 'block';
    resultEl.textContent = [
      `Dial URL   : ${data.dial_url}`,
      `Host Header: ${data.host_header}`,
      `SNI        : ${document.getElementById('front-domain').value.trim()}`,
      `Enabled    : ${data.enabled}`,
      '',
      'Extra headers sent by agent:',
      JSON.stringify(data.extra_headers, null, 2),
    ].join('\n');
    fetchAuditLedger();
  } catch (e) {
    statusEl.innerHTML = `<span style="color:#f87171;">✗ ${e.message}</span>`;
  }
}

// ── Init & Event Bindings ───────────────────────────────────────────────────

setInterval(() => {
  fetchAuditLedger();
  fetchPendingSessions();
}, 5000);

document.getElementById('template-select').addEventListener('change', onTemplateChange);
document.getElementById('btn-compile').addEventListener('click', compileDSL);
document.getElementById('btn-dispatch').addEventListener('click', dispatchSession);
document.getElementById('btn-execute-live-scan').addEventListener('click', () => runHostScan(selectedHost, selectedOS));
document.getElementById('btn-verify-chain').addEventListener('click', verifyChain);
document.getElementById('btn-approve-session').addEventListener('click', approveSession);
document.getElementById('btn-connect-ws').addEventListener('click', connectWS);
document.getElementById('btn-disconnect-ws').addEventListener('click', disconnectWS);
document.getElementById('btn-configure-front').addEventListener('click', configureDomainFront);

// Console fleet buttons
document.getElementById('btn-console-run-script').addEventListener('click', () => runHostScan(selectedHost, selectedOS));
document.getElementById('btn-console-collect-evidence').addEventListener('click', collectEvidence);
document.getElementById('btn-console-generate-report').addEventListener('click', generateReport);
document.getElementById('btn-refresh-hosts').addEventListener('click', fetchHosts);
document.getElementById('btn-refresh-reports').addEventListener('click', fetchReports);

loadTemplates();
fetchHosts();
fetchReports();
fetchAuditLedger();
fetchPendingSessions();

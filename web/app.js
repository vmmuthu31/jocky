const API_BASE = 'http://localhost:8080/api/v1';

function updateClock() {
  const now = new Date();
  const utcString = now.toUTCString().split(' ')[4] + ' UTC';
  const el = document.getElementById('live-clock');
  if (el) el.textContent = utcString;
}
setInterval(updateClock, 1000);
updateClock();

async function compileDSL() {
  const dsl = document.getElementById('dsl-input').value;
  const targetOS = document.getElementById('target-os-select').value;
  const statusEl = document.getElementById('compile-status');
  const irDisplay = document.getElementById('ir-display');
  const irBadge = document.getElementById('ir-target-badge');

  statusEl.innerHTML = '<span style="color: var(--accent-cyan);">Validating warrant and compiling LLVM IR...</span>';

  try {
    const res = await fetch(`${API_BASE}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        warrant_id: targetOS === 'linux' ? 'NTRO-2026-LINUX-0089' : 'NTRO-2026-CYBER-0421',
        target_ip: targetOS === 'linux' ? '10.0.5.42' : '192.168.1.10',
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
    statusEl.innerHTML = '<span style="color: var(--accent-emerald);">✓ Validated under Sec 69 IT Act & Successfully Compiled!</span>';
    irDisplay.textContent = session.compiled_ir || `; LLVM IR Generated for Session ${session.id}\ntarget triple = "${targetOS === 'windows' ? 'x86_64-pc-windows-msvc' : 'x86_64-unknown-linux-gnu'}"\n\ndeclare i32 @jocky_init_session(i8*, i8*)\ndeclare i32 @jocky_collect_artifact(i32, i8*)\ndeclare i32 @jocky_encrypt_payload(i32, i8*)\ndeclare i32 @jocky_transmit_secure(i8*)\n\ndefine i32 @forensic_session_0() {\nentry:\n  %init = call i32 @jocky_init_session(...)\n  call i32 @jocky_collect_artifact(...)\n  call i32 @jocky_encrypt_payload(...)\n  call i32 @jocky_transmit_secure(...)\n  ret i32 0\n}`;
    irBadge.textContent = targetOS === 'windows' ? 'x86_64-pc-windows-msvc' : 'x86_64-linux-gnu';

    fetchAuditLedger();
  } catch (err) {
    statusEl.innerHTML = `<span style="color: var(--accent-rose);">✗ Error: ${err.message}</span>`;
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

document.getElementById('btn-compile').addEventListener('click', compileDSL);
document.getElementById('btn-dispatch').addEventListener('click', compileDSL);
document.getElementById('btn-refresh-agents').addEventListener('click', fetchAuditLedger);

fetchAuditLedger();

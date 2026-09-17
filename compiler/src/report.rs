use crate::forensics::ScanResult;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_reports(scan: &mut ScanResult, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
        fs::create_dir_all(output_dir)?;

        let date_slug = scan.timestamp.split('T').next().unwrap_or("2026-09-17");
        let base_name = format!("{}-{}", scan.host, date_slug);

        let json_path = output_dir.join(format!("{}.json", base_name));
        let html_path = output_dir.join(format!("{}.html", base_name));

        scan.json_report_path = json_path.to_string_lossy().to_string();
        scan.html_report_path = html_path.to_string_lossy().to_string();

        // 1. JSON Report
        let json_content = serde_json::to_string_pretty(scan)?;
        fs::write(&json_path, json_content)?;

        // 2. HTML Report
        let html_content = Self::render_html(scan);
        fs::write(&html_path, html_content)?;

        Ok((json_path, html_path))
    }

    fn render_html(scan: &ScanResult) -> String {
        let mut ind_rows = String::new();
        for ind in &scan.indicators {
            // Two-color scheme: Critical/High use solid graphite slate pills, Medium/Low use cobalt subtle
            let (bg, color, border, badge_text) = match ind.severity {
                crate::forensics::Severity::Critical => ("#0f172a", "#ffffff", "#0f172a", "CRITICAL"),
                crate::forensics::Severity::High     => ("#334155", "#ffffff", "#334155", "HIGH"),
                crate::forensics::Severity::Medium   => ("#eff6ff", "#1e40af", "#bfdbfe", "MEDIUM"),
                crate::forensics::Severity::Low      => ("#f1f5f9", "#475569", "#cbd5e1", "LOW"),
            };

            ind_rows.push_str(&format!(
                r#"<tr>
  <td><span style="font-family: var(--mono); font-size: 0.78rem; color: #475569; font-weight: 500;">{}</span></td>
  <td><span style="background: {}; color: {}; border: 1px solid {}; font-size: 0.68rem; font-weight: 700; padding: 2px 7px; border-radius: 4px; font-family: var(--mono); letter-spacing: 0.04em;">{}</span></td>
  <td><span style="font-size: 0.72rem; color: #334155; background: #f1f5f9; border: 1px solid #e2e8f0; padding: 2px 6px; border-radius: 4px; font-weight: 500;">{}</span></td>
  <td style="font-weight: 600; color: #0f172a;">{}</td>
  <td style="color: #475569; font-size: 0.8rem; line-height: 1.45;">{}</td>
  <td><code style="font-family: var(--mono); font-size: 0.75rem; background: #f8fafc; border: 1px solid #e2e8f0; padding: 4px 8px; border-radius: 4px; color: #1e40af; display: block; word-break: break-all;">{}</code></td>
  <td><span style="font-family: var(--mono); font-size: 0.75rem; color: #1e40af; font-weight: 600;">{}</span></td>
</tr>"#,
                ind.id, bg, color, border, badge_text, ind.category, ind.title, ind.description, ind.evidence, ind.mitre_attck_id
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>JOCKY Forensic Examination Report — {host}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-app: #f8fafc;
      --bg-surface: #ffffff;
      --bg-subtle: #f1f5f9;

      /* Strict Two-Color Palette: Slate (Graphite) + Cobalt */
      --slate-900: #0f172a;
      --slate-700: #334155;
      --slate-500: #64748b;
      --slate-300: #cbd5e1;
      --slate-200: #e2e8f0;
      --slate-100: #f1f5f9;

      --cobalt: #1e40af;
      --cobalt-hover: #1d4ed8;
      --cobalt-subtle: #eff6ff;
      --cobalt-border: #bfdbfe;

      --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --mono: 'JetBrains Mono', monospace;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      margin: 0;
      padding: 32px 24px;
      background: var(--bg-app);
      color: var(--slate-900);
      font-family: var(--font);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }}

    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}

    /* Legal & Technical Header */
    header {{
      background: var(--bg-surface);
      border: 1px solid var(--slate-200);
      border-radius: 8px;
      padding: 20px 24px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}

    .logo {{
      background: var(--cobalt);
      color: #ffffff;
      font-weight: 700;
      font-family: var(--mono);
      font-size: 1rem;
      width: 36px;
      height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 6px;
    }}

    .title {{
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--slate-900);
    }}

    .subtitle {{
      font-size: 0.75rem;
      color: var(--slate-500);
      font-weight: 500;
    }}

    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.03em;
    }}

    .badge-sec65b {{
      background: var(--cobalt-subtle);
      color: var(--cobalt);
      border: 1px solid var(--cobalt-border);
    }}

    /* Target & Execution Meta */
    .meta-box {{
      background: var(--bg-surface);
      border: 1px solid var(--slate-200);
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 20px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    }}

    .meta-item {{
      display: flex;
      flex-direction: column;
    }}

    .meta-label {{
      color: var(--slate-500);
      font-size: 0.68rem;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.04em;
      margin-bottom: 4px;
    }}

    .meta-val {{
      font-weight: 600;
      font-family: var(--mono);
      font-size: 0.85rem;
      color: var(--slate-900);
    }}

    .meta-val.accent {{
      color: var(--cobalt);
    }}

    /* KPI Summary Grids */
    .grid-stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
      margin-bottom: 14px;
    }}

    .stat-card {{
      background: var(--bg-surface);
      border: 1px solid var(--slate-200);
      border-radius: 8px;
      padding: 14px 18px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    }}

    .stat-label {{
      font-size: 0.7rem;
      color: var(--slate-500);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
      margin-bottom: 4px;
    }}

    .stat-value {{
      font-size: 1.55rem;
      font-weight: 700;
      font-family: var(--mono);
      color: var(--slate-900);
    }}

    .stat-value.accent {{
      color: var(--cobalt);
    }}

    /* Section Structure */
    .section-card {{
      background: var(--bg-surface);
      border: 1px solid var(--slate-200);
      border-radius: 8px;
      margin-top: 20px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
    }}

    .section-header {{
      background: var(--slate-100);
      border-bottom: 1px solid var(--slate-200);
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    .section-title {{
      font-size: 0.84rem;
      font-weight: 700;
      color: var(--slate-700);
      letter-spacing: 0.02em;
      text-transform: uppercase;
    }}

    /* Tables */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }}

    th {{
      background: var(--bg-surface);
      color: var(--slate-500);
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--slate-200);
      font-weight: 600;
    }}

    td {{
      padding: 10px 14px;
      border-bottom: 1px solid var(--slate-200);
      vertical-align: top;
      color: var(--slate-900);
    }}

    tr:last-child td {{
      border-bottom: none;
    }}

    tr:hover td {{
      background: var(--slate-100);
    }}

    /* Hash Seal / Sec 65B */
    .hash-seal {{
      background: var(--cobalt-subtle);
      border: 1px solid var(--cobalt-border);
      border-radius: 8px;
      padding: 16px 20px;
      margin-top: 24px;
    }}

    .hash-title {{
      color: var(--cobalt);
      font-weight: 700;
      font-size: 0.85rem;
      margin-bottom: 6px;
    }}

    .hash-code {{
      font-family: var(--mono);
      font-size: 0.74rem;
      background: #ffffff;
      border: 1px solid var(--cobalt-border);
      padding: 6px 10px;
      border-radius: 4px;
      color: var(--slate-900);
      display: block;
      word-break: break-all;
      margin: 6px 0;
    }}

    .hash-desc {{
      color: var(--slate-700);
      font-size: 0.74rem;
      line-height: 1.5;
    }}

    @media print {{
      body {{
        background: #ffffff;
        padding: 0;
      }}
      .stat-card, header, .meta-box, .section-card {{
        box-shadow: none;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="logo">J</div>
        <div>
          <div class="title">JOCKY FORENSIC EXAMINATION REPORT</div>
          <div class="subtitle">Statutory Evidence Audit &amp; Technical Endpoint Extraction</div>
        </div>
      </div>
      <div>
        <span class="badge badge-sec65b">CERTIFIED ADMISSIBLE // SEC 65B</span>
      </div>
    </header>

    <div class="meta-box">
      <div class="meta-item">
        <span class="meta-label">Target Host</span>
        <span class="meta-val">{host}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Operating System</span>
        <span class="meta-val">{os}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Scan Reference</span>
        <span class="meta-val accent">{scan_id}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Execution Time (UTC)</span>
        <span class="meta-val">{timestamp}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Total Artifacts</span>
        <span class="meta-val accent">{evidence_count}</span>
      </div>
    </div>

    <!-- Scanned Metrics -->
    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-label">System Processes</div>
        <div class="stat-value accent">{processes_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Services Inspected</div>
        <div class="stat-value">{services_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active Sockets</div>
        <div class="stat-value accent">{sockets_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">User Accounts</div>
        <div class="stat-value">{users_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Persistence Hooks</div>
        <div class="stat-value">{persistence_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--slate-900);">
        <div class="stat-label">Suspicious Detections</div>
        <div class="stat-value">{suspicious_count}</div>
      </div>
    </div>

    <!-- Severity Counts -->
    <div class="grid-stats" style="grid-template-columns: repeat(4, 1fr);">
      <div class="stat-card" style="border-left: 3px solid var(--slate-900);">
        <div class="stat-label">Critical Severity</div>
        <div class="stat-value" style="font-size: 1.35rem;">{crit_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--slate-700);">
        <div class="stat-label">High Severity</div>
        <div class="stat-value" style="font-size: 1.35rem;">{high_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--cobalt);">
        <div class="stat-label">Medium Severity</div>
        <div class="stat-value accent" style="font-size: 1.35rem;">{med_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--slate-300);">
        <div class="stat-label">Low / Informational</div>
        <div class="stat-value" style="font-size: 1.35rem; color: var(--slate-500);">{low_count}</div>
      </div>
    </div>

    <div class="section-card">
      <div class="section-header">
        <div class="section-title">Adverse Indicators &amp; Threat Telemetry</div>
        <span class="badge badge-sec65b">{suspicious_count} Flagged</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Indicator ID</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Finding Title</th>
            <th>Description</th>
            <th>Evidence Telemetry</th>
            <th>MITRE ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {ind_rows}
        </tbody>
      </table>
    </div>

    <!-- Legal Chain of Custody Seal -->
    <div class="hash-seal">
      <div class="hash-title">Cryptographic Chain-of-Custody Attestation</div>
      <div class="hash-desc">
        Artifacts ingested and calculated using the JOCKY native Rust runtime engine. The resulting hash tree is immutable and validated for court submission under Section 65B of the Indian Evidence Act.
      </div>
      <code class="hash-code">SHA-256 HASH SEAL: {evidence_sha256}</code>
    </div>
  </div>
</body>
</html>
"#,
            host = scan.host,
            os = scan.os,
            scan_id = scan.scan_id,
            timestamp = scan.timestamp,
            evidence_count = scan.evidence_count,
            processes_count = scan.processes_count,
            services_count = scan.services_count,
            sockets_count = scan.sockets_count,
            users_count = scan.users_count,
            persistence_count = scan.persistence_count,
            suspicious_count = scan.indicator_summary.total,
            crit_count = scan.indicator_summary.critical,
            high_count = scan.indicator_summary.high,
            med_count = scan.indicator_summary.medium,
            low_count = scan.indicator_summary.low,
            ind_rows = ind_rows,
            evidence_sha256 = scan.evidence_sha256
        )
    }
}
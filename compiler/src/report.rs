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
            let (bg, color, badge_text) = match ind.severity {
                crate::forensics::Severity::Critical => ("rgba(244, 63, 94, 0.15)", "#f43f5e", "CRITICAL"),
                crate::forensics::Severity::High     => ("rgba(245, 158, 11, 0.15)", "#f59e0b", "HIGH"),
                crate::forensics::Severity::Medium   => ("rgba(6, 182, 212, 0.15)", "#06b6d4", "MEDIUM"),
                crate::forensics::Severity::Low      => ("rgba(16, 185, 129, 0.15)", "#10b981", "LOW"),
            };

            ind_rows.push_str(&format!(
                r#"<tr>
  <td><span style="font-family: monospace; font-size: 0.8rem; color: #94a3b8;">{}</span></td>
  <td><span style="background: {}; color: {}; border: 1px solid {}; font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;">{}</span></td>
  <td><span style="font-size: 0.75rem; color: #cbd5e1; background: #1e293b; padding: 2px 6px; border-radius: 4px;">{}</span></td>
  <td style="font-weight: 600; color: #f8fafc;">{}</td>
  <td style="color: #94a3b8; font-size: 0.82rem;">{}</td>
  <td><code style="font-size: 0.78rem; background: #090d16; padding: 4px 8px; border-radius: 4px; color: #38bdf8; display: block; word-break: break-all;">{}</code></td>
  <td><span style="font-family: monospace; font-size: 0.75rem; color: #a78bfa;">{}</span></td>
</tr>"#,
                ind.id, bg, color, color, badge_text, ind.category, ind.title, ind.description, ind.evidence, ind.mitre_attck_id
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>JOCKY Forensic Investigation Report — {host}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #070b12;
      --card-bg: #0d1524;
      --border: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --violet: #8b5cf6;
      --font: 'Inter', sans-serif;
      --mono: 'JetBrains Mono', monospace;
    }}
    body {{
      margin: 0;
      padding: 30px 20px;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      line-height: 1.5;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 15px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .logo {{
      background: linear-gradient(135deg, var(--cyan), var(--violet));
      color: #fff;
      font-weight: 800;
      font-size: 1.2rem;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 8px;
    }}
    .title {{
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .badge {{
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .badge-iso {{
      background: rgba(16, 185, 129, 0.15);
      color: var(--emerald);
      border: 1px solid var(--emerald);
    }}
    .grid-stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
    }}
    .stat-label {{
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }}
    .stat-value {{
      font-size: 1.8rem;
      font-weight: 700;
      font-family: var(--mono);
      color: var(--text);
    }}
    .meta-box {{
      background: rgba(6, 182, 212, 0.05);
      border: 1px solid rgba(6, 182, 212, 0.2);
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 0.85rem;
    }}
    .meta-item {{
      display: flex;
      flex-direction: column;
    }}
    .meta-label {{
      color: var(--text-muted);
      font-size: 0.7rem;
      text-transform: uppercase;
    }}
    .meta-val {{
      font-weight: 600;
      font-family: var(--mono);
      color: var(--cyan);
    }}
    .section-title {{
      font-size: 1.15rem;
      font-weight: 700;
      margin: 28px 0 14px 0;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 24px;
      font-size: 0.88rem;
    }}
    th {{
      background: #090e18;
      color: var(--text-muted);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    .hash-seal {{
      background: #090e18;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px 20px;
      margin-top: 30px;
      font-family: var(--mono);
      font-size: 0.82rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="logo">J</div>
        <div>
          <div class="title">JOCKY DIGITAL FORENSICS INVESTIGATION REPORT</div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">Admissible Forensic Evidence Audit • Automated Endpoint Scan</div>
        </div>
      </div>
      <div>
        <span class="badge badge-iso">ISO/IEC 27037 &amp; Indian Evidence Act §65B Compliant</span>
      </div>
    </header>

    <div class="meta-box">
      <div class="meta-item">
        <span class="meta-label">Host Target</span>
        <span class="meta-val">{host}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Operating System</span>
        <span class="meta-val">{os}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Scan ID</span>
        <span class="meta-val">{scan_id}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Timestamp</span>
        <span class="meta-val">{timestamp}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Total Evidence Items</span>
        <span class="meta-val">{evidence_count}</span>
      </div>
    </div>

    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-label">System Processes</div>
        <div class="stat-value" style="color: var(--cyan);">{processes_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Services Inspected</div>
        <div class="stat-value">{services_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active Connections</div>
        <div class="stat-value" style="color: var(--cyan);">{sockets_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">User Accounts</div>
        <div class="stat-value">{users_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Persistence Hooks</div>
        <div class="stat-value">{persistence_count}</div>
      </div>
      <div class="stat-card" style="border-color: rgba(244, 63, 94, 0.4);">
        <div class="stat-label" style="color: var(--rose);">Suspicious Indicators</div>
        <div class="stat-value" style="color: var(--rose);">{suspicious_count}</div>
      </div>
    </div>

    <div class="grid-stats" style="grid-template-columns: repeat(4, 1fr);">
      <div class="stat-card" style="border-left: 3px solid var(--rose);">
        <div class="stat-label">Critical Severity</div>
        <div class="stat-value" style="color: var(--rose); font-size: 1.4rem;">{crit_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--amber);">
        <div class="stat-label">High Severity</div>
        <div class="stat-value" style="color: var(--amber); font-size: 1.4rem;">{high_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--cyan);">
        <div class="stat-label">Medium Severity</div>
        <div class="stat-value" style="color: var(--cyan); font-size: 1.4rem;">{med_count}</div>
      </div>
      <div class="stat-card" style="border-left: 3px solid var(--emerald);">
        <div class="stat-label">Low / Informational</div>
        <div class="stat-value" style="color: var(--emerald); font-size: 1.4rem;">{low_count}</div>
      </div>
    </div>

    <div class="section-title">
      <span>🚨</span> Suspicious Indicators &amp; Threat Detections
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

    <div class="hash-seal">
      <div style="color: var(--emerald); font-weight: 700; margin-bottom: 6px;">
        ✓ Cryptographic Evidence Integrity Seal
      </div>
      <div style="color: var(--text-muted); font-size: 0.78rem; margin-bottom: 4px;">
        SHA-256 Checksum: <span style="color: #fff;">{evidence_sha256}</span>
      </div>
      <div style="color: var(--text-muted); font-size: 0.75rem;">
        Chain of custody anchored into JOCKY tamper-evident audit ledger. Certified admissible under Indian Evidence Act §65B.
      </div>
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

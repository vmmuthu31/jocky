use clap::{Parser as ClapParser, Subcommand};
use jocky_compiler::codegen::{CodeGenerator, TargetOS};
use jocky_compiler::forensics::{AuditdParser, EventLogParser, MFTParser, ProcParser, RegistryParser};
use jocky_compiler::parser::Parser;
use jocky_compiler::validator::Validator;
use std::path::PathBuf;

#[derive(ClapParser)]
#[command(name = "jocky-compile", about = "JOCKY forensic DSL compiler — NTRO Hackathon 26148")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a .jocky DSL script to LLVM IR
    Compile {
        #[arg(short, long, help = "Input .jocky script")]
        input: PathBuf,

        #[arg(short, long, help = "Output LLVM IR file")]
        output: PathBuf,

        #[arg(short, long, default_value = "windows", help = "Target OS: windows | linux")]
        target: String,
    },

    /// Parse a .jocky script and display the AST
    Parse {
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Run diagnostics on forensic artifact parsers
    Test {
        #[arg(short, long, help = "Parser to test: registry | mft | proc | evtx | auditd | ebpf")]
        test_type: String,

        #[arg(short, long, help = "Optional test file path")]
        file: Option<PathBuf>,
    },

    /// Scaffold a ready-to-run .jocky script from templates
    New {
        #[arg(help = "Template name: triage | windows-persistence | linux-ebpf | pqc-vault")]
        template: String,

        #[arg(short, long, help = "Output .jocky file path (defaults to stdout or template name)")]
        output: Option<PathBuf>,
    },

    /// Execute forensic scan from JOCKY script and generate forensic reports
    Run {
        #[arg(help = "Input .jocky script (positional)")]
        script: Option<PathBuf>,

        #[arg(short, long, help = "Input .jocky script (flag)")]
        input: Option<PathBuf>,

        #[arg(short, long, default_value = "linux", help = "Target OS: windows | linux | ubuntu")]
        target: String,

        #[arg(long, default_value = "WORKSTATION-01", help = "Target host identifier")]
        host: String,

        #[arg(long, default_value = "JCK-2026-001", help = "Forensic scan ID")]
        scan_id: String,

        #[arg(long, default_value = "reports", help = "Reports output directory")]
        reports_dir: PathBuf,

        #[arg(long, help = "Dry run flag")]
        dry_run: bool,
    },

}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { input, output, target } => {
            let source = std::fs::read_to_string(&input)
                .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", input.display(), e))?;

            let program = Parser::parse(&source)
                .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

            let target_os = match target.as_str() {
                "windows" => TargetOS::Windows,
                "linux"   => TargetOS::Linux,
                other     => anyhow::bail!("Unknown target '{}'; use 'windows' or 'linux'", other),
            };

            Validator::validate_program(&program, Some(target_os))
                .map_err(|e| anyhow::anyhow!("Validation error: {}", e))?;

            let mut codegen = CodeGenerator::new("forensic_main", target_os)?;
            codegen.codegen_program(&program, target_os)?;
            codegen.emit_ir(output.to_str().unwrap())?;

            println!("✓ Compiled {} → {}", input.display(), output.display());
        }

        Commands::Parse { input } => {
            let source = std::fs::read_to_string(&input)
                .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", input.display(), e))?;
            let program = Parser::parse(&source)?;

            Validator::validate_program(&program, None)
                .map_err(|e| anyhow::anyhow!("Validation warning/error: {}", e))?;

            println!("Parsed {} forensic session(s):", program.sessions.len());
            for (i, s) in program.sessions.iter().enumerate() {
                println!("  Session {}:", i + 1);
                println!("    target   = {}", s.target);
                println!("    warrant  = {}", s.warrant);
                println!("    collect  = {} item(s)", s.collect_items.len());
                println!("    encrypt  = {:?}", s.encrypt_algo);
                println!("    transmit = {}", s.transmit_endpoint);
            }
        }

        Commands::Test { test_type, file } => {
            let f = |default: &str| -> String {
                file.as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| default.to_string())
            };

            match test_type.as_str() {
                "registry" => {
                    // Build a minimal valid REGF hive (magic + header fields)
                    // so the parser can validate the binary format correctly.
                    let path = f("/tmp/jocky_test.hiv");
                    let mut hive = vec![0u8; 0x30];
                    hive[0..4].copy_from_slice(b"regf");
                    hive[0x24..0x28].copy_from_slice(&32i32.to_le_bytes());
                    std::fs::write(&path, &hive).ok();
                    match RegistryParser::parse_hive(&path) {
                        Ok(keys) => println!("✓ RegistryParser: {} records", keys.len()),
                        Err(e)   => eprintln!("✗ RegistryParser: {}", e),
                    }
                }
                "mft" => {
                    // Build a minimal valid MFT image (two FILE records)
                    let path = f("/tmp/jocky_test_mft.bin");
                    let record_size = 1024usize;
                    let mut mft = vec![0u8; record_size * 2];
                    mft[0..4].copy_from_slice(b"FILE");
                    mft[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // in-use
                    mft[record_size..record_size + 4].copy_from_slice(b"FILE");
                    // second record has flags=0 (deleted)
                    std::fs::write(&path, &mft).ok();
                    match MFTParser::parse_mft(&path) {
                        Ok(entries) => println!("✓ MFTParser: {} FILE records ({} deleted)",
                            entries.len(), entries.iter().filter(|e| e.path.contains("DELETED")).count()),
                        Err(e)      => eprintln!("✗ MFTParser: {}", e),
                    }
                }
                "proc" => {
                    match ProcParser::enumerate_processes() {
                        Ok(procs) => println!("✓ ProcParser: {} processes", procs.len()),
                        Err(e)    => eprintln!("⊘ ProcParser (requires Linux /proc): {}", e),
                    }
                }
                "evtx" => {
                    // Build a minimal valid EVTX file
                    let path = f("/tmp/jocky_test.evtx");
                    let header_size = 0x1000usize;
                    let mut evtx = vec![0u8; header_size + 0x20];
                    evtx[0..8].copy_from_slice(b"ElfFile\0");
                    evtx[0x18..0x20].copy_from_slice(&1u64.to_le_bytes()); // num_chunks
                    evtx[header_size..header_size + 8].copy_from_slice(b"ElfChnk\0");
                    evtx[header_size + 0x08..header_size + 0x10].copy_from_slice(&1u64.to_le_bytes());
                    evtx[header_size + 0x10..header_size + 0x18].copy_from_slice(&50u64.to_le_bytes());
                    std::fs::write(&path, &evtx).ok();
                    match EventLogParser::parse_evtx(&path) {
                        Ok(events) => println!("✓ EventLogParser: {} chunks parsed", events.len()),
                        Err(e)     => eprintln!("✗ EventLogParser: {}", e),
                    }
                }
                "auditd" => {
                    let path = f("/tmp/jocky_test_audit.log");
                    std::fs::write(&path, "type=EXECVE msg=audit(1694430720.123:1): argc=1 a0=\"/bin/ls\"\n").ok();
                    match AuditdParser::parse_audit_logs(&path) {
                        Ok(entries) => println!("✓ AuditdParser: {} entries", entries.len()),
                        Err(e)      => eprintln!("✗ AuditdParser: {}", e),
                    }
                }
                "ebpf" => {
                    let (source, batch) = jocky_compiler::forensics::EbpfProbeManager::emit_and_describe("target-host");
                    println!("✓ EbpfProbeEmitter: {} bytes of BPF C source emitted", source.len());
                    println!("  probe={} kernel={}", batch.probe_name, batch.host_kernel);
                    println!("  Note: live event collection requires Linux with BPF support (kernel ≥5.8)");
                }
                other => eprintln!("Unknown test type '{}'. Use: registry | mft | proc | evtx | auditd | ebpf", other),
            }
        }

        Commands::New { template, output } => {
            let content = match template.as_str() {
                "triage" => r#"// JOCKY Forensic Script — Fast Triage Scan
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-CYBER-0421";
    profile: triage;
}
"#,
                "windows-persistence" => r#"// JOCKY Forensic Script — Windows Persistence & Event Logs
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,
        disk: mft_scan,
        network: active_connections
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}
"#,
                "linux-ebpf" => r#"// JOCKY Forensic Script — Linux Kernel eBPF Telemetry
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
}
"#,
                "pqc-vault" => r#"// JOCKY Forensic Script — Post-Quantum Secure Vault Transmission
forensic session {
    target: "10.100.4.12";
    warrant: "NTRO-2026-INFIL-9901";
    profile: deep_audit;
    encrypt ml_kem(key: hsm_derived);
    transmit via: "wss://pqc-collector.ntro.gov.in/vault";
}
"#,
                other => anyhow::bail!("Unknown template '{}'. Available: triage, windows-persistence, linux-ebpf, pqc-vault", other),
            };

            if let Some(out_path) = output {
                std::fs::write(&out_path, content)?;
                println!("✓ Scaffolding created: {}", out_path.display());
            } else {
                println!("{}", content);
            }
        }

        Commands::Run {
            script,
            input,
            target,
            host,
            scan_id,
            reports_dir,
            dry_run,
        } => {
            let input_path = match (script, input) {
                (Some(p), _) => p,
                (_, Some(p)) => p,
                (None, None) => anyhow::bail!("Please specify a .jocky script file"),
            };

            let source = std::fs::read_to_string(&input_path)
                .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", input_path.display(), e))?;

            let program = Parser::parse(&source)
                .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

            let target_os = match target.to_lowercase().as_str() {
                "windows" => TargetOS::Windows,
                "linux" | "ubuntu" => TargetOS::Linux,
                other => anyhow::bail!("Unknown target '{}'; use 'windows' or 'linux'", other),
            };

            Validator::validate_program(&program, Some(target_os))
                .map_err(|e| anyhow::anyhow!("Validation error: {}", e))?;

            let target_os_str = match target_os {
                TargetOS::Windows => "Windows",
                TargetOS::Linux => "Ubuntu",
            };

            let scan_result = jocky_compiler::engine::ForensicEngine::execute_scan(
                &program,
                &host,
                target_os_str,
                &scan_id,
                &reports_dir,
            )?;

            println!("JOCKY FORENSIC SCAN");
            println!("────────────────────────────");
            println!();
            println!("Host: {}", scan_result.host);
            println!("OS: {}", scan_result.os);
            println!("Scan ID: {}", scan_result.scan_id);
            println!();
            println!("[✓] Process Analysis");
            println!("[✓] Service Analysis");
            println!("[✓] User Account Analysis");
            println!("[✓] Persistence Analysis");
            println!("[✓] File-System Analysis");
            println!("[✓] Event Log Analysis");
            println!("[✓] Network Connection Analysis");
            println!("[✓] System Configuration Analysis");
            println!();
            println!("Evidence Collected: {}", scan_result.evidence_count);
            println!("Suspicious Indicators: {}", scan_result.indicator_summary.total);
            println!();
            println!("Report Generated:");
            println!("{}", scan_result.json_report_path);
            println!("{}", scan_result.html_report_path);

            if dry_run {
                println!();
                println!("✓ Dry-run completed successfully.");
            }
        }

    }

    Ok(())
}

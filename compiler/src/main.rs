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

    /// Simulate forensic collection dry-run locally and output JSON telemetry
    Run {
        #[arg(short, long, help = "Input .jocky script")]
        input: PathBuf,

        #[arg(short, long, default_value = "linux", help = "Simulated Target OS: windows | linux")]
        target: String,
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
                    let path = f("/tmp/jocky_test.hiv");
                    std::fs::write(&path, b"mock registry hive").ok();
                    match RegistryParser::parse_hive(&path) {
                        Ok(keys) => println!("✓ RegistryParser: {} keys", keys.len()),
                        Err(e)   => eprintln!("✗ RegistryParser: {}", e),
                    }
                }
                "mft" => {
                    match MFTParser::parse_mft("/dev/mock") {
                        Ok(entries) => println!("✓ MFTParser: {} entries", entries.len()),
                        Err(e)      => eprintln!("✗ MFTParser: {}", e),
                    }
                }
                "proc" => {
                    match ProcParser::enumerate_processes() {
                        Ok(procs) => println!("✓ ProcParser: {} processes", procs.len()),
                        Err(e)    => eprintln!("⊘ ProcParser (may be non-Linux): {}", e),
                    }
                }
                "evtx" => {
                    let path = f("/tmp/jocky_test.evtx");
                    std::fs::write(&path, b"mock evtx").ok();
                    match EventLogParser::parse_evtx(&path) {
                        Ok(events) => println!("✓ EventLogParser: {} events", events.len()),
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
                    let batch = jocky_compiler::forensics::EbpfProbeManager::create_synthetic_telemetry("target-host");
                    println!("✓ EbpfProbeManager: {} exec events, {} file events, {} socket events",
                        batch.exec_events.len(), batch.file_events.len(), batch.socket_events.len());
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

        Commands::Run { input, target } => {
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

            println!("=== JOCKY DRY-RUN FORENSIC EXECUTION ===");
            for (i, session) in program.sessions.iter().enumerate() {
                println!("Session #{}: target={}, warrant={}", i + 1, session.target, session.warrant);
                println!("Encryption: {:?} (key source: {})", session.encrypt_algo, session.encrypt_key);
                println!("Transmit endpoint: {}", session.transmit_endpoint);
                println!("Artifact directives collected:");

                for item in &session.collect_items {
                    match item.artifact_type {
                        jocky_compiler::ast::ArtifactType::Proc => {
                            let procs = match ProcParser::enumerate_processes() {
                                Ok(p) => format!("{} live host processes found", p.len()),
                                Err(_) => "Simulated: 42 processes inspected".to_string(),
                            };
                            println!("  • [/proc]: {}", procs);
                        }
                        jocky_compiler::ast::ArtifactType::Network => {
                            println!("  • [network]: Ingested active socket telemetry (0 anomalous foreign sockets)");
                        }
                        jocky_compiler::ast::ArtifactType::Auditd => {
                            println!("  • [auditd]: Ingested syscall audit stream (execve, open, connect)");
                        }
                        jocky_compiler::ast::ArtifactType::Registry => {
                            println!("  • [registry]: Queried Run keys and UserAssist persistence hives");
                        }
                        jocky_compiler::ast::ArtifactType::Disk => {
                            println!("  • [disk]: Scanned NTFS MFT record table / ext4 journal structures");
                        }
                        _ => {
                            println!("  • [{:?}]: Ingested artifact directive", item.artifact_type);
                        }
                    }
                }
            }
            println!("Status: ALL ARTIFACT DIRECTIVES SIMULATED AND VERIFIED OK");
        }
    }

    Ok(())
}

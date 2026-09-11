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
        #[arg(short, long, help = "Parser to test: registry | mft | proc | evtx | auditd")]
        test_type: String,

        #[arg(short, long, help = "Optional test file path")]
        file: Option<PathBuf>,
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
                other => eprintln!("Unknown test type '{}'. Use: registry | mft | proc | evtx | auditd", other),
            }
        }
    }

    Ok(())
}

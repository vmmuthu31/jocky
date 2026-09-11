use jocky_compiler::ast::Program;
use jocky_compiler::codegen::{CodeGenerator, TargetOS};
use jocky_compiler::parser::Parser;
use jocky_compiler::validator::Validator;

#[test]
fn test_end_to_end_windows_forensics_pipeline() {
    let dsl = r#"
    forensic session {
        target: "192.168.1.50";
        warrant: "NTRO-2026-CYBER-1024";
        collect {
            registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
            memory: process "lsass.exe",
            disk: mft_scan
        };
        encrypt aes256(key: hsm_derived);
        transmit via: "wss://forensics-gateway.ntro.gov.in/telemetry";
    }
    "#;

    let program: Program = Parser::parse(dsl).expect("Parsing must succeed");
    assert_eq!(program.sessions.len(), 1);

    Validator::validate_program(&program, Some(TargetOS::Windows))
        .expect("Validation for Windows must pass");

    let mut codegen = CodeGenerator::new("windows_session", TargetOS::Windows)
        .expect("Codegen initialization");
    codegen
        .codegen_program(&program, TargetOS::Windows)
        .expect("Codegen must succeed");

    let ir = codegen.ir_text();
    assert!(ir.contains("target triple = \"x86_64-pc-windows-msvc\""));
    assert!(ir.contains("192.168.1.50"));
    assert!(ir.contains("NTRO-2026-CYBER-1024"));
    assert!(ir.contains("jocky_init_session"));
    assert!(ir.contains("jocky_collect_artifact"));
    assert!(ir.contains("jocky_encrypt_payload"));
    assert!(ir.contains("jocky_transmit_secure"));
}

#[test]
fn test_end_to_end_linux_ebpf_session() {
    let dsl = r#"
    forensic session {
        target: "10.100.4.12";
        warrant: "NTRO-2026-INFIL-9901";
        collect {
            proc: all_processes,
            auditd: execve | connect,
            network: active_sockets,
            ext4: journal_inspection
        };
        encrypt chacha20(key: hsm_derived);
        transmit via: "wss://node-alpha.ntro.gov.in/evidence";
    }
    "#;

    let program: Program = Parser::parse(dsl).expect("Parsing must succeed");
    assert_eq!(program.sessions.len(), 1);

    Validator::validate_program(&program, Some(TargetOS::Linux))
        .expect("Validation for Linux must pass");

    let mut codegen = CodeGenerator::new("linux_session", TargetOS::Linux)
        .expect("Codegen initialization");
    codegen
        .codegen_program(&program, TargetOS::Linux)
        .expect("Codegen must succeed");

    let ir = codegen.ir_text();
    assert!(ir.contains("target triple = \"x86_64-unknown-linux-gnu\""));
    assert!(ir.contains("10.100.4.12"));
    assert!(ir.contains("NTRO-2026-INFIL-9901"));
}

#[test]
fn test_illegal_cross_compilation_fails_validation() {
    let dsl = r#"
    forensic session {
        target: "10.0.0.9";
        warrant: "NTRO-2026-CYBER-0001";
        collect {
            registry: HKLM\Run
        };
        encrypt aes256(key: hsm_derived);
        transmit via: "wss://collector.ntro.gov.in";
    }
    "#;

    let program: Program = Parser::parse(dsl).expect("Parsing succeeded");
    let result = Validator::validate_program(&program, Some(TargetOS::Linux));
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("only compatible with Windows targets"));
}

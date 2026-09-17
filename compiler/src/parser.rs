use crate::ast::*;
use anyhow::{anyhow, Result};

pub struct Parser;

impl Parser {
    /// Parse a JOCKY DSL source string into a Program AST.
    /// Uses a hand-rolled recursive-descent parser (tree-sitter binding
    /// generation requires a C build step that is skipped for MVP; the
    /// grammar definition lives in grammar.js for reference).
    pub fn parse(source: &str) -> Result<Program> {
        let mut p = InnerParser::new(source);
        p.parse_program()
    }
}

// ── Internal parser ──────────────────────────────────────────────────────────

struct InnerParser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> InnerParser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn line_col(&self) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;
        for (i, b) in self.src.bytes().enumerate() {
            if i >= self.pos {
                break;
            }
            if b == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    fn error(&self, msg: &str) -> anyhow::Error {
        let (line, col) = self.line_col();
        anyhow::anyhow!("[Line {}, Col {}]: {}", line, col, msg)
    }

    fn parse_program(&mut self) -> Result<Program> {
        let mut sessions = Vec::new();
        let mut statements = Vec::new();
        self.skip_ws_comments();
        while self.pos < self.src.len() {
            if self.peek_keyword("forensic") {
                let save = self.pos;
                self.pos += "forensic".len();
                self.skip_ws_comments();
                if self.peek_char('.') {
                    self.pos = save;
                    statements.push(self.parse_method_call()?);
                } else {
                    self.pos = save;
                    sessions.push(self.parse_session()?);
                }
            } else if self.peek_keyword("system") {
                statements.push(self.parse_method_call()?);
            } else {
                statements.push(self.parse_method_call()?);
            }
            self.skip_ws_comments();
        }
        if sessions.is_empty() && statements.is_empty() {
            return Err(self.error("No forensic sessions or statements found in source"));
        }
        Ok(Program { sessions, statements })
    }

    fn parse_method_call(&mut self) -> Result<MethodCall> {
        let module = self.read_identifier()?;
        self.skip_ws_comments();
        self.expect_char('.')?;
        self.skip_ws_comments();
        let function = self.read_identifier()?;
        self.skip_ws_comments();
        self.expect_char('(')?;
        self.skip_ws_comments();
        let mut args = Vec::new();
        while !self.peek_char(')') && self.pos < self.src.len() {
            if self.peek_char('"') {
                args.push(self.parse_string()?);
            } else {
                let arg = self.read_identifier()?;
                args.push(arg);
            }
            self.skip_ws_comments();
            if self.peek_char(',') {
                self.pos += 1;
                self.skip_ws_comments();
            }
        }
        self.expect_char(')')?;
        self.skip_ws_comments();
        if self.peek_char(';') {
            self.pos += 1;
        }
        Ok(MethodCall { module, function, args })
    }


    fn parse_session(&mut self) -> Result<ForensicSession> {
        self.expect_keyword("forensic")?;
        self.skip_ws_comments();
        self.expect_keyword("session")?;
        self.skip_ws_comments();
        self.expect_char('{')?;
        self.skip_ws_comments();

        let mut target = String::new();
        let mut warrant = String::new();
        let mut profile: Option<Profile> = None;
        let mut collect_items = Vec::new();
        let mut encrypt_algo = EncryptionAlgo::Aes256;
        let mut encrypt_key = "hsm_derived".to_string();
        let mut has_encrypt = false;
        let mut transmit_endpoint = "wss://telemetry.jocky.internal/forensics".to_string();

        while !self.peek_char('}') && self.pos < self.src.len() {
            if self.peek_keyword("target") {
                target = self.parse_field("target")?;
            } else if self.peek_keyword("warrant") {
                warrant = self.parse_field("warrant")?;
            } else if self.peek_keyword("profile") {
                profile = Some(self.parse_profile()?);
            } else if self.peek_keyword("collect") {
                collect_items = self.parse_collect_block()?;
                self.skip_ws_comments();
                if self.peek_char(';') {
                    self.pos += 1;
                }
            } else if self.peek_keyword("encrypt") {
                let (algo, key) = self.parse_encrypt()?;
                encrypt_algo = algo;
                encrypt_key = key;
                has_encrypt = true;
            } else if self.peek_keyword("transmit") {
                transmit_endpoint = self.parse_transmit()?;
            } else {
                return Err(self.error("Unexpected statement inside forensic session. Expected target, warrant, profile, collect, encrypt, or transmit"));
            }
            self.skip_ws_comments();
        }

        self.expect_char('}')?;

        if target.is_empty() {
            return Err(self.error("Missing required 'target' field in forensic session"));
        }
        if warrant.is_empty() {
            return Err(self.error("Missing required 'warrant' field in forensic session"));
        }

        if collect_items.is_empty() {
            if let Some(ref prof) = profile {
                collect_items = Self::expand_profile_defaults(prof);
            }
        }

        if !has_encrypt && profile.is_some() {
            encrypt_algo = EncryptionAlgo::Aes256;
            encrypt_key = "hsm_derived".to_string();
        }

        Ok(ForensicSession {
            target,
            warrant,
            profile,
            collect_items,
            encrypt_algo,
            encrypt_key,
            transmit_endpoint,
        })
    }

    fn parse_profile(&mut self) -> Result<Profile> {
        self.expect_keyword("profile")?;
        self.skip_ws_comments();
        self.expect_char(':')?;
        self.skip_ws_comments();
        let prof_name = self.read_identifier()?;
        self.skip_ws_comments();
        self.expect_char(';')?;

        match prof_name.as_str() {
            "triage" => Ok(Profile::Triage),
            "incident_response" => Ok(Profile::IncidentResponse),
            "network_trace" => Ok(Profile::NetworkTrace),
            "deep_audit" => Ok(Profile::DeepAudit),
            other => Err(self.error(&format!("Unknown profile '{}'. Available: triage, incident_response, network_trace, deep_audit", other))),
        }
    }

    fn expand_profile_defaults(profile: &Profile) -> Vec<CollectItem> {
        match profile {
            Profile::Triage => vec![
                CollectItem {
                    artifact_type: ArtifactType::Proc,
                    expression: Expression::Identifier("all_processes".to_string()),
                },
                CollectItem {
                    artifact_type: ArtifactType::Network,
                    expression: Expression::Identifier("active_connections".to_string()),
                },
            ],
            Profile::IncidentResponse => vec![
                CollectItem {
                    artifact_type: ArtifactType::Proc,
                    expression: Expression::Identifier("all_processes".to_string()),
                },
                CollectItem {
                    artifact_type: ArtifactType::Auditd,
                    expression: Expression::PipeExpr {
                        left: Box::new(Expression::Identifier("execve".to_string())),
                        right: Box::new(Expression::Identifier("connect".to_string())),
                    },
                },
                CollectItem {
                    artifact_type: ArtifactType::Network,
                    expression: Expression::Identifier("active_connections".to_string()),
                },
            ],
            Profile::NetworkTrace => vec![
                CollectItem {
                    artifact_type: ArtifactType::Network,
                    expression: Expression::Identifier("active_connections".to_string()),
                },
            ],
            Profile::DeepAudit => vec![
                CollectItem {
                    artifact_type: ArtifactType::Proc,
                    expression: Expression::Identifier("all_processes".to_string()),
                },
                CollectItem {
                    artifact_type: ArtifactType::Auditd,
                    expression: Expression::Identifier("execve".to_string()),
                },
                CollectItem {
                    artifact_type: ArtifactType::Ext4,
                    expression: Expression::Identifier("journal_inspection".to_string()),
                },
                CollectItem {
                    artifact_type: ArtifactType::Network,
                    expression: Expression::Identifier("active_connections".to_string()),
                },
            ],
        }
    }

    fn parse_field(&mut self, name: &str) -> Result<String> {
        self.expect_keyword(name)?;
        self.skip_ws_comments();
        self.expect_char(':')?;
        self.skip_ws_comments();
        let val = self.parse_string()?;
        self.skip_ws_comments();
        self.expect_char(';')?;
        Ok(val)
    }

    fn parse_collect_block(&mut self) -> Result<Vec<CollectItem>> {
        self.expect_keyword("collect")?;
        self.skip_ws_comments();
        self.expect_char('{')?;
        self.skip_ws_comments();

        let mut items = Vec::new();
        while !self.peek_char('}') {
            items.push(self.parse_collect_item()?);
            self.skip_ws_comments();
            // optional trailing comma
            if self.peek_char(',') {
                self.pos += 1;
                self.skip_ws_comments();
            }
        }
        self.expect_char('}')?;
        Ok(items)
    }

    fn parse_collect_item(&mut self) -> Result<CollectItem> {
        let artifact_type = self.parse_artifact_type()?;
        self.skip_ws_comments();
        self.expect_char(':')?;
        self.skip_ws_comments();
        let expression = self.parse_expression()?;
        // consume optional trailing semicolon inside collect block
        self.skip_ws_comments();
        if self.peek_char(';') {
            self.pos += 1;
        }
        Ok(CollectItem { artifact_type, expression })
    }

    fn parse_artifact_type(&mut self) -> Result<ArtifactType> {
        let word = self.read_identifier()?;
        match word.as_str() {
            "registry" => Ok(ArtifactType::Registry),
            "memory"   => Ok(ArtifactType::Memory),
            "network"  => Ok(ArtifactType::Network),
            "disk"     => Ok(ArtifactType::Disk),
            "proc"     => Ok(ArtifactType::Proc),
            "auditd"   => Ok(ArtifactType::Auditd),
            "ext4"     => Ok(ArtifactType::Ext4),
            other      => Err(anyhow!("Unknown artifact type: {}", other)),
        }
    }

    fn parse_expression(&mut self) -> Result<Expression> {
        if self.peek_char('"') {
            return Ok(Expression::StringLiteral(self.parse_string()?));
        }
        // Read until comma, newline, closing brace, or semicolon
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src.as_bytes()[self.pos] as char;
            if c == ',' || c == '}' || c == ';' || c == '\n' {
                break;
            }
            self.pos += 1;
        }
        let raw = self.src[start..self.pos].trim().to_string();
        if raw.is_empty() {
            return Err(anyhow!("Empty expression"));
        }
        // Handle process "name" form
        if raw.starts_with("process ") {
            let inner = raw[8..].trim().trim_matches('"').to_string();
            return Ok(Expression::ProcessExpr { process: inner });
        }
        // Handle a | b pipe form
        if raw.contains('|') {
            let parts: Vec<&str> = raw.splitn(2, '|').collect();
            return Ok(Expression::PipeExpr {
                left: Box::new(Expression::Identifier(parts[0].trim().to_string())),
                right: Box::new(Expression::Identifier(parts[1].trim().to_string())),
            });
        }
        Ok(Expression::Identifier(raw))
    }

    fn parse_encrypt(&mut self) -> Result<(EncryptionAlgo, String)> {
        self.expect_keyword("encrypt")?;
        self.skip_ws_comments();
        let algo_str = self.read_identifier()?;
        let algo = match algo_str.as_str() {
            "aes256"   => EncryptionAlgo::Aes256,
            "chacha20" => EncryptionAlgo::ChaCha20,
            "ml_kem"   => EncryptionAlgo::MlKem,
            other      => return Err(anyhow!("Unknown encryption algorithm: {}", other)),
        };
        self.skip_ws_comments();
        self.expect_char('(')?;
        self.skip_ws_comments();
        self.expect_keyword("key")?;
        self.skip_ws_comments();
        self.expect_char(':')?;
        self.skip_ws_comments();
        let key = self.read_identifier()?;
        self.skip_ws_comments();
        self.expect_char(')')?;
        self.skip_ws_comments();
        self.expect_char(';')?;
        Ok((algo, key))
    }

    fn parse_transmit(&mut self) -> Result<String> {
        self.expect_keyword("transmit")?;
        self.skip_ws_comments();
        self.expect_keyword("via")?;
        self.skip_ws_comments();
        self.expect_char(':')?;
        self.skip_ws_comments();
        let endpoint = self.parse_string()?;
        self.skip_ws_comments();
        self.expect_char(';')?;
        Ok(endpoint)
    }

    // ── Primitives ────────────────────────────────────────────────────────────

    fn parse_string(&mut self) -> Result<String> {
        self.expect_char('"')?;
        let start = self.pos;
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos] != b'"' {
            self.pos += 1;
        }
        let s = self.src[start..self.pos].to_string();
        self.expect_char('"')?;
        Ok(s)
    }

    fn read_identifier(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src.as_bytes()[self.pos] as char;
            if c.is_alphanumeric() || c == '_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let word = &self.src[start..self.pos];
        if word.is_empty() {
            Err(self.error(&format!("Expected identifier at offset {}", start)))
        } else {
            Ok(word.to_string())
        }
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<()> {
        if self.src[self.pos..].starts_with(kw) {
            self.pos += kw.len();
            Ok(())
        } else {
            Err(self.error(&format!("Expected keyword '{}'", kw)))
        }
    }

    fn expect_char(&mut self, ch: char) -> Result<()> {
        if self.pos < self.src.len() && self.src.as_bytes()[self.pos] as char == ch {
            self.pos += 1;
            Ok(())
        } else {
            let got = self.src.get(self.pos..self.pos + 1).unwrap_or("EOF");
            Err(self.error(&format!("Expected '{}' but found '{}'", ch, got)))
        }
    }

    fn peek_char(&self, ch: char) -> bool {
        self.src.as_bytes().get(self.pos).copied() == Some(ch as u8)
    }

    fn peek_keyword(&self, kw: &str) -> bool {
        self.src[self.pos..].starts_with(kw)
    }

    fn skip_ws_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.pos < self.src.len() && (self.src.as_bytes()[self.pos] as char).is_whitespace() {
                self.pos += 1;
            }
            // Skip // line comments
            if self.src[self.pos..].starts_with("//") {
                while self.pos < self.src.len() && self.src.as_bytes()[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_procedural_script() {
        let src = r#"
system.processes()
system.services()
system.network_connections()
system.users()
system.persistence()

forensic.collect_logs()
forensic.collect_files()
forensic.generate_report()
"#;
        let prog = Parser::parse(src).expect("Should parse procedural script");
        assert_eq!(prog.statements.len(), 8);
        assert_eq!(prog.statements[0].module, "system");
        assert_eq!(prog.statements[0].function, "processes");
        assert_eq!(prog.statements[7].module, "forensic");
        assert_eq!(prog.statements[7].function, "generate_report");
    }
}


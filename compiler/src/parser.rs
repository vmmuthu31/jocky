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

    fn parse_program(&mut self) -> Result<Program> {
        let mut sessions = Vec::new();
        self.skip_ws_comments();
        while self.pos < self.src.len() {
            sessions.push(self.parse_session()?);
            self.skip_ws_comments();
        }
        if sessions.is_empty() {
            return Err(anyhow!("No forensic sessions found in source"));
        }
        Ok(Program { sessions })
    }

    fn parse_session(&mut self) -> Result<ForensicSession> {
        self.expect_keyword("forensic")?;
        self.skip_ws_comments();
        self.expect_keyword("session")?;
        self.skip_ws_comments();
        self.expect_char('{')?;
        self.skip_ws_comments();

        let target = self.parse_field("target")?;
        self.skip_ws_comments();

        // warrant is required
        if !self.peek_keyword("warrant") {
            return Err(anyhow!("Missing required 'warrant' field in forensic session"));
        }
        let warrant = self.parse_field("warrant")?;
        self.skip_ws_comments();

        let collect_items = self.parse_collect_block()?;
        self.skip_ws_comments();
        // DSL allows optional `;` after the collect `}` block
        if self.peek_char(';') {
            self.pos += 1;
        }
        self.skip_ws_comments();

        let (encrypt_algo, encrypt_key) = self.parse_encrypt()?;
        self.skip_ws_comments();

        let transmit_endpoint = self.parse_transmit()?;
        self.skip_ws_comments();

        self.expect_char('}')?;

        Ok(ForensicSession {
            target,
            warrant,
            collect_items,
            encrypt_algo,
            encrypt_key,
            transmit_endpoint,
        })
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
            Err(anyhow!("Expected identifier at position {}", start))
        } else {
            Ok(word.to_string())
        }
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<()> {
        if self.src[self.pos..].starts_with(kw) {
            self.pos += kw.len();
            Ok(())
        } else {
            Err(anyhow!("Expected keyword '{}' at pos {}", kw, self.pos))
        }
    }

    fn expect_char(&mut self, ch: char) -> Result<()> {
        if self.pos < self.src.len() && self.src.as_bytes()[self.pos] as char == ch {
            self.pos += 1;
            Ok(())
        } else {
            let got = self.src.get(self.pos..self.pos + 1).unwrap_or("EOF");
            Err(anyhow!("Expected '{}' but got '{}' at pos {}", ch, got, self.pos))
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

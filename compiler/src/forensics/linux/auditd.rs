use crate::forensics::AuditEntry;
use anyhow::Result;
use std::fs;

pub struct AuditdParser;

impl AuditdParser {
    /// Parse a Linux auditd audit.log file.
    /// Each line is expected to begin with `type=<TYPE>`.
    pub fn parse_audit_logs(log_path: &str) -> Result<Vec<AuditEntry>> {
        let contents = fs::read_to_string(log_path)
            .map_err(|e| anyhow::anyhow!("Failed to read audit log '{}': {}", log_path, e))?;

        let entries: Vec<AuditEntry> = contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| Self::parse_line(line).ok())
            .collect();

        Ok(entries)
    }

    fn parse_line(line: &str) -> Result<AuditEntry> {
        // Example: type=EXECVE msg=audit(1694430720.123:42): argc=2 a0="/bin/bash"
        let syscall = if line.contains("EXECVE") {
            "execve"
        } else if line.contains("OPEN") || line.contains("openat") {
            "open"
        } else if line.contains("CONNECT") {
            "connect"
        } else {
            "unknown"
        };

        // Extract timestamp from msg=audit(TIMESTAMP.xxx:N)
        let timestamp = Self::extract_timestamp(line);

        // Extract argc args
        let args = Self::extract_args(line);

        Ok(AuditEntry {
            timestamp,
            syscall: syscall.to_string(),
            pid: 0,   // real impl extracts pid= field
            uid: 0,   // real impl extracts uid= field
            name: String::new(),
            result: "success".to_string(),
            args,
        })
    }

    fn extract_timestamp(line: &str) -> u64 {
        if let Some(start) = line.find("audit(") {
            let rest = &line[start + 6..];
            if let Some(end) = rest.find('.') {
                return rest[..end].parse().unwrap_or(0);
            }
        }
        0
    }

    fn extract_args(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let rest = line;
        while let Some(pos) = rest.find("a0=") {
            let start = pos + 3;
            let chunk = &rest[start..];
            let arg = if chunk.starts_with('"') {
                // quoted string
                let inner = &chunk[1..];
                let end = inner.find('"').unwrap_or(inner.len());
                inner[..end].to_string()
            } else {
                // unquoted token
                chunk.split_whitespace().next().unwrap_or("").to_string()
            };
            args.push(arg);
            let _ = &rest[pos + 3..];
            break; // MVP: parse a0 only; real impl loops a0..aN
        }
        args
    }

    pub fn filter_by_syscall(log_path: &str, syscall: &str) -> Result<Vec<AuditEntry>> {
        Ok(Self::parse_audit_logs(log_path)?
            .into_iter()
            .filter(|e| e.syscall == syscall)
            .collect())
    }

    pub fn extract_execve(log_path: &str) -> Result<Vec<AuditEntry>> {
        Self::filter_by_syscall(log_path, "execve")
    }

    pub fn extract_file_access(log_path: &str) -> Result<Vec<AuditEntry>> {
        Self::filter_by_syscall(log_path, "open")
    }

    pub fn extract_network_connect(log_path: &str) -> Result<Vec<AuditEntry>> {
        Self::filter_by_syscall(log_path, "connect")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_audit_log(path: &str, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_parse_audit_logs_execve() {
        let p = "/tmp/audit_test.log";
        write_audit_log(
            p,
            "type=EXECVE msg=audit(1694430720.123:42): argc=2 a0=\"/bin/bash\" a1=\"-c\"\n",
        );
        let entries = AuditdParser::parse_audit_logs(p).expect("parse_audit_logs failed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].syscall, "execve");
        assert_eq!(entries[0].timestamp, 1_694_430_720);
    }

    #[test]
    fn test_extract_execve() {
        let p = "/tmp/audit_execve.log";
        write_audit_log(p, "type=EXECVE msg=audit(1694430720.123:1): argc=1 a0=\"/bin/ls\"\n");
        let entries = AuditdParser::extract_execve(p).expect("extract_execve failed");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.syscall == "execve"));
    }

    #[test]
    fn test_missing_log_returns_error() {
        let result = AuditdParser::parse_audit_logs("/nonexistent/audit.log");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_network_connect() {
        let p = "/tmp/audit_connect.log";
        write_audit_log(p, "type=CONNECT msg=audit(1694430720.456:10): addr=10.0.0.1\n");
        let entries = AuditdParser::extract_network_connect(p).expect("extract connect failed");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.syscall == "connect"));
    }
}

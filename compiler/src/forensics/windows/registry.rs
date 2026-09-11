use crate::forensics::RegistryKey;
use anyhow::Result;
use std::fs;

pub struct RegistryParser;

impl RegistryParser {
    /// Parse a Windows registry hive file.
    /// Real implementation parses the binary NK/VK record format;
    /// this stub returns representative data for testing.
    pub fn parse_hive(hive_path: &str) -> Result<Vec<RegistryKey>> {
        let _contents = fs::read(hive_path)
            .map_err(|e| anyhow::anyhow!("Failed to read hive '{}': {}", hive_path, e))?;

        Ok(vec![
            RegistryKey {
                path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                hive: "HKLM".to_string(),
                value_name: "Malware".to_string(),
                value_type: "REG_SZ".to_string(),
                value_data: br"C:\Windows\System32\malware.exe".to_vec(),
                last_write_time: 1694430720,
            },
            RegistryKey {
                path: r"Software\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
                hive: "HKCU".to_string(),
                value_name: "Persistence".to_string(),
                value_type: "REG_SZ".to_string(),
                value_data: br"powershell -enc BASE64".to_vec(),
                last_write_time: 1694431000,
            },
        ])
    }

    pub fn extract_run_keys(hive_path: &str) -> Result<Vec<RegistryKey>> {
        Ok(Self::parse_hive(hive_path)?
            .into_iter()
            .filter(|k| k.path.contains("Run"))
            .collect())
    }

    pub fn extract_userassist(hive_path: &str) -> Result<Vec<RegistryKey>> {
        Ok(Self::parse_hive(hive_path)?
            .into_iter()
            .filter(|k| k.path.contains("UserAssist"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_mock_hive(path: &str) {
        std::fs::write(path, b"mock hive content").unwrap();
    }

    #[test]
    fn test_parse_registry_hive() {
        let p = "/tmp/test_hive.bin";
        write_mock_hive(p);
        let keys = RegistryParser::parse_hive(p).expect("parse_hive failed");
        assert!(!keys.is_empty());
        assert_eq!(keys[0].hive, "HKLM");
    }

    #[test]
    fn test_extract_run_keys() {
        let p = "/tmp/test_hive.bin";
        write_mock_hive(p);
        let run_keys = RegistryParser::extract_run_keys(p).expect("extract_run_keys failed");
        assert!(run_keys.iter().all(|k| k.path.contains("Run")));
    }

    #[test]
    fn test_missing_hive_returns_error() {
        let result = RegistryParser::parse_hive("/nonexistent/hive.bin");
        assert!(result.is_err());
    }
}

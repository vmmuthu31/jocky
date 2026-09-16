use crate::forensics::RegistryKey;
use anyhow::{bail, Result};
use std::fs;

pub struct RegistryParser;

// Windows registry hive files start with the signature "regf" (0x72 0x65 0x67 0x66).
const REGF_MAGIC: &[u8] = b"regf";

impl RegistryParser {
    /// Parse a Windows registry hive file.
    ///
    /// The file must be a valid REGF hive (magic bytes `regf`).  Full NK/VK
    /// record parsing requires the `nt-hive2` crate which is not bundled in
    /// this build — this implementation validates the format and returns the
    /// parsed header metadata.  On a live Windows forensic agent the registry
    /// is read via `RegOpenKeyEx` / offline via the ntdll hive loader; this
    /// function handles the offline image path.
    pub fn parse_hive(hive_path: &str) -> Result<Vec<RegistryKey>> {
        let contents = fs::read(hive_path)
            .map_err(|e| anyhow::anyhow!("Cannot read hive '{}': {}", hive_path, e))?;

        if contents.len() < 4 {
            bail!("File '{}' is too small to be a registry hive ({} bytes)", hive_path, contents.len());
        }

        if &contents[..4] != REGF_MAGIC {
            bail!(
                "File '{}' does not have the REGF magic signature (got {:02x?}); \
                 ensure this is a raw Windows registry hive exported with `reg save` or \
                 acquired from %SystemRoot%\\System32\\config\\",
                hive_path, &contents[..4]
            );
        }

        // hbin blocks start at offset 0x1000.  A minimal parser reads the root
        // cell offset from bytes 0x24..0x28 (little-endian i32).
        if contents.len() < 0x28 {
            bail!("REGF header truncated in '{}'", hive_path);
        }
        let root_cell_offset = i32::from_le_bytes([
            contents[0x24], contents[0x25], contents[0x26], contents[0x27],
        ]);

        // Return a minimal structural record describing the hive root.
        // Full deep-parse of NK cells requires the `nt-hive2` crate.
        Ok(vec![RegistryKey {
            path: "(hive root)".to_string(),
            hive: hive_path.to_string(),
            value_name: "__root_cell_offset__".to_string(),
            value_type: "DWORD".to_string(),
            value_data: root_cell_offset.to_le_bytes().to_vec(),
            last_write_time: Self::parse_last_write_time(&contents),
        }])
    }

    fn parse_last_write_time(contents: &[u8]) -> u64 {
        if contents.len() >= 0x30 {
            u64::from_le_bytes([
                contents[0x28], contents[0x29], contents[0x2A], contents[0x2B],
                contents[0x2C], contents[0x2D], contents[0x2E], contents[0x2F],
            ])
        } else {
            0
        }
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

    fn write_valid_regf(path: &str) {
        // Minimal valid REGF header: magic + padding to satisfy the 0x28 length check.
        let mut hive = vec![0u8; 0x30];
        hive[0..4].copy_from_slice(b"regf");
        // root_cell_offset at 0x24
        hive[0x24..0x28].copy_from_slice(&32i32.to_le_bytes());
        std::fs::write(path, &hive).unwrap();
    }

    #[test]
    fn test_parse_valid_regf_header() {
        let p = "/tmp/jocky_test_valid.hiv";
        write_valid_regf(p);
        let keys = RegistryParser::parse_hive(p).expect("valid REGF should parse");
        assert!(!keys.is_empty());
        assert_eq!(keys[0].path, "(hive root)");
    }

    #[test]
    fn test_invalid_magic_returns_error() {
        let p = "/tmp/jocky_test_bad.hiv";
        std::fs::write(p, b"BAD_MAGIC_BYTES_HERE").unwrap();
        let result = RegistryParser::parse_hive(p);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("REGF magic"), "error should mention REGF: {}", msg);
    }

    #[test]
    fn test_missing_hive_returns_error() {
        let result = RegistryParser::parse_hive("/nonexistent/hive.bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_too_small_returns_error() {
        let p = "/tmp/jocky_too_small.hiv";
        std::fs::write(p, b"re").unwrap();
        let result = RegistryParser::parse_hive(p);
        assert!(result.is_err());
    }
}

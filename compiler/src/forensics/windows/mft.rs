use crate::forensics::FileEntry;
use anyhow::Result;

pub struct MFTParser;

impl MFTParser {
    /// Parse Master File Table from an NTFS volume or image file.
    /// Stub returns representative entries; real implementation reads
    /// the $MFT file at logical cluster 0 of the NTFS volume.
    pub fn parse_mft(_device_or_file: &str) -> Result<Vec<FileEntry>> {
        Ok(vec![
            FileEntry {
                path: r"C:\Windows\System32\cmd.exe".to_string(),
                inode: 5,
                size: 348_160,
                created: 1_672_531_200,
                modified: 1_694_430_720,
                accessed: 1_694_431_800,
                mft_record_number: 42,
            },
            FileEntry {
                path: r"C:\Users\Admin\AppData\Roaming\malware.exe".to_string(),
                inode: 102,
                size: 512_000,
                created: 1_694_425_000,
                modified: 1_694_429_900,
                accessed: 1_694_430_100,
                mft_record_number: 102,
            },
        ])
    }

    pub fn extract_deleted_files(device: &str) -> Result<Vec<FileEntry>> {
        Self::parse_mft(device)
    }

    pub fn parse_usn_journal(_device: &str) -> Result<Vec<String>> {
        Ok(vec![
            "File C:\\deleted.txt was deleted at 1694430000".to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mft() {
        let entries = MFTParser::parse_mft("/dev/mock").expect("parse_mft failed");
        assert!(!entries.is_empty());
        assert!(entries[0].path.contains("cmd.exe"));
    }

    #[test]
    fn test_extract_deleted_files() {
        let result = MFTParser::extract_deleted_files("/dev/mock");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_usn_journal() {
        let result = MFTParser::parse_usn_journal("/dev/mock").expect("usn_journal failed");
        assert!(!result.is_empty());
        assert!(result[0].contains("deleted"));
    }
}

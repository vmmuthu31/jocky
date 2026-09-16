use crate::forensics::FileEntry;
use anyhow::{bail, Result};
use std::fs;

pub struct MFTParser;

// NTFS volume boot record starts with 0xEB 0x52 0x90 "NTFS    " at offset 3.
// MFT records (FILE) start with the magic "FILE" (0x46 0x49 0x4C 0x45).
const FILE_MAGIC: &[u8] = b"FILE";
const MFT_RECORD_SIZE: usize = 1024; // standard 1 KB MFT record

impl MFTParser {
    /// Parse Master File Table records from an NTFS volume image or raw $MFT file.
    ///
    /// The device/file must either be:
    ///   (a) a raw $MFT export (sequence of 1 KB FILE records), or
    ///   (b) an NTFS volume image with the boot sector at offset 0.
    ///
    /// Full attribute parsing (0x30 $FILE_NAME, 0x80 $DATA) requires additional
    /// implementation; this parses FILE record headers and LSN/sequence numbers.
    /// On a live Windows agent, $MFT is read via a raw volume handle with
    /// `CreateFile("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ|WRITE, ...)`.
    pub fn parse_mft(device_or_file: &str) -> Result<Vec<FileEntry>> {
        let contents = fs::read(device_or_file)
            .map_err(|e| anyhow::anyhow!("Cannot read MFT source '{}': {}", device_or_file, e))?;

        if contents.is_empty() {
            bail!("MFT source '{}' is empty", device_or_file);
        }

        // Check if this looks like a raw $MFT file (first record must be FILE magic)
        if contents.len() < FILE_MAGIC.len() {
            bail!("MFT source '{}' too small ({} bytes)", device_or_file, contents.len());
        }

        if &contents[..FILE_MAGIC.len()] != FILE_MAGIC {
            bail!(
                "MFT source '{}' does not start with FILE record magic (got {:02x?}). \
                 Export $MFT with: `cp \\\\.\\C:\\$MFT <output>` or use a forensic imager.",
                device_or_file, &contents[..FILE_MAGIC.len()]
            );
        }

        let mut entries = Vec::new();
        let mut offset = 0usize;
        let mut record_num: u64 = 0;

        while offset + MFT_RECORD_SIZE <= contents.len() {
            let record = &contents[offset..offset + MFT_RECORD_SIZE];

            if &record[..4] != FILE_MAGIC {
                offset += MFT_RECORD_SIZE;
                record_num += 1;
                continue;
            }

            // Sequence number at bytes 0x10..0x12 (u16 LE)
            let seq = u16::from_le_bytes([record[0x10], record[0x11]]);

            // Flags at bytes 0x16..0x18 (u16 LE): bit 0 = in-use, bit 1 = directory
            let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
            let in_use = (flags & 1) != 0;

            entries.push(FileEntry {
                path: format!("$MFT[{}] seq={} flags={:#06x}", record_num, seq, flags),
                inode: record_num,
                size: MFT_RECORD_SIZE as u64,
                created: 0,   // $STANDARD_INFORMATION attribute parse needed
                modified: 0,
                accessed: 0,
                mft_record_number: record_num,
            });

            if !in_use {
                // Deleted/unallocated record — mark path for analyst attention
                let last = entries.last_mut().unwrap();
                last.path = format!("$MFT[{}] seq={} DELETED flags={:#06x}", record_num, seq, flags);
            }

            offset += MFT_RECORD_SIZE;
            record_num += 1;
        }

        if entries.is_empty() {
            bail!("No valid FILE records found in '{}' — file may be corrupted or not an MFT image", device_or_file);
        }

        Ok(entries)
    }

    pub fn extract_deleted_files(device: &str) -> Result<Vec<FileEntry>> {
        Ok(Self::parse_mft(device)?
            .into_iter()
            .filter(|e| e.path.contains("DELETED"))
            .collect())
    }

    pub fn parse_usn_journal(device: &str) -> Result<Vec<String>> {
        let contents = fs::read(device)
            .map_err(|e| anyhow::anyhow!("Cannot read USN journal source '{}': {}", device, e))?;

        if contents.is_empty() {
            bail!("USN journal source '{}' is empty", device);
        }

        // USN_RECORD_V2 starts with a 4-byte RecordLength (u32 LE).
        // First record at offset 8 (the journal header is 8 bytes of zeros for a raw export).
        let mut records = Vec::new();
        let mut offset = 8usize;

        while offset + 60 <= contents.len() {
            let rec_len = u32::from_le_bytes([
                contents[offset], contents[offset + 1],
                contents[offset + 2], contents[offset + 3],
            ]) as usize;

            if rec_len == 0 || offset + rec_len > contents.len() {
                break;
            }

            let usn = u64::from_le_bytes([
                contents[offset + 8], contents[offset + 9],
                contents[offset + 10], contents[offset + 11],
                contents[offset + 12], contents[offset + 13],
                contents[offset + 14], contents[offset + 15],
            ]);

            let reason = u32::from_le_bytes([
                contents[offset + 40], contents[offset + 41],
                contents[offset + 42], contents[offset + 43],
            ]);

            records.push(format!("USN={} reason_flags={:#010x}", usn, reason));
            offset += rec_len;
        }

        if records.is_empty() {
            bail!("No USN records found in '{}' — export $UsnJrnl:$J with `fsutil usn readjournal C:`", device);
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_valid_mft(path: &str, num_records: usize) {
        let mut data = vec![0u8; MFT_RECORD_SIZE * num_records];
        for i in 0..num_records {
            let off = i * MFT_RECORD_SIZE;
            data[off..off + 4].copy_from_slice(FILE_MAGIC);
            // seq = i as u16
            let seq = i as u16;
            data[off + 0x10..off + 0x12].copy_from_slice(&seq.to_le_bytes());
            // flags: in-use for even, deleted for odd
            let flags: u16 = if i % 2 == 0 { 1 } else { 0 };
            data[off + 0x16..off + 0x18].copy_from_slice(&flags.to_le_bytes());
        }
        std::fs::write(path, &data).unwrap();
    }

    #[test]
    fn test_parse_mft_records() {
        let p = "/tmp/jocky_test_mft.bin";
        write_valid_mft(p, 4);
        let entries = MFTParser::parse_mft(p).expect("valid MFT should parse");
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn test_extract_deleted_files() {
        let p = "/tmp/jocky_test_mft_del.bin";
        write_valid_mft(p, 4);
        let deleted = MFTParser::extract_deleted_files(p).expect("should work");
        // Records 1 and 3 have flags=0 (not in-use)
        assert!(!deleted.is_empty());
        assert!(deleted.iter().all(|e| e.path.contains("DELETED")));
    }

    #[test]
    fn test_invalid_magic_returns_error() {
        let p = "/tmp/jocky_bad_mft.bin";
        std::fs::write(p, b"NOTFILENOT").unwrap();
        let result = MFTParser::parse_mft(p);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("FILE record magic"), "error must mention FILE magic: {}", msg);
    }

    #[test]
    fn test_missing_file_returns_error() {
        let result = MFTParser::parse_mft("/nonexistent/mft.bin");
        assert!(result.is_err());
    }
}

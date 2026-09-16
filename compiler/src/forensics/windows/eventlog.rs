use crate::forensics::EventLogEntry;
use anyhow::{bail, Result};
use std::fs;

pub struct EventLogParser;

// Windows EVTX files start with "ElfFile\0" (0x45 0x6C 0x66 0x46 0x69 0x6C 0x65 0x00).
const EVTX_MAGIC: &[u8] = b"ElfFile\0";

// EVTX chunk header magic "ElfChnk\0"
const CHUNK_MAGIC: &[u8] = b"ElfChnk\0";

// Offset of first_chunk offset in the EVTX file header (bytes 0x10..0x18, little-endian u64)
const HEADER_FIRST_CHUNK_OFFSET: usize = 0x10;
const HEADER_SIZE: usize = 0x1000; // 4 KB file header

impl EventLogParser {
    /// Parse a Windows .evtx file.
    ///
    /// Validates the EVTX file magic and scans chunk headers to extract
    /// event records.  Full XML binxml deserialization of each record requires
    /// the `evtx` crate (not bundled in this build); this implementation
    /// validates the binary structure and returns structural metadata per chunk.
    ///
    /// On a live Windows forensic agent, events are read via `EvtQuery` /
    /// `EvtRender` Win32 APIs; this function handles offline image analysis.
    pub fn parse_evtx(evtx_path: &str) -> Result<Vec<EventLogEntry>> {
        let contents = fs::read(evtx_path)
            .map_err(|e| anyhow::anyhow!("Cannot read evtx '{}': {}", evtx_path, e))?;

        if contents.len() < EVTX_MAGIC.len() {
            bail!("File '{}' is too small to be an EVTX log ({} bytes)", evtx_path, contents.len());
        }

        if &contents[..EVTX_MAGIC.len()] != EVTX_MAGIC {
            bail!(
                "File '{}' does not have the EVTX magic 'ElfFile\\0' (got {:02x?}); \
                 ensure this is a Windows Event Log exported with `wevtutil epl` or \
                 copied from %SystemRoot%\\System32\\winevt\\Logs\\",
                evtx_path, &contents[..EVTX_MAGIC.len().min(contents.len())]
            );
        }

        if contents.len() < HEADER_SIZE + CHUNK_MAGIC.len() {
            // Valid magic but no chunks yet (freshly created log)
            return Ok(vec![]);
        }

        // Read number_of_chunks from file header at offset 0x18 (u64 LE)
        let num_chunks = if contents.len() >= 0x20 {
            u64::from_le_bytes([
                contents[0x18], contents[0x19], contents[0x1A], contents[0x1B],
                contents[0x1C], contents[0x1D], contents[0x1E], contents[0x1F],
            ])
        } else {
            0
        };

        let mut entries = Vec::new();

        // Scan chunks starting at HEADER_SIZE (0x1000)
        let mut pos = HEADER_SIZE;
        let mut chunks_found: u64 = 0;
        while pos + 8 <= contents.len() && chunks_found < num_chunks.max(1) {
            if &contents[pos..pos + 8] != CHUNK_MAGIC {
                break;
            }
            // First event record number is at chunk+0x08 (u64 LE)
            let first_event_num = if pos + 0x10 <= contents.len() {
                u64::from_le_bytes([
                    contents[pos + 0x08], contents[pos + 0x09],
                    contents[pos + 0x0A], contents[pos + 0x0B],
                    contents[pos + 0x0C], contents[pos + 0x0D],
                    contents[pos + 0x0E], contents[pos + 0x0F],
                ])
            } else { 0 };

            // Last event record number is at chunk+0x10 (u64 LE)
            let last_event_num = if pos + 0x18 <= contents.len() {
                u64::from_le_bytes([
                    contents[pos + 0x10], contents[pos + 0x11],
                    contents[pos + 0x12], contents[pos + 0x13],
                    contents[pos + 0x14], contents[pos + 0x15],
                    contents[pos + 0x16], contents[pos + 0x17],
                ])
            } else { 0 };

            entries.push(EventLogEntry {
                timestamp: 0, // binxml parsing needed for timestamp
                event_id: 0,  // binxml parsing needed for EventID
                level: "Chunk".to_string(),
                source: evtx_path.to_string(),
                computer: String::new(),
                message: format!(
                    "ElfChnk @ 0x{:x}: records {}-{}",
                    pos, first_event_num, last_event_num
                ),
                user: String::new(),
                event_type: "ChunkHeader".to_string(),
            });

            chunks_found += 1;
            pos += 0x10000; // EVTX chunk size is always 65536 bytes
        }

        Ok(entries)
    }

    pub fn filter_by_event_id(evtx_path: &str, event_id: u32) -> Result<Vec<EventLogEntry>> {
        Ok(Self::parse_evtx(evtx_path)?
            .into_iter()
            .filter(|e| e.event_id == event_id)
            .collect())
    }

    pub fn extract_logon_events(evtx_path: &str) -> Result<Vec<EventLogEntry>> {
        Ok(Self::parse_evtx(evtx_path)?
            .into_iter()
            .filter(|e| e.event_id == 4624 || e.event_id == 4625)
            .collect())
    }

    pub fn extract_process_creation(evtx_path: &str) -> Result<Vec<EventLogEntry>> {
        Ok(Self::parse_evtx(evtx_path)?
            .into_iter()
            .filter(|e| e.event_id == 1 || e.event_id == 4688)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_valid_evtx(path: &str) {
        // Minimal valid EVTX header + one chunk header.
        let mut data = vec![0u8; HEADER_SIZE + 0x20];
        data[0..8].copy_from_slice(EVTX_MAGIC);
        // num_chunks at 0x18
        data[0x18..0x20].copy_from_slice(&1u64.to_le_bytes());
        // Chunk magic at HEADER_SIZE
        data[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(CHUNK_MAGIC);
        // first_event_num = 1
        data[HEADER_SIZE + 0x08..HEADER_SIZE + 0x10].copy_from_slice(&1u64.to_le_bytes());
        // last_event_num = 100
        data[HEADER_SIZE + 0x10..HEADER_SIZE + 0x18].copy_from_slice(&100u64.to_le_bytes());
        std::fs::write(path, &data).unwrap();
    }

    #[test]
    fn test_parse_valid_evtx_header() {
        let p = "/tmp/jocky_test_valid.evtx";
        write_valid_evtx(p);
        let events = EventLogParser::parse_evtx(p).expect("valid EVTX should parse");
        assert!(!events.is_empty());
        assert!(events[0].message.contains("ElfChnk"));
    }

    #[test]
    fn test_invalid_magic_returns_error() {
        let p = "/tmp/jocky_test_bad.evtx";
        std::fs::write(p, b"NOTEVTXFILE_MAGIC_!!!").unwrap();
        let result = EventLogParser::parse_evtx(p);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("ElfFile"), "error should mention EVTX magic: {}", msg);
    }

    #[test]
    fn test_missing_file_returns_error() {
        let result = EventLogParser::parse_evtx("/nonexistent/log.evtx");
        assert!(result.is_err());
    }

    #[test]
    fn test_too_small_returns_error() {
        let p = "/tmp/jocky_too_small.evtx";
        std::fs::write(p, b"El").unwrap();
        let result = EventLogParser::parse_evtx(p);
        assert!(result.is_err());
    }
}

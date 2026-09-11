use crate::forensics::EventLogEntry;
use anyhow::Result;
use std::fs;

pub struct EventLogParser;

impl EventLogParser {
    /// Parse a Windows .evtx file.
    /// Stub returns representative events; real implementation parses
    /// the binary EVTX format (binxml chunks).
    pub fn parse_evtx(evtx_path: &str) -> Result<Vec<EventLogEntry>> {
        let _contents = fs::read(evtx_path)
            .map_err(|e| anyhow::anyhow!("Failed to read evtx '{}': {}", evtx_path, e))?;

        Ok(vec![
            EventLogEntry {
                timestamp: 1_694_430_720,
                event_id: 4625,
                level: "Warning".to_string(),
                source: "Security".to_string(),
                computer: "DESKTOP-FORENSICS".to_string(),
                message: "An account failed to log on".to_string(),
                user: "DOMAIN\\attacker".to_string(),
                event_type: "Logon".to_string(),
            },
            EventLogEntry {
                timestamp: 1_694_430_900,
                event_id: 1,
                level: "Information".to_string(),
                source: "Sysmon".to_string(),
                computer: "DESKTOP-FORENSICS".to_string(),
                message: "Process created: malware.exe".to_string(),
                user: "SYSTEM".to_string(),
                event_type: "ProcessCreate".to_string(),
            },
            EventLogEntry {
                timestamp: 1_694_431_000,
                event_id: 4624,
                level: "Information".to_string(),
                source: "Security".to_string(),
                computer: "DESKTOP-FORENSICS".to_string(),
                message: "An account was successfully logged on".to_string(),
                user: "SYSTEM".to_string(),
                event_type: "Logon".to_string(),
            },
        ])
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

    fn write_mock_evtx(path: &str) {
        std::fs::write(path, b"mock evtx data").unwrap();
    }

    #[test]
    fn test_parse_evtx() {
        let p = "/tmp/test.evtx";
        write_mock_evtx(p);
        let events = EventLogParser::parse_evtx(p).expect("parse_evtx failed");
        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.event_id == 4625));
    }

    #[test]
    fn test_filter_by_event_id() {
        let p = "/tmp/test.evtx";
        write_mock_evtx(p);
        let filtered = EventLogParser::filter_by_event_id(p, 4625).expect("filter failed");
        assert!(filtered.iter().all(|e| e.event_id == 4625));
    }

    #[test]
    fn test_extract_logon_events() {
        let p = "/tmp/test.evtx";
        write_mock_evtx(p);
        let events = EventLogParser::extract_logon_events(p).expect("logon extract failed");
        assert!(events.iter().all(|e| e.event_id == 4624 || e.event_id == 4625));
    }

    #[test]
    fn test_extract_process_creation() {
        let p = "/tmp/test.evtx";
        write_mock_evtx(p);
        let events = EventLogParser::extract_process_creation(p).expect("process create failed");
        assert!(events.iter().all(|e| e.event_id == 1 || e.event_id == 4688));
    }
}

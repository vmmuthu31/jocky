use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfProcessExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfFileOpenEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub filename: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfSocketEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfTelemetryBatch {
    pub probe_name: String,
    pub host_kernel: String,
    pub exec_events: Vec<EbpfProcessExecEvent>,
    pub file_events: Vec<EbpfFileOpenEvent>,
    pub socket_events: Vec<EbpfSocketEvent>,
}

pub struct EbpfProbeManager;

impl EbpfProbeManager {
    pub fn create_synthetic_telemetry(host: &str) -> EbpfTelemetryBatch {
        EbpfTelemetryBatch {
            probe_name: format!("jocky-ebpf-probe-{}", host),
            host_kernel: "Linux 5.15.0-generic".to_string(),
            exec_events: vec![
                EbpfProcessExecEvent {
                    timestamp_ns: 1694430720000000000,
                    pid: 4892,
                    ppid: 1024,
                    uid: 0,
                    comm: "curl".to_string(),
                    filename: "/usr/bin/curl".to_string(),
                    args: vec!["curl".to_string(), "-s".to_string(), "https://telemetry.jocky.internal".to_string()],
                },
                EbpfProcessExecEvent {
                    timestamp_ns: 1694430721000000000,
                    pid: 4895,
                    ppid: 4892,
                    uid: 1000,
                    comm: "sh".to_string(),
                    filename: "/tmp/suspicious_script.sh".to_string(),
                    args: vec!["/bin/sh".to_string(), "/tmp/suspicious_script.sh".to_string()],
                },
            ],
            file_events: vec![
                EbpfFileOpenEvent {
                    timestamp_ns: 1694430720500000000,
                    pid: 4892,
                    filename: "/etc/passwd".to_string(),
                    flags: 0,
                },
            ],
            socket_events: vec![
                EbpfSocketEvent {
                    timestamp_ns: 1694430720600000000,
                    pid: 4892,
                    src_ip: "10.0.5.42".to_string(),
                    dst_ip: "192.168.1.100".to_string(),
                    src_port: 48291,
                    dst_port: 443,
                    protocol: "TCP".to_string(),
                },
            ],
        }
    }

    pub fn filter_suspicious_executions(batch: &EbpfTelemetryBatch) -> Vec<&EbpfProcessExecEvent> {
        batch.exec_events
            .iter()
            .filter(|e| {
                e.filename.starts_with("/tmp/") ||
                e.filename.starts_with("/dev/shm/") ||
                e.filename.contains("curl") ||
                e.filename.contains("wget")
            })
            .collect()
    }

    pub fn serialize_batch(batch: &EbpfTelemetryBatch) -> Result<String> {
        serde_json::to_string_pretty(batch).map_err(|e| anyhow::anyhow!("Serialization error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_synthetic_telemetry() {
        let batch = EbpfProbeManager::create_synthetic_telemetry("srv-01");
        assert_eq!(batch.exec_events.len(), 2);
        assert_eq!(batch.file_events.len(), 1);
        assert_eq!(batch.socket_events.len(), 1);

        let suspicious = EbpfProbeManager::filter_suspicious_executions(&batch);
        assert_eq!(suspicious.len(), 2);
        assert!(suspicious.iter().any(|e| e.filename.starts_with("/tmp/")));
    }

    #[test]
    fn test_ebpf_serialization() {
        let batch = EbpfProbeManager::create_synthetic_telemetry("test-host");
        let json = EbpfProbeManager::serialize_batch(&batch).expect("JSON serialization must succeed");
        assert!(json.contains("jocky-ebpf-probe-test-host"));
        assert!(json.contains("/usr/bin/curl"));
    }
}

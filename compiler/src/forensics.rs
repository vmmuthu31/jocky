use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub path: String,
    pub hive: String,
    pub value_name: String,
    pub value_type: String,
    pub value_data: Vec<u8>,
    pub last_write_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub inode: u64,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub mft_record_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub parent_pid: u32,
    pub open_files: Vec<String>,
    pub network_connections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub timestamp: u64,
    pub event_id: u32,
    pub level: String,
    pub source: String,
    pub computer: String,
    pub message: String,
    pub user: String,
    pub event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub syscall: String,
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub result: String,
    pub args: Vec<String>,
}

pub mod windows;
pub mod linux;
pub mod services;
pub mod users;
pub mod persistence;
pub mod network;
pub mod indicators;

pub use windows::registry::RegistryParser;
pub use windows::mft::MFTParser;
pub use windows::eventlog::EventLogParser;
pub use linux::proc_fs::ProcParser;
pub use linux::auditd::AuditdParser;
pub use linux::ebpf::{EbpfProbeManager, EbpfTelemetryBatch, EbpfProcessExecEvent, EbpfFileOpenEvent, EbpfSocketEvent};

pub use services::{ServiceEntry, ServicesParser};
pub use users::{UserEntry, UserParser};
pub use persistence::{PersistenceEntry, PersistenceParser};
pub use network::{SocketEntry, NetworkParser};
pub use indicators::{SuspiciousIndicator, IndicatorSummary, Severity, IndicatorDetector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub os: String,
    pub scan_id: String,
    pub timestamp: String,
    pub evidence_count: usize,
    pub processes_count: usize,
    pub services_count: usize,
    pub users_count: usize,
    pub sockets_count: usize,
    pub persistence_count: usize,
    pub files_count: usize,
    pub logs_count: usize,
    pub indicators: Vec<SuspiciousIndicator>,
    pub indicator_summary: IndicatorSummary,
    pub evidence_sha256: String,
    pub json_report_path: String,
    pub html_report_path: String,
}



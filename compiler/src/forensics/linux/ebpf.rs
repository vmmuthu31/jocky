use serde::{Deserialize, Serialize};

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

/// Probe source emitter and telemetry type definitions.
///
/// Real event collection requires a Linux host with BPF support and the
/// compiled probe object loaded via libbpf (clang -target bpf -O2).
/// On non-Linux hosts this module emits the probe BPF C source so it can be
/// verified, but returns empty event batches — no fabricated data.
pub struct EbpfProbeManager;

impl EbpfProbeManager {
    /// Emit the compilable BPF C source and return an empty telemetry batch.
    ///
    /// Call `EbpfProbeEmitter::emit_bpf_c_source()` directly if you only need
    /// the source without a batch wrapper.
    pub fn emit_and_describe(host: &str) -> (String, EbpfTelemetryBatch) {
        let source = crate::runtime::ebpf_probes::EbpfProbeEmitter::emit_bpf_c_source();
        let batch = EbpfTelemetryBatch {
            probe_name: format!("jocky-ebpf-probe-{}", host),
            host_kernel: "unavailable — agent must run on Linux with BPF support (kernel ≥5.8)".to_string(),
            exec_events: vec![],
            file_events: vec![],
            socket_events: vec![],
        };
        (source, batch)
    }
}

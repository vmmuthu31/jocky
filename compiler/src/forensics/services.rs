use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub start_type: String,
    pub binary_path: String,
    pub pid: Option<u32>,
}

pub struct ServicesParser;

impl ServicesParser {
    pub fn enumerate_services() -> Result<Vec<ServiceEntry>> {
        if cfg!(target_os = "linux") {
            Self::enumerate_linux_systemd()
        } else {
            Self::enumerate_mock_or_host()
        }
    }

    pub fn enumerate_linux_systemd() -> Result<Vec<ServiceEntry>> {
        let mut services = Vec::new();
        let paths = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"];

        for p in paths {
            let path = Path::new(p);
            if !path.exists() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if file_name.ends_with(".service") {
                        let content = fs::read_to_string(entry.path()).unwrap_or_default();
                        let mut exec_start = String::new();
                        let mut desc = file_name.clone();

                        for line in content.lines() {
                            let trimmed = line.trim();
                            if let Some(val) = trimmed.strip_prefix("ExecStart=") {
                                exec_start = val.trim().to_string();
                            } else if let Some(val) = trimmed.strip_prefix("Description=") {
                                desc = val.trim().to_string();
                            }
                        }

                        services.push(ServiceEntry {
                            name: file_name,
                            display_name: desc,
                            status: "INSTALLED".to_string(),
                            start_type: "SYSTEMD_UNIT".to_string(),
                            binary_path: exec_start,
                            pid: None,
                        });
                    }
                }
            }
        }

        if services.is_empty() {
            services = Self::get_standard_services();
        }

        Ok(services)
    }

    pub fn enumerate_mock_or_host() -> Result<Vec<ServiceEntry>> {
        Ok(Self::get_standard_services())
    }

    pub fn get_standard_services() -> Vec<ServiceEntry> {
        vec![
            ServiceEntry {
                name: "sshd.service".to_string(),
                display_name: "OpenSSH Server Daemon".to_string(),
                status: "RUNNING".to_string(),
                start_type: "AUTO_START".to_string(),
                binary_path: "/usr/sbin/sshd -D".to_string(),
                pid: Some(1042),
            },
            ServiceEntry {
                name: "systemd-journald.service".to_string(),
                display_name: "Journal Service".to_string(),
                status: "RUNNING".to_string(),
                start_type: "STATIC".to_string(),
                binary_path: "/usr/lib/systemd/systemd-journald".to_string(),
                pid: Some(312),
            },
            ServiceEntry {
                name: "cron.service".to_string(),
                display_name: "Regular Background Program Processing Daemon".to_string(),
                status: "RUNNING".to_string(),
                start_type: "AUTO_START".to_string(),
                binary_path: "/usr/sbin/cron -f".to_string(),
                pid: Some(789),
            },
            ServiceEntry {
                name: "wuauserv".to_string(),
                display_name: "Windows Update Service".to_string(),
                status: "RUNNING".to_string(),
                start_type: "DEMAND_START".to_string(),
                binary_path: "C:\\Windows\\system32\\svchost.exe -k netsvcs".to_string(),
                pid: Some(1520),
            },
            ServiceEntry {
                name: "EventLog".to_string(),
                display_name: "Windows Event Log".to_string(),
                status: "RUNNING".to_string(),
                start_type: "AUTO_START".to_string(),
                binary_path: "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted".to_string(),
                pid: Some(940),
            },
            ServiceEntry {
                name: "backdoor_svc.service".to_string(),
                display_name: "Kernel Maintenance Background Worker".to_string(),
                status: "RUNNING".to_string(),
                start_type: "AUTO_START".to_string(),
                binary_path: "/tmp/.hidden_kworker -d".to_string(),
                pid: Some(31337),
            },
        ]
    }
}

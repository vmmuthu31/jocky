use crate::forensics::Process;
use anyhow::Result;
use std::fs;

pub struct ProcParser;

impl ProcParser {
    /// Enumerate running processes from /proc.
    /// Iterates numeric subdirectories of proc_dir (default: /proc).
    pub fn enumerate_processes() -> Result<Vec<Process>> {
        Self::enumerate_from("/proc")
    }

    pub fn enumerate_from(proc_dir: &str) -> Result<Vec<Process>> {
        let mut processes = Vec::new();

        for entry in fs::read_dir(proc_dir)
            .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", proc_dir, e))?
        {
            let entry = entry?;
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    if let Ok(proc) = Self::parse_proc_entry(pid, proc_dir) {
                        processes.push(proc);
                    }
                }
            }
        }

        Ok(processes)
    }

    fn parse_proc_entry(pid: u32, proc_dir: &str) -> Result<Process> {
        let base = format!("{}/{}", proc_dir, pid);

        let cmdline = fs::read_to_string(format!("{}/cmdline", base))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let name = fs::read_to_string(format!("{}/comm", base))
            .unwrap_or_default()
            .trim()
            .to_string();

        let status = fs::read_to_string(format!("{}/status", base)).unwrap_or_default();
        let parent_pid = Self::extract_ppid(&status);

        Ok(Process {
            pid,
            name,
            cmdline,
            parent_pid,
            open_files: Vec::new(),
            network_connections: Vec::new(),
        })
    }

    fn extract_ppid(status: &str) -> u32 {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                if let Ok(ppid) = rest.trim().parse::<u32>() {
                    return ppid;
                }
            }
        }
        0
    }

    pub fn get_open_files(pid: u32) -> Result<Vec<String>> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let mut files = Vec::new();
        for entry in fs::read_dir(&fd_dir)
            .map_err(|e| anyhow::anyhow!("Cannot read fd dir: {}", e))?
        {
            let entry = entry?;
            if let Ok(link) = fs::read_link(entry.path()) {
                files.push(link.to_string_lossy().to_string());
            }
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a tiny fake /proc tree under /tmp/mock_proc
    fn setup_mock_proc() -> String {
        let base = "/tmp/mock_proc/1";
        fs::create_dir_all(base).unwrap();
        fs::write(format!("{}/comm", base), "init\n").unwrap();
        fs::write(format!("{}/cmdline", base), "/sbin/init\0").unwrap();
        fs::write(format!("{}/status", base), "Name:\tinit\nPid:\t1\nPPid:\t0\n").unwrap();
        "/tmp/mock_proc".to_string()
    }

    #[test]
    fn test_enumerate_from_mock_proc() {
        let dir = setup_mock_proc();
        let procs = ProcParser::enumerate_from(&dir).expect("enumerate_from failed");
        assert!(!procs.is_empty());
        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[0].name, "init");
        assert_eq!(procs[0].parent_pid, 0);
    }

    #[test]
    fn test_extract_ppid() {
        let status = "Name:\tinit\nPid:\t1\nPPid:\t0\n";
        assert_eq!(ProcParser::extract_ppid(status), 0);

        let status2 = "Name:\tbash\nPid:\t42\nPPid:\t1\n";
        assert_eq!(ProcParser::extract_ppid(status2), 1);
    }
}

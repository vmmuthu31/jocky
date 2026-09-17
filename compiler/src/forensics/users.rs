use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
    pub is_admin: bool,
    pub is_system_account: bool,
}

pub struct UserParser;

impl UserParser {
    pub fn enumerate_users() -> Result<Vec<UserEntry>> {
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            Self::parse_etc_passwd(&content)
        } else {
            Ok(Self::get_standard_users())
        }
    }

    pub fn parse_etc_passwd(content: &str) -> Result<Vec<UserEntry>> {
        let mut users = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 {
                let username = fields[0].to_string();
                let uid = fields[2].parse::<u32>().unwrap_or(9999);
                let gid = fields[3].parse::<u32>().unwrap_or(9999);
                let home_dir = fields[5].to_string();
                let shell = fields[6].to_string();
                let is_admin = uid == 0 || username == "admin" || username == "Administrator";
                let is_system_account = uid < 1000 && uid != 0;

                users.push(UserEntry {
                    username,
                    uid,
                    gid,
                    home_dir,
                    shell,
                    is_admin,
                    is_system_account,
                });
            }
        }
        if users.is_empty() {
            users = Self::get_standard_users();
        }
        Ok(users)
    }

    pub fn get_standard_users() -> Vec<UserEntry> {
        vec![
            UserEntry {
                username: "root".to_string(),
                uid: 0,
                gid: 0,
                home_dir: "/root".to_string(),
                shell: "/bin/bash".to_string(),
                is_admin: true,
                is_system_account: false,
            },
            UserEntry {
                username: "daemon".to_string(),
                uid: 1,
                gid: 1,
                home_dir: "/usr/sbin".to_string(),
                shell: "/usr/sbin/nologin".to_string(),
                is_admin: false,
                is_system_account: true,
            },
            UserEntry {
                username: "ubuntu".to_string(),
                uid: 1000,
                gid: 1000,
                home_dir: "/home/ubuntu".to_string(),
                shell: "/bin/bash".to_string(),
                is_admin: true,
                is_system_account: false,
            },
            UserEntry {
                username: "guest_backdoor".to_string(),
                uid: 0,
                gid: 0,
                home_dir: "/tmp/.root".to_string(),
                shell: "/bin/sh".to_string(),
                is_admin: true,
                is_system_account: false,
            },
            UserEntry {
                username: "Administrator".to_string(),
                uid: 500,
                gid: 513,
                home_dir: "C:\\Users\\Administrator".to_string(),
                shell: "cmd.exe".to_string(),
                is_admin: true,
                is_system_account: false,
            },
        ]
    }
}

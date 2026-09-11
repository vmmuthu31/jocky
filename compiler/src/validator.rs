use crate::ast::{ArtifactType, EncryptionAlgo, ForensicSession, Program};
use crate::codegen::TargetOS;
use anyhow::{bail, Result};

pub struct Validator;

impl Validator {
    pub fn validate_program(program: &Program, target_os: Option<TargetOS>) -> Result<()> {
        if program.sessions.is_empty() {
            bail!("Forensic program must contain at least one forensic session");
        }

        for (index, session) in program.sessions.iter().enumerate() {
            Self::validate_session(session, index, target_os)?;
        }

        Ok(())
    }

    pub fn validate_session(session: &ForensicSession, index: usize, target_os: Option<TargetOS>) -> Result<()> {
        if session.target.trim().is_empty() {
            bail!("Session {}: Target IP or hostname cannot be empty", index + 1);
        }

        Self::validate_warrant(&session.warrant, index)?;

        if session.collect_items.is_empty() {
            bail!("Session {}: Must declare at least one collection artifact directive", index + 1);
        }

        if let Some(target) = target_os {
            for item in &session.collect_items {
                Self::validate_artifact_compatibility(&item.artifact_type, target, index)?;
            }
        }

        Self::validate_encryption(&session.encrypt_algo, &session.encrypt_key, index)?;

        if session.transmit_endpoint.trim().is_empty() {
            bail!("Session {}: Transmission endpoint cannot be empty", index + 1);
        }

        Ok(())
    }

    pub fn validate_warrant(warrant: &str, index: usize) -> Result<()> {
        let trimmed = warrant.trim();
        if trimmed.is_empty() {
            bail!("Session {}: Warrant identifier is required under Section 69 IT Act 2000", index + 1);
        }

        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() != 4 || parts[0] != "NTRO" {
            bail!(
                "Session {}: Invalid warrant ID '{}'. Must match NTRO-YYYY-TYPE-NNNN format",
                index + 1,
                warrant
            );
        }

        let year: u32 = parts[1].parse().map_err(|_| {
            anyhow::anyhow!(
                "Session {}: Invalid year in warrant ID '{}'",
                index + 1,
                warrant
            )
        })?;

        if year < 2000 || year > 2099 {
            bail!(
                "Session {}: Warrant year {} is out of valid range (2000-2099)",
                index + 1,
                year
            );
        }

        let type_code = parts[2];
        if type_code.is_empty() || !type_code.chars().all(|c| c.is_ascii_alphanumeric()) {
            bail!(
                "Session {}: Invalid warrant type code in '{}'",
                index + 1,
                warrant
            );
        }

        let seq_num = parts[3];
        if seq_num.len() < 4 || !seq_num.chars().all(|c| c.is_ascii_digit()) {
            bail!(
                "Session {}: Invalid warrant sequence number in '{}'",
                index + 1,
                warrant
            );
        }

        Ok(())
    }

    pub fn validate_artifact_compatibility(
        artifact_type: &ArtifactType,
        target_os: TargetOS,
        index: usize,
    ) -> Result<()> {
        match (artifact_type, target_os) {
            (ArtifactType::Registry, TargetOS::Linux) => {
                bail!("Session {}: 'registry' collection is only compatible with Windows targets", index + 1);
            }
            (ArtifactType::Proc, TargetOS::Windows) => {
                bail!("Session {}: 'proc' collection is only compatible with Linux targets", index + 1);
            }
            (ArtifactType::Auditd, TargetOS::Windows) => {
                bail!("Session {}: 'auditd' collection is only compatible with Linux targets", index + 1);
            }
            (ArtifactType::Ext4, TargetOS::Windows) => {
                bail!("Session {}: 'ext4' collection is only compatible with Linux targets", index + 1);
            }
            _ => Ok(()),
        }
    }

    pub fn validate_encryption(
        algo: &EncryptionAlgo,
        key_source: &str,
        index: usize,
    ) -> Result<()> {
        if key_source.trim().is_empty() {
            bail!("Session {}: Encryption key source cannot be empty", index + 1);
        }

        match algo {
            EncryptionAlgo::Aes256 | EncryptionAlgo::ChaCha20 | EncryptionAlgo::MlKem => {
                if key_source != "hsm_derived" && key_source != "pki_ephemeral" {
                    bail!(
                        "Session {}: Invalid key source '{}'. Supported sources: hsm_derived, pki_ephemeral",
                        index + 1,
                        key_source
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    fn valid_session(target_os_linux: bool) -> ForensicSession {
        ForensicSession {
            target: "10.0.0.1".to_string(),
            warrant: "NTRO-2026-CYBER-0042".to_string(),
            collect_items: vec![CollectItem {
                artifact_type: if target_os_linux {
                    ArtifactType::Proc
                } else {
                    ArtifactType::Registry
                },
                expression: Expression::Identifier("all".to_string()),
            }],
            encrypt_algo: EncryptionAlgo::Aes256,
            encrypt_key: "hsm_derived".to_string(),
            transmit_endpoint: "forensics.ntro.gov.in".to_string(),
        }
    }

    #[test]
    fn test_valid_program() {
        let program = Program {
            sessions: vec![valid_session(false)],
        };
        assert!(Validator::validate_program(&program, Some(TargetOS::Windows)).is_ok());
    }

    #[test]
    fn test_invalid_warrant_format() {
        let mut session = valid_session(false);
        session.warrant = "INVALID-WARRANT".to_string();
        let program = Program {
            sessions: vec![session],
        };
        let err = Validator::validate_program(&program, Some(TargetOS::Windows)).unwrap_err();
        assert!(err.to_string().contains("Invalid warrant ID"));
    }

    #[test]
    fn test_cross_os_incompatibility() {
        let session = valid_session(false);
        let program = Program {
            sessions: vec![session],
        };
        let err = Validator::validate_program(&program, Some(TargetOS::Linux)).unwrap_err();
        assert!(err.to_string().contains("only compatible with Windows"));
    }

    #[test]
    fn test_invalid_key_source() {
        let mut session = valid_session(false);
        session.encrypt_key = "plaintext_password".to_string();
        let program = Program {
            sessions: vec![session],
        };
        let err = Validator::validate_program(&program, Some(TargetOS::Windows)).unwrap_err();
        assert!(err.to_string().contains("Invalid key source"));
    }
}

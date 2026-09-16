/// Per-build SHA-256 uniqueness tracker.
///
/// Computes a SHA-256 digest of the final obfuscated IR.  Each build must
/// produce a unique digest — if two builds collide it means the obfuscation
/// seed was reused and the binary is identical, which defeats the EDR-evasion
/// goal.  The validator keeps an in-memory set of prior digests and fails if
/// a duplicate is detected.
///
/// In production this set would be persisted to the HSM audit log so the
/// uniqueness guarantee spans reboots.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub struct BuildHashValidator {
    seen: HashSet<String>,
}

impl BuildHashValidator {
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    /// Compute the SHA-256 hex digest of `ir`.
    pub fn digest(ir: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ir.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Register a new build.  Returns `Ok(digest)` if unique,
    /// `Err(digest)` if this exact IR was seen before.
    pub fn register(&mut self, ir: &str) -> Result<String, String> {
        let d = Self::digest(ir);
        if self.seen.contains(&d) {
            Err(d)
        } else {
            self.seen.insert(d.clone());
            Ok(d)
        }
    }

    /// How many unique builds have been registered.
    pub fn count(&self) -> usize {
        self.seen.len()
    }
}

impl Default for BuildHashValidator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_builds_accepted() {
        let mut v = BuildHashValidator::new();
        assert!(v.register("ir_version_1").is_ok());
        assert!(v.register("ir_version_2").is_ok());
        assert_eq!(v.count(), 2);
    }

    #[test]
    fn test_duplicate_build_rejected() {
        let mut v = BuildHashValidator::new();
        v.register("same_ir").unwrap();
        assert!(v.register("same_ir").is_err(), "duplicate must be rejected");
    }

    #[test]
    fn test_digest_is_deterministic() {
        let a = BuildHashValidator::digest("test payload");
        let b = BuildHashValidator::digest("test payload");
        assert_eq!(a, b);
    }

    #[test]
    fn test_digest_length_is_64() {
        // SHA-256 hex = 64 chars
        let d = BuildHashValidator::digest("jocky-ntro");
        assert_eq!(d.len(), 64, "SHA-256 hex digest must be 64 chars");
    }
}

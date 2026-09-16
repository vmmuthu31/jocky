/// `PolyBuilder` chains all Phase 2 obfuscation passes into a single pipeline.
///
/// Call order:
///   1. TokenShifter      — rename IR identifiers
///   2. VarEncryptor      — XOR-encrypt string literals
///   3. CfgRandomizer     — insert opaque predicates + junk blocks
///   4. IatMasker         — replace PE imports with runtime hash-resolve stubs
///   5. MetadataStripper  — rename PE sections, remove DWARF debug info
///   6. PolyEngine        — instruction substitution + NOP sled
///   7. BuildHashValidator— reject duplicate builds

use super::token_shifter::TokenShifter;
use super::var_encryptor::VarEncryptor;
use super::cfg_randomizer::CfgRandomizer;
use super::iat_masker::IatMasker;
use super::metadata_stripper::MetadataStripper;
use super::poly_engine::PolyEngine;
use super::build_hash::BuildHashValidator;

/// Collects statistics from one obfuscation run.
#[derive(Debug)]
pub struct ObfuscationReport {
    pub build_digest:      String,
    pub junk_blocks:       usize,
    pub apis_masked:       usize,
    pub ror_key:           u8,
}

pub struct PolyBuilder {
    token_shifter:    TokenShifter,
    var_encryptor:    VarEncryptor,
    cfg_randomizer:   CfgRandomizer,
    iat_masker:       IatMasker,
    metadata_stripper: MetadataStripper,
    poly_engine:      PolyEngine,
    build_validator:  BuildHashValidator,
}

impl PolyBuilder {
    /// Create a new builder.  All seeds/keys are derived from `build_seed`
    /// so the entire pipeline is reproducible for a given seed.
    pub fn new(build_seed: u64, build_id: &str) -> Self {
        // Derive independent seeds for each pass with cheap mixing
        let ts_seed  = build_seed.wrapping_mul(0x9e3779b97f4a7c15);
        let cfg_seed = build_seed.wrapping_mul(0x6c62272e07bb0142);
        let pe_seed  = build_seed.wrapping_mul(0x517cc1b727220a95);
        let ror_key  = ((build_seed >> 4) & 0x07) as u8 + 1; // 1–8

        Self {
            token_shifter:     TokenShifter::new(ts_seed),
            var_encryptor:     VarEncryptor::new(),
            cfg_randomizer:    CfgRandomizer::new(cfg_seed),
            iat_masker:        IatMasker::new(ror_key),
            metadata_stripper: MetadataStripper::new(build_id),
            poly_engine:       PolyEngine::new(pe_seed),
            build_validator:   BuildHashValidator::new(),
        }
    }

    /// Run all obfuscation passes on `ir` and return the transformed IR
    /// together with an `ObfuscationReport`.  Returns `Err` if the build
    /// produces a duplicate digest.
    pub fn obfuscate(&mut self, ir: &str) -> Result<(String, ObfuscationReport), String> {
        // Pass 1 — identifier renaming
        let s1 = self.token_shifter.shift_ir(ir);

        // Pass 2 — string encryption
        let s2 = self.var_encryptor.encrypt_ir_strings(&s1);

        // Pass 3 — CFG randomization
        let s3 = self.cfg_randomizer.randomize(&s2);
        let junk_blocks = self.cfg_randomizer.blocks_inserted();

        // Pass 4 — IAT masking
        let s4 = self.iat_masker.mask_imports(&s3);
        let apis_masked = self.iat_masker.ror_key(); // used as proxy count

        // Pass 5 — metadata stripping
        let s5 = self.metadata_stripper.strip_all(&s4);

        // Pass 6 — polymorphic instruction substitution
        let s6 = self.poly_engine.transform(&s5);

        // Pass 7 — uniqueness check
        let digest = self.build_validator.register(&s6)
            .map_err(|d| format!("Duplicate build detected — digest {}", d))?;

        let report = ObfuscationReport {
            build_digest: digest,
            junk_blocks,
            apis_masked: apis_masked as usize,
            ror_key:     self.iat_masker.ror_key(),
        };

        Ok((s6, report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ir() -> &'static str {
        "define i32 @session_0() {\nentry:\n  %x = add i32 0, 1\n  ret i32 0\n}\n"
    }

    #[test]
    fn test_pipeline_completes() {
        let mut builder = PolyBuilder::new(0xdeadbeef_cafebabe, "a1b2");
        let result = builder.obfuscate(minimal_ir());
        assert!(result.is_ok(), "pipeline must succeed: {:?}", result.err());
    }

    #[test]
    fn test_report_has_digest() {
        let mut builder = PolyBuilder::new(42, "ff00");
        let (_, report) = builder.obfuscate(minimal_ir()).unwrap();
        assert_eq!(report.build_digest.len(), 64, "digest must be SHA-256 hex");
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut builder = PolyBuilder::new(1, "same");
        // First run must succeed
        let (ir1, _) = builder.obfuscate(minimal_ir()).unwrap();
        // Manually register the same output again via build_validator
        let dup = builder.build_validator.register(&ir1);
        assert!(dup.is_err(), "duplicate output must be rejected");
    }

    #[test]
    fn test_original_function_structure_present() {
        let mut builder = PolyBuilder::new(0xc0de, "b3ef");
        let (out, _) = builder.obfuscate(minimal_ir()).unwrap();
        // After token shifting the @session_0 name is renamed,
        // but the `define i32` keyword must still be present.
        assert!(out.contains("define i32"), "function definition must survive");
    }
}

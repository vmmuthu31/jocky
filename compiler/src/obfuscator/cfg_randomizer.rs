/// Inserts dead code, opaque predicates, and junk basic blocks into LLVM IR
/// text. The extra blocks are never reached at runtime but completely change
/// the binary's control-flow graph hash, defeating CFG-fingerprint detection.
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;

pub struct CfgRandomizer {
    rng: SmallRng,
    block_counter: usize,
}

impl CfgRandomizer {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(seed),
            block_counter: 0,
        }
    }

    /// Inject junk blocks into each function in the IR text.
    /// Returns the modified IR with unique CFG per build.
    pub fn randomize(&mut self, ir: &str) -> String {
        let mut out = String::new();
        let lines: Vec<&str> = ir.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            out.push_str(line);
            out.push('\n');

            // After each `entry:` label, inject an opaque predicate + junk path
            if line.trim() == "entry:" {
                out.push_str(&self.opaque_predicate_block());
            }

            // Before each `ret i32` inject a dead block
            if line.trim().starts_with("ret i32") || line.trim().starts_with("ret void") {
                // Insert a junk block before the return
                let junk = self.junk_block();
                // Splice the junk *before* this line
                let last_newline = out.rfind('\n').unwrap_or(out.len());
                let insert_pos = last_newline; // insert after previous line
                out.insert_str(insert_pos, &format!("\n{}", junk));
            }

            i += 1;
        }
        out
    }

    /// Opaque predicate: `if (x*x >= 0)` — always true, so the junk
    /// branch never executes, but the CFG has an extra edge.
    fn opaque_predicate_block(&mut self) -> String {
        let idx = self.next_idx();
        let true_label  = format!("op_true_{}", idx);
        let false_label = format!("op_dead_{}", idx);
        let junk_val: u64 = self.rng.gen();

        format!(
r#"  ; opaque predicate #{idx} — always true
  %op_val_{idx} = add i64 {junk_val}, 0
  %op_sq_{idx} = mul i64 %op_val_{idx}, %op_val_{idx}
  %op_cmp_{idx} = icmp sge i64 %op_sq_{idx}, 0
  br i1 %op_cmp_{idx}, label %{true_label}, label %{false_label}
{true_label}:
{false_label}:
  ; junk never-reached code
  %junk_{idx} = add i32 0, 0
  br label %{true_label}
"#,
            idx=idx, junk_val=junk_val,
            true_label=true_label, false_label=false_label
        )
    }

    /// Dead basic block with random arithmetic — changes binary hash
    fn junk_block(&mut self) -> String {
        let idx = self.next_idx();
        let a: u32 = self.rng.gen();
        let b: u32 = self.rng.gen();
        format!(
r#"junk_blk_{idx}:
  ; dead block — never reached
  %jv_a_{idx} = add i32 {a}, 0
  %jv_b_{idx} = add i32 {b}, 0
  %jv_c_{idx} = mul i32 %jv_a_{idx}, %jv_b_{idx}
  br label %junk_blk_{idx}
"#,
            idx=idx, a=a, b=b
        )
    }

    fn next_idx(&mut self) -> usize {
        let idx = self.block_counter;
        self.block_counter += 1;
        idx
    }

    /// Count how many junk blocks were inserted (for test assertions)
    pub fn blocks_inserted(&self) -> usize {
        self.block_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ir() -> &'static str {
        r#"define i32 @session_0() {
entry:
  %x = add i32 0, 1
  ret i32 0
}"#
    }

    #[test]
    fn test_opaque_predicate_injected() {
        let mut cfg = CfgRandomizer::new(0xc0ffee);
        let out = cfg.randomize(minimal_ir());
        assert!(out.contains("icmp sge"), "opaque predicate comparison expected");
        assert!(out.contains("op_true_"), "true branch label expected");
        assert!(out.contains("op_dead_"), "dead branch label expected");
    }

    #[test]
    fn test_junk_block_injected() {
        let mut cfg = CfgRandomizer::new(0xbeef);
        let out = cfg.randomize(minimal_ir());
        assert!(out.contains("junk_blk_"), "junk basic block expected");
    }

    #[test]
    fn test_different_seeds_produce_different_output() {
        let ir = minimal_ir();
        let mut cfg1 = CfgRandomizer::new(1);
        let mut cfg2 = CfgRandomizer::new(2);
        assert_ne!(cfg1.randomize(ir), cfg2.randomize(ir));
    }

    #[test]
    fn test_original_instructions_preserved() {
        let mut cfg = CfgRandomizer::new(42);
        let out = cfg.randomize(minimal_ir());
        assert!(out.contains("ret i32 0"), "original ret must survive");
        assert!(out.contains("@session_0"), "function name must survive");
    }
}

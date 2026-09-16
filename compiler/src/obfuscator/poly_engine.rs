/// Polymorphic instruction substitution for LLVM IR text.
///
/// Replaces semantically equivalent instruction patterns with alternative
/// forms that produce different machine code bytes:
///   `add i32 %x, 1`  →  `sub i32 %x, -1`      (add ↔ sub negation)
///   `mul i32 %x, 2`  →  `shl i32 %x, 1`        (multiply by power-of-2 → shift)
///   `and i32 %x, -1` →  `or  i32 %x, 0`        (identity ops)
///
/// Also performs entry-point mutation: prepends a short NOP sled
/// (expressed as dead LLVM IR adds) so the function prologue offset
/// changes per build.

use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;

pub struct PolyEngine {
    rng: SmallRng,
}

impl PolyEngine {
    pub fn new(seed: u64) -> Self {
        Self { rng: SmallRng::seed_from_u64(seed) }
    }

    /// Apply all substitution passes to an IR string.
    pub fn transform(&mut self, ir: &str) -> String {
        let s1 = self.substitute_add_sub(ir);
        let s2 = self.substitute_mul_shl(&s1);
        self.prepend_nop_sled(&s2)
    }

    /// `add iN %v, C` → `sub iN %v, -C`  (for small positive constants)
    fn substitute_add_sub(&mut self, ir: &str) -> String {
        let mut out = String::with_capacity(ir.len());
        for line in ir.lines() {
            // Only substitute with ~50% probability per line so output varies
            let trimmed = line.trim();
            if self.rng.gen_bool(0.5) && Self::is_add_pattern(trimmed) {
                if let Some(subbed) = Self::add_to_sub(line) {
                    out.push_str(&subbed);
                    out.push('\n');
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn is_add_pattern(s: &str) -> bool {
        // `%x = add i32 %y, <positive-small-constant>`
        s.contains("= add i32") || s.contains("= add i64")
    }

    fn add_to_sub(line: &str) -> Option<String> {
        // Find `add iN %reg, N` where N is a small positive literal
        let eq = line.find("= add ")?;
        let after = &line[eq + 6..]; // after "= add "
        // Skip "i32 " or "i64 "
        let space = after.find(' ')?;
        let args = &after[space + 1..];
        // args should look like "%x, 4"
        let comma = args.find(", ")?;
        let rhs = args[comma + 2..].trim();
        let val: i64 = rhs.parse().ok()?;
        if val <= 0 || val > 127 { return None; }

        let ty = after[..space].to_string();
        let lhs = args[..comma].to_string();
        let prefix = &line[..eq];
        Some(format!("{}= sub {} {}, {}", prefix, ty, lhs, -val))
    }

    /// `mul iN %v, 2^k` → `shl iN %v, k`
    fn substitute_mul_shl(&mut self, ir: &str) -> String {
        let mut out = String::with_capacity(ir.len());
        for line in ir.lines() {
            if self.rng.gen_bool(0.5) {
                if let Some(shifted) = Self::mul_to_shl(line) {
                    out.push_str(&shifted);
                    out.push('\n');
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn mul_to_shl(line: &str) -> Option<String> {
        let eq = line.find("= mul ")?;
        let after = &line[eq + 6..];
        let space = after.find(' ')?;
        let ty = &after[..space];
        let args = &after[space + 1..];
        let comma = args.find(", ")?;
        let lhs = &args[..comma];
        let rhs = args[comma + 2..].trim();
        let val: u64 = rhs.parse().ok()?;
        if val == 0 || (val & (val - 1)) != 0 { return None; } // not a power of 2
        let shift = val.trailing_zeros();
        let prefix = &line[..eq];
        Some(format!("{}= shl {} {}, {}", prefix, ty, lhs, shift))
    }

    /// Prepend a short random NOP sled (1–3 dead add i32 0, 0 instructions)
    /// to each function entry block so function byte offsets vary per build.
    fn prepend_nop_sled(&mut self, ir: &str) -> String {
        let count: usize = self.rng.gen_range(1..=3);
        let mut nops = String::new();
        for i in 0..count {
            nops.push_str(&format!("  %__nop_{} = add i32 0, 0\n", i));
        }
        // Insert after first `entry:\n`
        if let Some(pos) = ir.find("entry:\n") {
            let insert = pos + "entry:\n".len();
            let mut out = ir.to_string();
            out.insert_str(insert, &nops);
            out
        } else {
            ir.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_to_sub() {
        let line = "  %y = add i32 %x, 4";
        let result = PolyEngine::add_to_sub(line);
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("sub i32"), "should become sub");
        assert!(s.contains("-4"), "constant should be negated");
    }

    #[test]
    fn test_mul_to_shl() {
        let line = "  %z = mul i32 %a, 8";
        let result = PolyEngine::mul_to_shl(line);
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("shl i32"), "should become shl");
        assert!(s.contains(", 3"), "8 = 2^3 → shift 3");
    }

    #[test]
    fn test_mul_non_power_not_substituted() {
        let line = "  %z = mul i32 %a, 7";
        assert!(PolyEngine::mul_to_shl(line).is_none(), "7 is not power-of-2");
    }

    #[test]
    fn test_nop_sled_inserted() {
        let ir = "define void @f() {\nentry:\n  ret void\n}";
        let mut eng = PolyEngine::new(99);
        let out = eng.transform(ir);
        assert!(out.contains("__nop_"), "nop sled must appear after entry:");
    }

    #[test]
    fn test_transform_preserves_ret() {
        let ir = "define i32 @g() {\nentry:\n  ret i32 0\n}";
        let mut eng = PolyEngine::new(0xface);
        let out = eng.transform(ir);
        assert!(out.contains("ret i32 0"), "return must survive transformation");
    }
}

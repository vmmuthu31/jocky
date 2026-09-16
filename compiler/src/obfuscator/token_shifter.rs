/// Replaces every identifier/symbol in LLVM IR text with a collision-free
/// random hex name. This makes static signature matching on function names,
/// global names, and type tokens infeasible across builds.
use std::collections::HashMap;

pub struct TokenShifter {
    /// Seed drives the RNG so the same IR always produces the same shifted
    /// output within one build, but a different seed gives a different output.
    seed: u64,
    map: HashMap<String, String>,
    counter: u64,
}

impl TokenShifter {
    pub fn new(seed: u64) -> Self {
        Self { seed, map: HashMap::new(), counter: 0 }
    }

    /// Transform a block of LLVM IR text: replace every `@name` and `%name`
    /// with a unique randomised alias.
    pub fn shift_ir(&mut self, ir: &str) -> String {
        let mut out = String::with_capacity(ir.len());
        let mut chars = ir.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '@' || c == '%' {
                let sigil = c;
                let ident = Self::read_ident(&mut chars);
                if ident.is_empty() {
                    out.push(sigil);
                } else {
                    let alias = self.alias_for(&ident);
                    out.push(sigil);
                    out.push_str(&alias);
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn read_ident(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
        let mut s = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_alphanumeric() || c == '_' || c == '.' {
                s.push(c);
                chars.next();
            } else {
                break;
            }
        }
        s
    }

    fn alias_for(&mut self, name: &str) -> String {
        if let Some(existing) = self.map.get(name) {
            return existing.clone();
        }
        let alias = self.next_name();
        self.map.insert(name.to_string(), alias.clone());
        alias
    }

    fn next_name(&mut self) -> String {
        // xorshift64 for cheap deterministic randomness
        let mut x = self.seed.wrapping_add(self.counter.wrapping_mul(6364136223846793005));
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.counter += 1;
        format!("x{:016x}", x.wrapping_mul(2685821657736338717))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifiers_are_replaced() {
        let ir = "define i32 @forensic_session_0() {\nentry:\n  %target_ptr = alloca i8\n  ret i32 0\n}";
        let mut ts = TokenShifter::new(0xdeadbeef);
        let out = ts.shift_ir(ir);
        assert!(!out.contains("@forensic_session_0"), "original name should be gone");
        assert!(!out.contains("%target_ptr"), "local var should be renamed");
    }

    #[test]
    fn test_same_name_maps_consistently() {
        let ir = "call @foo() + @foo()";
        let mut ts = TokenShifter::new(42);
        let out = ts.shift_ir(ir);
        // Both occurrences of @foo should map to the same alias
        let first  = out.find('@').unwrap();
        let second = out.rfind('@').unwrap();
        let a1: String = out[first+1..].chars().take_while(|c| c.is_alphanumeric() || *c=='_').collect();
        let a2: String = out[second+1..].chars().take_while(|c| c.is_alphanumeric() || *c=='_').collect();
        assert_eq!(a1, a2, "same original name must map to same alias");
    }

    #[test]
    fn test_different_seeds_produce_different_output() {
        let ir = "define i32 @session()";
        let mut ts1 = TokenShifter::new(1);
        let mut ts2 = TokenShifter::new(2);
        assert_ne!(ts1.shift_ir(ir), ts2.shift_ir(ir));
    }
}

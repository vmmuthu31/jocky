/// Generates hash-based API resolution stubs.
///
/// Instead of `call @CreateFile(...)` appearing in the PE import table,
/// the binary resolves the function at runtime by walking the PEB/InMemoryOrderLinks,
/// hashing each export name with a per-build ROR13 key, and comparing to a
/// stored hash. This removes the function name from the Import Address Table entirely.
///
/// The emitted IR calls a runtime helper `@jocky_resolve_api(i64 %hash) -> i8*`
/// which is provided by the JOCKY runtime and performs the PEB walk.

use std::collections::HashMap;

/// djb2-variant hash with per-build rotation offset — changes every build
pub fn hash_api_name(name: &str, ror_key: u8) -> u64 {
    let mut h: u64 = 5381;
    for b in name.bytes() {
        let rotated = b.rotate_right(ror_key as u32);
        h = h.wrapping_mul(33).wrapping_add(rotated as u64);
    }
    h
}

pub struct IatMasker {
    /// Per-build rotation key (1–7) — changes every compile
    ror_key: u8,
    /// api_name -> (hash, local_var_name)
    resolved: HashMap<String, (u64, String)>,
    counter: usize,
}

impl IatMasker {
    pub fn new(ror_key: u8) -> Self {
        Self {
            ror_key,
            resolved: HashMap::new(),
            counter: 0,
        }
    }

    /// Return LLVM IR that resolves `api_name` via runtime PEB walk.
    /// Multiple calls for the same API reuse the first resolution.
    pub fn resolve_api_ir(&mut self, api_name: &str) -> String {
        if let Some((hash, var)) = self.resolved.get(api_name) {
            return format!(
                "  ; reuse resolved {api_name} -> {var}\n  ; hash=0x{hash:016x}",
                api_name=api_name, var=var, hash=hash
            );
        }

        let hash = hash_api_name(api_name, self.ror_key);
        let var  = format!("%api_ptr_{}", self.counter);
        self.counter += 1;
        self.resolved.insert(api_name.to_string(), (hash, var.clone()));

        format!(
r#"  ; resolve {api_name} (hash=0x{hash:016x}, ror_key={ror})
  {var}_hash = add i64 0, {hash}
  {var} = call i8* @jocky_resolve_api(i64 {var}_hash)"#,
            api_name=api_name, hash=hash, ror=self.ror_key, var=var
        )
    }

    /// Replace known Windows API `declare` lines with runtime-resolve stubs.
    /// Removes them from the IR so they never appear in the PE import table.
    pub fn mask_imports(&mut self, ir: &str) -> String {
        let known_apis = [
            "CreateFileA", "CreateFileW", "OpenProcess", "VirtualAlloc",
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "RegOpenKeyExA", "RegQueryValueExA", "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory", "NtCreateThreadEx",
        ];

        let mut out = ir.to_string();
        let mut preamble = String::new();
        preamble.push_str("  ; === IAT-masked API resolution stubs ===\n");

        for api in &known_apis {
            if ir.contains(api) {
                preamble.push_str(&self.resolve_api_ir(api));
                preamble.push('\n');
                // Remove the `declare` line for this API
                let declare_pat = format!("declare i8* @{}(", api);
                out = out.lines()
                    .filter(|l| !l.contains(&declare_pat))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }

        // Inject the resolution block after first `entry:` label
        if let Some(pos) = out.find("entry:\n") {
            let insert = pos + "entry:\n".len();
            out.insert_str(insert, &preamble);
        }

        out
    }

    pub fn ror_key(&self) -> u8 {
        self.ror_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_changes_with_ror_key() {
        let h1 = hash_api_name("CreateFileA", 3);
        let h2 = hash_api_name("CreateFileA", 5);
        assert_ne!(h1, h2, "different ror_key must produce different hash");
    }

    #[test]
    fn test_hash_stable_for_same_key() {
        let h1 = hash_api_name("OpenProcess", 4);
        let h2 = hash_api_name("OpenProcess", 4);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_resolve_api_ir_emits_hash_call() {
        let mut masker = IatMasker::new(3);
        let ir = masker.resolve_api_ir("CreateFileA");
        assert!(ir.contains("jocky_resolve_api"), "must call resolver");
        assert!(ir.contains("CreateFileA"), "should document original name in comment");
    }

    #[test]
    fn test_same_api_reuses_variable() {
        let mut masker = IatMasker::new(3);
        let ir1 = masker.resolve_api_ir("OpenProcess");
        let ir2 = masker.resolve_api_ir("OpenProcess");
        assert!(ir2.contains("reuse"), "second call must reuse resolved pointer");
        let _ = ir1;
    }

    #[test]
    fn test_mask_imports_removes_declare() {
        let ir = "declare i8* @CreateFileA(i8*, i32)\ndefine void @main() {\nentry:\n  ret void\n}";
        let mut masker = IatMasker::new(2);
        let out = masker.mask_imports(ir);
        assert!(!out.contains("declare i8* @CreateFileA"), "declare must be removed");
        assert!(out.contains("jocky_resolve_api"), "resolution stub must be injected");
    }
}

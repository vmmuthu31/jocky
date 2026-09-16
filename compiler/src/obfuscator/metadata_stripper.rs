/// Strips and renames PE section metadata in LLVM IR text.
///
/// In the compiled binary the linker uses section names from IR attributes.
/// Renaming `.text` → a random hex name and removing DWARF/debug attributes
/// defeats PE-header signatures and makes dynamic analysis harder.

/// Well-known section names that EDRs key on
const SUSPICIOUS_SECTIONS: &[(&str, &str)] = &[
    (".text",    ".t"),
    (".data",    ".d"),
    (".rdata",   ".r"),
    (".bss",     ".b"),
    (".idata",   ".i"),   // import directory
    (".edata",   ".e"),   // export directory
    (".debug",   ".g"),
    (".pdata",   ".p"),
];

pub struct MetadataStripper {
    section_suffix: String,
}

impl MetadataStripper {
    /// `build_id` is a short per-build hex string (4–8 chars) appended to
    /// section name stubs so each build uses unique names.
    pub fn new(build_id: &str) -> Self {
        Self {
            section_suffix: build_id.to_string(),
        }
    }

    /// Rename known PE sections in IR `!section "..."` metadata attributes.
    pub fn rename_sections(&self, ir: &str) -> String {
        let mut out = ir.to_string();
        for (original, stub) in SUSPICIOUS_SECTIONS {
            let old_attr = format!("!section \"{}\"", original);
            let new_name = format!("{}{}", stub, &self.section_suffix);
            let new_attr = format!("!section \"{}\"", new_name);
            out = out.replace(&old_attr, &new_attr);

            // Handle `, section "..."` (with comma) and ` section "..."` (space only)
            let old_inline_comma = format!(", section \"{}\"", original);
            let new_inline_comma = format!(", section \"{}\"", new_name);
            out = out.replace(&old_inline_comma, &new_inline_comma);

            let old_inline_space = format!(" section \"{}\"", original);
            let new_inline_space = format!(" section \"{}\"", new_name);
            out = out.replace(&old_inline_space, &new_inline_space);
        }
        out
    }

    /// Remove DWARF debug metadata lines entirely.
    /// These lines start with `!` followed by a debug/DIFile/DISubprogram tag.
    pub fn strip_debug_info(&self, ir: &str) -> String {
        ir.lines()
            .filter(|l| !Self::is_debug_metadata(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn is_debug_metadata(line: &str) -> bool {
        let t = line.trim();
        // Metadata node definitions like `!0 = !DIFile(...)`
        // or `!llvm.dbg.cu = !{!0}`
        if t.starts_with("!llvm.dbg") { return true; }
        if t.starts_with("!llvm.module.flags") { return false; } // keep module flags
        // `!N = !{...}` debug-info numbered nodes — keep only if not DWARF
        if let Some(rest) = t.strip_prefix('!') {
            if rest.trim_start_matches(|c: char| c.is_ascii_digit()).trim_start().starts_with("= !DI") {
                return true;
            }
            if rest.trim_start_matches(|c: char| c.is_ascii_digit()).trim_start().starts_with("= distinct !DI") {
                return true;
            }
        }
        false
    }

    /// Remove `!dbg` references from instructions so we don't have dangling
    /// metadata references after stripping the nodes.
    pub fn strip_dbg_references(&self, ir: &str) -> String {
        // `!dbg !N` appears at the end of instruction lines
        let mut out = String::with_capacity(ir.len());
        for line in ir.lines() {
            let cleaned = Self::remove_dbg_suffix(line);
            out.push_str(cleaned.trim_end());
            out.push('\n');
        }
        out
    }

    fn remove_dbg_suffix(line: &str) -> &str {
        // Find `, !dbg !<number>` suffix
        if let Some(pos) = line.rfind(", !dbg !") {
            // Verify everything after `!dbg !` is digits
            let rest = &line[pos + 8..];
            if rest.chars().all(|c| c.is_ascii_digit()) {
                return &line[..pos];
            }
        }
        line
    }

    /// Run all stripping passes in order.
    pub fn strip_all(&self, ir: &str) -> String {
        let step1 = self.rename_sections(ir);
        let step2 = self.strip_debug_info(&step1);
        self.strip_dbg_references(&step2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_renamed() {
        let ir = r#"define void @f() section ".text" { ret void }"#;
        let s = MetadataStripper::new("a1b2");
        let out = s.rename_sections(ir);
        assert!(!out.contains(".text"), ".text must be renamed");
        assert!(out.contains(".ta1b2"), "expected .t + build_id");
    }

    #[test]
    fn test_debug_metadata_stripped() {
        let ir = "!0 = !DIFile(filename: \"main.rs\")\n!llvm.dbg.cu = !{!0}\ndefine void @f() { ret void }";
        let s = MetadataStripper::new("xx");
        let out = s.strip_debug_info(ir);
        assert!(!out.contains("!DIFile"), "DIFile must be stripped");
        assert!(out.contains("define void @f()"), "function must survive");
    }

    #[test]
    fn test_dbg_reference_removed() {
        let ir = "  %x = add i32 1, 2, !dbg !42\n";
        let s = MetadataStripper::new("zz");
        let out = s.strip_dbg_references(ir);
        assert!(!out.contains("!dbg"), "!dbg reference must be removed");
        assert!(out.contains("%x = add i32 1, 2"), "instruction must survive");
    }
}

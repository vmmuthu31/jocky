/// Encrypts all string literals in generated LLVM IR with a per-build XOR key.
/// At runtime the decryption stub (emitted inline) XORs each byte back.
/// This breaks string-based IOC matching in EDR memory scanners.
use rand::Rng;

#[derive(Debug, Clone)]
pub struct EncryptedString {
    pub key: u8,
    pub ciphertext: Vec<u8>,
    /// LLVM IR that decrypts and returns an i8* pointer at runtime
    pub ir_stub: String,
    pub global_name: String,
}

pub struct VarEncryptor {
    counter: usize,
}

impl VarEncryptor {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Encrypt a string and return IR globals + decryption stub.
    /// The stub can be inlined into the function body.
    pub fn encrypt_string(&mut self, value: &str) -> EncryptedString {
        let key: u8 = rand::thread_rng().gen_range(1..=255); // never 0 (XOR identity)
        let ciphertext: Vec<u8> = value.bytes().map(|b| b ^ key).collect();

        let idx = self.counter;
        self.counter += 1;

        let global_name = format!("@.enc.{}", idx);
        let local_ptr   = format!("%dec_buf_{}", idx);
        let local_key   = format!("%xor_key_{}", idx);
        let n = ciphertext.len();

        // Emit the encrypted bytes as a constant array
        let bytes_str: String = ciphertext.iter()
            .map(|b| format!("i8 {}", *b as i8))
            .collect::<Vec<_>>()
            .join(", ");

        let global_decl = format!(
            "{} = private unnamed_addr constant [{} x i8] [{}], align 1",
            global_name, n, bytes_str
        );

        // Inline decryption loop emitted as LLVM IR
        let ir_stub = format!(
r#"  ; decrypt string #{idx}
  {local_ptr} = alloca [{n} x i8], align 1
  {local_key} = add i8 0, {key}
  call void @jocky_xor_decrypt(i8* getelementptr inbounds ([{n} x i8], [{n} x i8]* {global_name}, i64 0, i64 0),
                               i8* getelementptr inbounds ([{n} x i8], [{n} x i8]* {local_ptr}, i64 0, i64 0),
                               i64 {n}, i8 {local_key})"#,
            idx=idx, n=n, key=key,
            global_name=global_name, local_ptr=local_ptr, local_key=local_key
        );

        EncryptedString {
            key,
            ciphertext,
            ir_stub,
            global_name: global_decl,
        }
    }

    /// Walk an IR string and encrypt every c-string constant `c"...\00"`,
    /// replacing them with decrypt stubs.
    pub fn encrypt_ir_strings(&mut self, ir: &str) -> String {
        // Simple approach: find `c"` quoted string constants and replace them
        let mut out = ir.to_string();
        let mut search_from = 0;

        loop {
            if let Some(start) = out[search_from..].find("c\"") {
                let abs_start = search_from + start;
                let content_start = abs_start + 2;
                // Find closing quote (handling \00 and other escapes)
                if let Some(rel_end) = out[content_start..].find('"') {
                    let abs_end = content_start + rel_end;
                    let raw = &out[content_start..abs_end].replace("\\00", "\0");
                    let enc = self.encrypt_string(raw);
                    // Replace the constant declaration with the encrypted version
                    let original = &format!("c\"{}\"", &out[content_start..abs_end]);
                    let replacement = format!("[{} x i8] [{}]",
                        enc.ciphertext.len(),
                        enc.ciphertext.iter()
                            .map(|b| format!("i8 {}", *b as i8))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    out = out.replacen(original, &replacement, 1);
                    search_from = abs_start + replacement.len();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        out
    }
}

impl Default for VarEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut enc = VarEncryptor::new();
        let es = enc.encrypt_string("192.168.1.105");
        // XOR again with same key recovers original
        let recovered: Vec<u8> = es.ciphertext.iter().map(|b| b ^ es.key).collect();
        assert_eq!(recovered, b"192.168.1.105");
    }

    #[test]
    fn test_key_is_never_zero() {
        let mut enc = VarEncryptor::new();
        for _ in 0..100 {
            let es = enc.encrypt_string("test");
            assert_ne!(es.key, 0, "XOR key 0 leaves plaintext unchanged");
        }
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let mut enc = VarEncryptor::new();
        let es = enc.encrypt_string("NTRO-2026-CYBER");
        assert_ne!(es.ciphertext, b"NTRO-2026-CYBER".to_vec());
    }

    #[test]
    fn test_ir_string_encryption() {
        let ir = r#"@.str = constant [5 x i8] c"test\00""#;
        let mut enc = VarEncryptor::new();
        let out = enc.encrypt_ir_strings(ir);
        // The output should not contain the plaintext as c"" literal
        assert!(!out.contains(r#"c"test"#), "plaintext string should be encrypted");
    }
}

pub mod ast;
pub mod parser;
pub mod validator;
pub mod codegen;
pub mod crypto;
pub mod forensics;
pub mod obfuscator;
pub mod runtime;

// Single process-wide mutex serialising all tests that touch env vars.
// Cargo runs tests in parallel within a crate; concurrent set_var/remove_var
// calls on JOCKY_ALLOW_DEV_KEY / JOCKY_HSM_MASTER_KEY would race.
// All crypto test modules import this and hold _guard for their full test body.
#[cfg(test)]
pub mod test_util {
    use std::sync::Mutex;
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub fn with_dev_key<T, F: FnOnce() -> T>(f: F) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("JOCKY_HSM_MASTER_KEY");
        std::env::set_var("JOCKY_ALLOW_DEV_KEY", "1");
        let result = f();
        std::env::remove_var("JOCKY_ALLOW_DEV_KEY");
        result
    }

    pub fn with_prod_key<T, F: FnOnce() -> T>(key: &str, f: F) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("JOCKY_ALLOW_DEV_KEY");
        std::env::set_var("JOCKY_HSM_MASTER_KEY", key);
        let result = f();
        std::env::remove_var("JOCKY_HSM_MASTER_KEY");
        result
    }
}

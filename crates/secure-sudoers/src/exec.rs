use nix::unistd::fexecve;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use std::ffi::CString;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn execute_securely(
    cmd: &ValidatedCommand,
    policy: &SecureSudoersPolicy,
) -> Result<(), String> {
    let binary_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(cmd.binary())
        .map_err(|e| format!("Failed to open binary '{}': {e}", cmd.binary()))?;

    let clean_env = build_scrubbed_env(cmd.env_whitelist());

    crate::isolation::setup_isolation(
        cmd.isolation(),
        &policy.global_settings.blocked_paths,
        cmd.binary(),
        cmd.args(),
    )
    .map_err(|e| format!("Isolation setup failed: {e}"))?;

    crate::isolation::drop_capabilities().map_err(|e| format!("Capability drop failed: {e}"))?;

    let binary_name = Path::new(cmd.binary())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd.binary());
    let mut argv: Vec<CString> = Vec::with_capacity(1 + cmd.args().len());
    argv.push(
        CString::new(binary_name).map_err(|e| format!("Binary name contains NUL byte: {e}"))?,
    );
    for arg in cmd.args() {
        argv.push(
            CString::new(arg.as_str())
                .map_err(|e| format!("Argument '{arg}' contains NUL byte: {e}"))?,
        );
    }

    let envp: Result<Vec<CString>, String> = clean_env
        .iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}"))
                .map_err(|e| format!("Env var '{k}' contains NUL byte: {e}"))
        })
        .collect();
    let envp = envp?;

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            }
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => std::process::exit(code),
                Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                    std::process::exit(128 + sig as i32)
                }
                _ => std::process::exit(1),
            }
        }
        Ok(nix::unistd::ForkResult::Child) => match fexecve(&binary_file, &argv, &envp) {
            Ok(infallible) => match infallible {},
            Err(e) => Err(format!("fexecve failed: {e}")),
        },
        Err(e) => Err(format!("fork failed: {e}")),
    }
}

pub fn build_scrubbed_env(whitelist: &[String]) -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| whitelist.contains(key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    fn wl(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        keys: Vec<String>,
    }

    impl EnvGuard {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let guard = ENV_LOCK.lock().unwrap();
            let mut keys = Vec::new();
            for (k, v) in pairs {
                unsafe {
                    std::env::set_var(k, v);
                }
                keys.push(k.to_string());
            }
            Self { _lock: guard, keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                unsafe {
                    std::env::remove_var(k);
                }
            }
        }
    }

    #[test]
    fn test_whitelisted_var_is_kept() {
        let _g = EnvGuard::new(&[("TERM", "xterm")]);
        let env = build_scrubbed_env(&wl(&["TERM"]));
        assert!(env.iter().any(|(k, _)| k == "TERM"));
    }

    #[test]
    fn test_ld_preload_is_stripped() {
        let _g = EnvGuard::new(&[("LD_PRELOAD", "evil.so"), ("TERM", "xterm")]);
        let env = build_scrubbed_env(&wl(&["TERM"]));
        assert!(!env.iter().any(|(k, _)| k == "LD_PRELOAD"));
    }
}

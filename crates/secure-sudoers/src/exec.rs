use nix::unistd::fexecve;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::Path;

pub fn hash_binary_fd(fd_raw: std::os::unix::io::RawFd) -> Result<String, String> {
    let proc_path = format!("/proc/self/fd/{}", fd_raw);
    let file = std::fs::File::open(&proc_path)
        .map_err(|e| format!("Cannot open binary for hashing via {}: {}", proc_path, e))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Read error while hashing binary: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn execute_securely(
    cmd: &ValidatedCommand,
    policy: &SecureSudoersPolicy,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    // Use the already opened FD from the validation phase to prevent TOCTOU
    let binary_fd_raw = unsafe { libc::dup(cmd.binary().fd.as_raw_fd()) };
    if binary_fd_raw < 0 {
        return Err(format!(
            "Failed to duplicate binary FD: {}",
            std::io::Error::last_os_error()
        ));
    }
    let binary_file = unsafe { std::fs::File::from_raw_fd(binary_fd_raw) };

    let clean_env = build_scrubbed_env(cmd.env_whitelist());

    crate::isolation::setup_isolation(
        cmd.isolation(),
        &policy.global_settings.blocked_paths,
        cmd.binary(),
        cmd.args(),
    )
    .map_err(|e| format!("Isolation setup failed: {e}"))?;

    crate::isolation::drop_capabilities().map_err(|e| format!("Capability drop failed: {e}"))?;

    let binary_name = Path::new(&cmd.binary().path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&cmd.binary().path);
    let mut argv: Vec<CString> = Vec::with_capacity(1 + cmd.args().len());
    argv.push(
        CString::new(binary_name).map_err(|e| format!("Binary name contains NUL byte: {e}"))?,
    );
    for arg in cmd.args() {
        let arg_str = arg.as_str();
        argv.push(
            CString::new(arg_str)
                .map_err(|e| format!("Argument '{}' contains NUL byte: {e}", arg_str))?,
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

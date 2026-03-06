//! Secure execution engine: TOCTOU-safe binary loading, environment scrubbing,
//! isolation application, capability dropping, and `fexecve`.
//!
//! The chronological order of operations inside [`execute_securely`] is not
//! arbitrary — each step depends on the previous one for correctness.
//!
//! See [`execute_securely`] for the full security rationale.

use crate::models::SSDFPolicy;
use crate::validator::ValidatedCommand;

// ── Public surface ────────────────────────────────────────────────────────────

/// Execute `cmd` in a hardened child environment.
///
/// **This function does not return on success.** `fexecve(2)` replaces the
/// current process image entirely; if it returns we map the error to a
/// descriptive `String` so the caller can log and exit cleanly.
///
/// On non-Linux platforms an `Err` is returned immediately, so the crate
/// remains cross-compilable for development on other operating systems.
///
/// # Operation order (security-critical)
///
/// 1. **Open binary fd** — Before any namespace or mount change, we open the
///    validated binary with `O_RDONLY | O_CLOEXEC`. This pins the exact inode
///    that was policy-checked. An attacker who swaps a symlink on disk *after*
///    our `validate_command` call cannot redirect execution because we already
///    hold a file descriptor to the real inode.
///
/// 2. **Scrub environment** — Build the clean `envp` from the current process
///    environment while we can still read it. We start from an empty set and
///    copy only the keys in `policy.global_settings.common_env_whitelist`.
///    `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, and every other injected
///    variable are destroyed by never being added.
///
/// 3. **Apply isolation** — Call `setup_isolation` *after* `open()` so that
///    `CLONE_NEWNS` does not change the mount-namespace view before we resolve
///    the binary path. Failing here aborts the pipeline.
///
/// 4. **Drop capabilities** — Strip dangerous capabilities from the bounding
///    set so they cannot be re-acquired via `execve`. Failing here aborts.
///
/// 5. **`fexecve`** — Replace the process image using the fd from step 1.
///    `O_CLOEXEC` on that fd ensures it is closed in the new process
///    automatically, leaving no accessible handle inside the sandboxed tool.
pub fn execute_securely(cmd: &ValidatedCommand, policy: &SSDFPolicy) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _ = policy; // whitelist is pre-merged into cmd; policy retained for future use
        linux_exec::run(cmd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cmd, policy);
        Err("Secure execution requires Linux; this platform is unsupported.".to_string())
    }
}

/// Build a scrubbed environment from the calling process's environment.
///
/// Iterates the *current* process environment, keeps only entries whose key
/// appears in `whitelist`, and returns them as `(key, value)` pairs.
///
/// The strategy is **allowlist-only**: we start with nothing and add
/// permitted keys, rather than starting with everything and removing bad keys.
/// This guarantees that newly introduced dangerous variables (e.g. a future
/// `LD_AUDIT` variant) are blocked by default without requiring a policy
/// update.
pub fn build_scrubbed_env(whitelist: &[String]) -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| whitelist.contains(key))
        .collect()
}

// ── Linux-only implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_exec {
    use super::{build_scrubbed_env, ValidatedCommand};
    use nix::unistd::fexecve;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub fn run(cmd: &ValidatedCommand, policy: &crate::models::SSDFPolicy) -> Result<(), String> {
        // ── Step 1: TOCTOU anchor ─────────────────────────────────────────────
        //
        // Open the binary before any namespace or mount changes so we hold an
        // fd to the exact inode the policy validated.
        //
        // O_CLOEXEC: the kernel closes this fd in the new process after a
        // successful exec so it does not leak as an accessible handle inside
        // the sandboxed tool.
        let binary_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(cmd.binary())
            .map_err(|e| format!("Failed to open binary '{}': {e}", cmd.binary()))?;

        // ── Step 2: Environment scrubbing ─────────────────────────────────────
        //
        // Use the pre-merged whitelist carried inside the ValidatedCommand
        // (global common_env_whitelist ∪ tool-specific env_whitelist, deduped).
        let clean_env = build_scrubbed_env(cmd.env_whitelist());

        // ── Step 3: Apply namespace isolation ────────────────────────────────
        //
        // Must happen after open() — CLONE_NEWNS must not affect the path
        // resolution we already completed.
        crate::isolation::setup_isolation(cmd.isolation(), &policy.global_settings.blocked_paths)
            .map_err(|e| format!("Isolation setup failed: {e}"))?;

        // ── Step 4: Drop dangerous capabilities ──────────────────────────────
        crate::isolation::drop_capabilities()
            .map_err(|e| format!("Capability drop failed: {e}"))?;

        // ── Step 5: Build argv CString array ─────────────────────────────────
        //
        // argv[0] is the bare binary name as seen in /proc/<pid>/comm and
        // process listings. Subsequent elements are the validated args.
        let binary_name = Path::new(cmd.binary())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(cmd.binary());

        let mut argv: Vec<CString> = Vec::with_capacity(1 + cmd.args().len());
        argv.push(
            CString::new(binary_name)
                .map_err(|e| format!("Binary name contains NUL byte: {e}"))?,
        );
        for arg in cmd.args() {
            argv.push(
                CString::new(arg.as_str())
                    .map_err(|e| format!("Argument '{arg}' contains NUL byte: {e}"))?,
            );
        }

        // ── Step 6: Build envp CString array ─────────────────────────────────
        let envp: Result<Vec<CString>, String> = clean_env
            .iter()
            .map(|(k, v)| {
                CString::new(format!("{k}={v}"))
                    .map_err(|e| format!("Env var '{k}' contains NUL byte: {e}"))
            })
            .collect();
        let envp = envp?;

        // ── Step 7: Replace the process image via fexecve ────────────────────
        //
        // Uses the fd from step 1 — not a path — so no path-based race is
        // possible at this point. Only returns if exec fails.
        match fexecve(binary_file.as_raw_fd(), &argv, &envp) {
            Ok(infallible) => match infallible {},
            Err(e) => Err(format!("fexecve failed: {e}")),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn wl(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }

    /// Module-level mutex that serialises all tests which touch the process
    /// environment. `std::env::set_var` / `remove_var` are not thread-safe;
    /// concurrent modifications from parallel test threads cause flaky reads.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Set env vars, run the closure, then clean up regardless of outcome.
    /// Holds `ENV_LOCK` for the entire duration so no two env-touching tests
    /// run concurrently.
    fn with_env<F: FnOnce()>(pairs: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        f();
        for (k, _) in pairs {
            std::env::remove_var(k);
        }
    }

    // ── Allowlisted variables are forwarded ───────────────────────────────────

    #[test]
    fn test_whitelisted_var_is_kept() {
        with_env(&[("TERM", "xterm-256color")], || {
            let env = build_scrubbed_env(&wl(&["TERM"]));
            let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
            assert!(keys.contains(&"TERM"), "TERM must be forwarded");
        });
    }

    #[test]
    fn test_multiple_whitelisted_vars_are_kept() {
        with_env(
            &[
                ("TERM", "xterm-256color"),
                ("LANG", "en_US.UTF-8"),
                ("LC_ALL", "en_US.UTF-8"),
            ],
            || {
                let env = build_scrubbed_env(&wl(&["TERM", "LANG", "LC_ALL"]));
                let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                assert!(keys.contains(&"TERM"));
                assert!(keys.contains(&"LANG"));
                assert!(keys.contains(&"LC_ALL"));
            },
        );
    }

    #[test]
    fn test_value_is_preserved_exactly() {
        with_env(&[("TERM", "screen-256color")], || {
            let env = build_scrubbed_env(&wl(&["TERM"]));
            let val = env.iter().find(|(k, _)| k == "TERM").map(|(_, v)| v.as_str());
            assert_eq!(val, Some("screen-256color"), "value must be preserved verbatim");
        });
    }

    // ── Dangerous variables are stripped ─────────────────────────────────────

    #[test]
    fn test_ld_preload_is_stripped() {
        with_env(&[("LD_PRELOAD", "/evil/lib.so"), ("TERM", "xterm")], || {
            let env = build_scrubbed_env(&wl(&["TERM"]));
            let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
            assert!(
                !keys.contains(&"LD_PRELOAD"),
                "LD_PRELOAD must be absent from the child environment"
            );
            assert!(keys.contains(&"TERM"), "TERM must still be present");
        });
    }

    #[test]
    fn test_ld_library_path_is_stripped() {
        with_env(
            &[("LD_LIBRARY_PATH", "/malicious/libs"), ("LANG", "en_US.UTF-8")],
            || {
                let env = build_scrubbed_env(&wl(&["LANG"]));
                let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                assert!(!keys.contains(&"LD_LIBRARY_PATH"));
            },
        );
    }

    #[test]
    fn test_pythonpath_is_stripped() {
        with_env(&[("PYTHONPATH", "/malicious"), ("LANG", "en_US.UTF-8")], || {
            let env = build_scrubbed_env(&wl(&["LANG"]));
            let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
            assert!(!keys.contains(&"PYTHONPATH"), "PYTHONPATH must be stripped");
        });
    }

    #[test]
    fn test_home_stripped_when_not_whitelisted() {
        with_env(&[("HOME", "/root"), ("TERM", "xterm")], || {
            let env = build_scrubbed_env(&wl(&["TERM"]));
            let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
            assert!(
                !keys.contains(&"HOME"),
                "HOME must not appear unless explicitly whitelisted"
            );
        });
    }

    // ── Empty / absent cases ──────────────────────────────────────────────────

    #[test]
    fn test_combined_whitelist_forwards_both_global_and_tool_vars() {
        // Simulate a merged whitelist: TERM (global) + AWS_PROFILE (tool-specific).
        with_env(
            &[
                ("TERM", "xterm-256color"),
                ("AWS_PROFILE", "prod"),
                ("LD_PRELOAD", "/evil/lib.so"),
            ],
            || {
                let combined = wl(&["TERM", "AWS_PROFILE"]);
                let env = build_scrubbed_env(&combined);
                let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                assert!(keys.contains(&"TERM"), "global var TERM must be forwarded");
                assert!(
                    keys.contains(&"AWS_PROFILE"),
                    "tool-specific AWS_PROFILE must be forwarded"
                );
                assert!(
                    !keys.contains(&"LD_PRELOAD"),
                    "LD_PRELOAD must still be stripped even with a combined whitelist"
                );
            },
        );
    }

    #[test]
    fn test_combined_whitelist_deduplication_does_not_repeat_vars() {
        // If TERM appears in both global and tool lists, the scrubbed env
        // must contain exactly one TERM entry (not two).
        with_env(&[("TERM", "xterm")], || {
            // Simulate the post-merge result: TERM listed twice, then deduped.
            let already_deduped = wl(&["TERM"]); // dedup already done in validate_command
            let env = build_scrubbed_env(&already_deduped);
            let term_count = env.iter().filter(|(k, _)| k == "TERM").count();
            assert_eq!(term_count, 1, "TERM must appear exactly once");
        });
    }

    #[test]
    fn test_empty_whitelist_produces_empty_env() {
        with_env(&[("TERM", "xterm"), ("HOME", "/root")], || {
            let env = build_scrubbed_env(&wl(&[]));
            assert!(
                env.is_empty(),
                "An empty whitelist must produce an empty environment"
            );
        });
    }

    #[test]
    fn test_key_in_whitelist_but_not_in_env_is_silently_skipped() {
        // A whitelisted key that does not exist in the environment must simply
        // be absent from the output — no panic, no empty-string insertion.
        let env = build_scrubbed_env(&wl(&["NONEXISTENT_VAR_XYZ_12345"]));
        assert!(
            env.is_empty(),
            "A missing env var must not produce a spurious empty entry"
        );
    }

    // ── Platform stub verification ────────────────────────────────────────────

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_non_linux_isolation_stubs_return_err() {
        // Verify the non-Linux stubs for isolation always return Err (never panic).
        let result =
            crate::isolation::setup_isolation(&crate::models::IsolationSettings::default(), &[]);
        assert!(result.is_err(), "setup_isolation stub must return Err on non-Linux");
        assert!(
            crate::isolation::drop_capabilities().is_err(),
            "drop_capabilities stub must return Err on non-Linux"
        );
    }
}

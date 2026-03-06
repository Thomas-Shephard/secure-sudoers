use crate::exec;
use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use std::sync::atomic::{AtomicBool, Ordering};

static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigwinch_handler(_: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
}

pub fn run_supervisor(cmd: &ValidatedCommand, policy: &SecureSudoersPolicy) -> Result<i32, String> {
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    let mut _tg = None;

    if stdin_is_tty {
        _tg = Some(TerminalGuard::new()?);
        install_sigwinch_handler()?;
    }

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            }

            loop {
                if SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) && stdin_is_tty {
                    let _ = forward_winsize(child);
                }

                match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => return Ok(code),
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                        return Ok(128 + sig as i32);
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => return Err(format!("waitpid failed: {e}")),
                    _ => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            if let Err(e) = exec::execute_securely(cmd, policy) {
                eprintln!("FATAL: {e}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => Err(format!("fork failed: {e}")),
    }
}

struct TerminalGuard {
    original_termios: libc::termios,
}

impl TerminalGuard {
    fn new() -> Result<Self, String> {
        let mut termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) } != 0 {
            return Err("tcgetattr failed".to_string());
        }
        let guard = Self {
            original_termios: termios,
        };

        let mut raw = termios;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &raw) } != 0 {
            return Err("tcsetattr failed".to_string());
        }

        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.original_termios);
        }
    }
}

fn install_sigwinch_handler() -> Result<(), String> {
    let sa = libc::sigaction {
        sa_sigaction: sigwinch_handler as *const () as usize,
        sa_mask: unsafe { std::mem::zeroed() },
        sa_flags: 0,
        sa_restorer: None,
    };
    if unsafe { libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut()) } != 0 {
        return Err("sigaction failed".to_string());
    }
    Ok(())
}

fn forward_winsize(child: nix::unistd::Pid) -> Result<(), String> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0 {
        unsafe { libc::ioctl(child.as_raw(), libc::TIOCSWINSZ, &ws) };
    }
    Ok(())
}

pub fn run_simple_supervisor(child: nix::unistd::Pid) -> Result<i32, String> {
    match nix::sys::wait::waitpid(child, None) {
        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Ok(code),
        Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => Ok(128 + sig as i32),
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::models::IsolationSettings;
    use secure_sudoers_common::testing::fixtures::make_policy;
    use secure_sudoers_common::validator::ValidatedCommand;

    #[test]
    fn test_sigwinch_handler_sets_flag() {
        use std::sync::atomic::Ordering;
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
        sigwinch_handler(libc::SIGWINCH);
        assert!(SIGWINCH_RECEIVED.load(Ordering::SeqCst));
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_supervisor_tty_stdin_covers_raw_mode_and_winch() {
        require_root!();

        fn child_fn() -> bool {
            let mut master_raw: libc::c_int = -1;
            let mut slave_raw: libc::c_int = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut master_raw,
                    &mut slave_raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                eprintln!("  openpty failed");
                return false;
            }

            if unsafe { libc::dup2(slave_raw, libc::STDIN_FILENO) } < 0 {
                eprintln!("  dup2 failed");
                return false;
            }
            unsafe { libc::close(slave_raw) };

            SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);

            let policy = make_policy();
            let cmd = ValidatedCommand::new_for_testing(
                "/usr/bin/true",
                vec![],
                IsolationSettings::default(),
                vec![],
            );
            match run_supervisor(&cmd, &policy) {
                Ok(0) => true,
                Ok(c) => {
                    eprintln!("  exit code {c}");
                    false
                }
                Err(e) => {
                    eprintln!("  err: {e}");
                    false
                }
            }
        }

        assert!(unsafe { in_fork(child_fn) });
    }
}

use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::ValidatedCommand;
use nix::errno::Errno;
use nix::pty::{forkpty, ForkptyResult};
use nix::sys::select::{select, FdSet};
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg, Termios};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

const BUF: usize = 4096;
static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);
}

struct TerminalGuard {
    fd: libc::c_int,
    saved: Termios,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = tcsetattr(borrowed, SetArg::TCSAFLUSH, &self.saved);
    }
}

fn forward_winsize(src_fd: libc::c_int, dst_fd: libc::c_int) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(src_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(dst_fd, libc::TIOCSWINSZ, &ws);
        }
    }
}

fn write_all(fd: libc::c_int, data: &[u8]) -> Result<(), String> {
    let mut pos = 0;
    while pos < data.len() {
        let n = unsafe {
            libc::write(fd, data[pos..].as_ptr() as *const libc::c_void, data.len() - pos)
        };
        match n.cmp(&0) {
            std::cmp::Ordering::Greater => pos += n as usize,
            std::cmp::Ordering::Equal => return Err(format!("write(fd={fd}): zero-byte write")),
            std::cmp::Ordering::Less => if Errno::last() != Errno::EINTR { return Err(format!("write(fd={fd}) failed")); }
        }
    }
    Ok(())
}

fn transfer_data(src: libc::c_int, dst: libc::c_int, buf: &mut [u8]) -> Result<bool, String> {
    let n = unsafe { libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n > 0 {
        write_all(dst, &buf[..n as usize])?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn run_supervisor(cmd: &ValidatedCommand, policy: &SecureSudoersPolicy) -> Result<i32, String> {
    let initial_ws: Option<nix::pty::Winsize> = unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && (ws.ws_row > 0 || ws.ws_col > 0) {
            Some(nix::pty::Winsize { ws_row: ws.ws_row, ws_col: ws.ws_col, ws_xpixel: ws.ws_xpixel, ws_ypixel: ws.ws_ypixel })
        } else { None }
    };

    let result = unsafe { forkpty(initial_ws.as_ref(), None) }.map_err(|e| format!("forkpty failed: {e}"))?;
    match result {
        ForkptyResult::Child => {
            if let Err(e) = crate::exec::execute_securely(cmd, policy) { eprintln!("secure-sudoers: exec failed: {e}"); }
            std::process::exit(1);
        }
        ForkptyResult::Parent { master, child } => parent_loop(master, child),
    }
}

fn parent_loop(master: OwnedFd, child: Pid) -> Result<i32, String> {
    let master_fd = master.as_raw_fd();
    let stdin_fd = libc::STDIN_FILENO;
    let stdout_fd = libc::STDOUT_FILENO;
    let stdin_is_tty = unsafe { libc::isatty(stdin_fd) } == 1;

    let _guard = if stdin_is_tty {
        let saved = tcgetattr(unsafe { BorrowedFd::borrow_raw(stdin_fd) }).map_err(|e| format!("tcgetattr: {e}"))?;
        let mut raw = saved.clone(); cfmakeraw(&mut raw);
        tcsetattr(unsafe { BorrowedFd::borrow_raw(stdin_fd) }, SetArg::TCSANOW, &raw).map_err(|e| format!("tcsetattr: {e}"))?;
        unsafe { libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as libc::sighandler_t); }
        forward_winsize(stdout_fd, master_fd);
        Some(TerminalGuard { fd: stdin_fd, saved })
    } else { None };

    let mut buf = [0u8; BUF];
    loop {
        if SIGWINCH_RECEIVED.swap(false, Ordering::Relaxed) { forward_winsize(stdout_fd, master_fd); }
        let mut readfds = FdSet::new();
        if stdin_is_tty { readfds.insert(unsafe { BorrowedFd::borrow_raw(stdin_fd) }); }
        readfds.insert(unsafe { BorrowedFd::borrow_raw(master_fd) });
        let nfds = if stdin_is_tty { stdin_fd.max(master_fd) } else { master_fd } + 1;
        match select(nfds, Some(&mut readfds), None, None, None) {
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(format!("select: {e}")),
            Ok(_) => {}
        }
        if readfds.contains(unsafe { BorrowedFd::borrow_raw(stdin_fd) }) {
            if !transfer_data(stdin_fd, master_fd, &mut buf)? { break; }
        }
        if readfds.contains(unsafe { BorrowedFd::borrow_raw(master_fd) }) {
            if !transfer_data(master_fd, stdout_fd, &mut buf)? { break; }
        }
    }
    drop(_guard);
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => Ok(code),
        Ok(WaitStatus::Signaled(_, sig, _)) => Ok(128 + sig as i32),
        _ => Ok(0),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use secure_sudoers_common::models::IsolationSettings;
    use secure_sudoers_common::testing::fixtures::make_policy;
    use secure_sudoers_common::validator::ValidatedCommand;

    macro_rules! require_root {
        () => {
            if unsafe { libc::getuid() } != 0 {
                eprintln!("  [SKIP] test requires root");
                return;
            }
        };
    }

    unsafe fn in_fork(child_fn: impl FnOnce() -> bool) -> bool {
        match unsafe { fork().expect("fork failed") } {
            ForkResult::Child => {
                let ok = child_fn();
                std::process::exit(if ok { 0 } else { 1 });
            }
            ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid") {
                WaitStatus::Exited(_, 0) => true,
                WaitStatus::Exited(_, code) => {
                    eprintln!("  child exited with code {code}");
                    false
                }
                other => {
                    eprintln!("  unexpected child status: {other:?}");
                    false
                }
            },
        }
    }

    /// Directly invoke the signal handler and verify the atomic flag is set.
    /// This covers the `sigwinch_handler` function body.
    #[test]
    fn test_sigwinch_handler_sets_flag() {
        use std::sync::atomic::Ordering;
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
        sigwinch_handler(libc::SIGWINCH);
        assert!(SIGWINCH_RECEIVED.load(Ordering::SeqCst));
        SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);
    }

    /// Run the supervisor with stdin bound to a PTY slave so that
    /// `stdin_is_tty = true`, covering: tcgetattr, cfmakeraw, tcsetattr,
    /// SIGWINCH signal installation, forward_winsize, and TerminalGuard::drop.
    /// Pre-seeding SIGWINCH_RECEIVED also covers the swap-and-forward branch.
    #[test]
    fn test_supervisor_tty_stdin_covers_raw_mode_and_winch() {
        require_root!();

        let ok = unsafe {
            in_fork(|| {
                // Allocate a PTY pair; make the slave our stdin/stdout so
                // isatty(STDIN_FILENO) returns 1 inside run_supervisor.
                let mut master_raw: libc::c_int = -1;
                let mut slave_raw: libc::c_int = -1;
                let ret = libc::openpty(
                    &mut master_raw,
                    &mut slave_raw,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                );
                if ret != 0 {
                    eprintln!("  openpty failed: {}", std::io::Error::last_os_error());
                    return false;
                }

                if libc::dup2(slave_raw, libc::STDIN_FILENO) < 0
                    || libc::dup2(slave_raw, libc::STDOUT_FILENO) < 0
                {
                    eprintln!("  dup2 failed");
                    return false;
                }
                libc::close(slave_raw);

                // Pre-seed the SIGWINCH flag so the first loop iteration
                // exercises the forward_winsize-on-signal path.
                SIGWINCH_RECEIVED.store(true, std::sync::atomic::Ordering::Relaxed);

                let policy = make_policy();
                let cmd = ValidatedCommand::new_for_testing(
                    "/usr/bin/true",
                    vec![],
                    IsolationSettings::default(),
                    vec![],
                );

                let result = run_supervisor(&cmd, &policy);
                libc::close(master_raw);
                match result {
                    Ok(code) => {
                        if code != 0 {
                            eprintln!("  /usr/bin/true exited {code}");
                        }
                        true
                    }
                    Err(e) => {
                        eprintln!("  supervisor failed: {e}");
                        false
                    }
                }
            })
        };

        assert!(ok, "supervisor TTY mode with SIGWINCH should succeed");
    }
}

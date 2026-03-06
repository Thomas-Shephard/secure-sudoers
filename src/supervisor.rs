//! PTY supervisor: allocates a pseudo-terminal, forks the validated child,
//! manages terminal raw-mode state, forwards I/O bidirectionally, handles
//! window-resize signals, and collects the child's exit code.
//!
//! # Why a PTY?
//! Without a PTY, programs like `apt`, `vim`, or `top` cannot query the
//! terminal window size or switch the terminal into canonical/raw mode.
//! Allocating a PTY makes the child believe it has a real terminal, so
//! interactive output (progress bars, colour, cursor movement) works as
//! expected.
//!
//! # Threat model note on escape-sequence filtering
//! If a malicious script sends a terminal-injection payload through the PTY,
//! that payload reaches the *calling user's* terminal emulator — the same
//! user who already owns the session. An injection can only yield an
//! unprivileged shell, not a root shell, so strict ANSI filtering is omitted
//! in favour of full UI compatibility.

use crate::models::SSDFPolicy;
use crate::validator::ValidatedCommand;

// ── Public surface ────────────────────────────────────────────────────────────

/// Allocate a PTY, fork the child, supervise I/O, and return the child's
/// exit code.
///
/// Replaces a direct [`crate::exec::execute_securely`] call in `main`.
/// On non-Linux platforms returns a stub `Err` so the crate stays
/// cross-compilable.
pub fn run_supervisor(cmd: &ValidatedCommand, policy: &SSDFPolicy) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    {
        linux_pty::run(cmd, policy)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cmd, policy);
        Err("PTY supervisor requires Linux; this platform is unsupported.".to_string())
    }
}

// ── Linux-only implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_pty {
    use crate::models::SSDFPolicy;
    use crate::validator::ValidatedCommand;
    use nix::errno::Errno;
    use nix::pty::{forkpty, ForkptyResult};
    use nix::sys::select::{select, FdSet};
    use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg, Termios};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;
    use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Read/write buffer size. 4 KiB balances latency and throughput.
    const BUF: usize = 4096;

    // ── SIGWINCH flag ─────────────────────────────────────────────────────────

    /// Set to `true` by the SIGWINCH handler; atomically consumed in the loop.
    static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

    /// Async-signal-safe handler — writes only a single atomic boolean.
    ///
    /// POSIX permits signal handlers to call only a small set of
    /// async-signal-safe functions. Storing an `AtomicBool` with
    /// `Relaxed` ordering is safe and sufficient here.
    extern "C" fn sigwinch_handler(_sig: libc::c_int) {
        SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);
    }

    // ── TerminalGuard ─────────────────────────────────────────────────────────

    /// RAII guard that restores the original `termios` state when dropped.
    ///
    /// Ensures the user's terminal is never left in raw mode even if the
    /// supervisor returns early due to an error or panic.
    struct TerminalGuard {
        /// File descriptor whose termios this guard owns (stdin = 0).
        fd: libc::c_int,
        /// Original termios captured before we applied raw mode.
        saved: Termios,
    }

    impl Drop for TerminalGuard {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is stdin (fd 0), which outlives any guard.
            let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
            // Best-effort restore; ignore errors (e.g. terminal already gone).
            let _ = tcsetattr(borrowed, SetArg::TCSAFLUSH, &self.saved);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Read the window size of `src_fd` (`TIOCGWINSZ`) and apply it to
    /// `dst_fd` (`TIOCSWINSZ`). Silently no-ops if either ioctl fails.
    fn forward_winsize(src_fd: libc::c_int, dst_fd: libc::c_int) {
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(src_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                libc::ioctl(dst_fd, libc::TIOCSWINSZ, &ws);
            }
        }
    }

    /// Write all bytes of `data` to `fd`, retrying on `EINTR`.
    fn write_all(fd: libc::c_int, data: &[u8]) -> Result<(), String> {
        let mut pos = 0;
        while pos < data.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    data[pos..].as_ptr() as *const libc::c_void,
                    data.len() - pos,
                )
            };
            match n.cmp(&0) {
                std::cmp::Ordering::Greater => pos += n as usize,
                std::cmp::Ordering::Equal => {
                    return Err(format!("write(fd={fd}): zero-byte write, pipe closed"))
                }
                std::cmp::Ordering::Less => {
                    let e = Errno::last();
                    if e != Errno::EINTR {
                        return Err(format!("write(fd={fd}) failed: {e}"));
                    }
                    // EINTR: retry
                }
            }
        }
        Ok(())
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    pub fn run(cmd: &ValidatedCommand, policy: &SSDFPolicy) -> Result<i32, String> {
        // Query the caller's terminal window size so the child PTY starts with
        // the correct dimensions, avoiding an initial resize flash.
        let initial_ws: Option<nix::pty::Winsize> = unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
                && (ws.ws_row > 0 || ws.ws_col > 0)
            {
                Some(nix::pty::Winsize {
                    ws_row: ws.ws_row,
                    ws_col: ws.ws_col,
                    ws_xpixel: ws.ws_xpixel,
                    ws_ypixel: ws.ws_ypixel,
                })
            } else {
                None
            }
        };

        // SAFETY: `forkpty` internally calls `fork(2)`, which is unsafe in
        // multi-threaded programs due to potential lock inversion in the child.
        // This binary is single-threaded at the point of forking (no background
        // threads are spawned before this call), so the invariant holds.
        let result = unsafe { forkpty(initial_ws.as_ref(), None) }
            .map_err(|e| format!("forkpty failed: {e}"))?;

        match result {
            // ── Child process ─────────────────────────────────────────────────
            ForkptyResult::Child => {
                // `execute_securely` replaces this image via `fexecve`.
                // It only returns if exec failed; exit immediately in that case.
                if let Err(e) = crate::exec::execute_securely(cmd, policy) {
                    eprintln!("secure-sudoers: exec failed: {e}");
                }
                std::process::exit(1);
            }

            // ── Parent process ────────────────────────────────────────────────
            ForkptyResult::Parent { master, child } => parent_loop(master, child),
        }
    }

    // ── Parent: I/O forwarding loop ───────────────────────────────────────────

    fn parent_loop(master: OwnedFd, child: Pid) -> Result<i32, String> {
        let master_fd = master.as_raw_fd();
        let stdin_fd: libc::c_int = libc::STDIN_FILENO;
        let stdout_fd: libc::c_int = libc::STDOUT_FILENO;

        // Determine once whether stdin is an interactive terminal.
        // When stdin is a pipe or /dev/null (e.g. test harnesses or scripts),
        // we must NOT monitor it in select(2): /dev/null is always readable and
        // returns 0 bytes (EOF) immediately, which would terminate the loop
        // before any child output has been forwarded.
        let stdin_is_tty = unsafe { libc::isatty(stdin_fd) } == 1;

        // Put stdin into raw mode only when it is actually connected to a TTY.
        // If stdin is a pipe (e.g. in scripts) we skip raw mode and SIGWINCH.
        let _guard: Option<TerminalGuard> =
            if stdin_is_tty {
                // Capture the current termios so TerminalGuard can restore it.
                let saved = tcgetattr(unsafe { BorrowedFd::borrow_raw(stdin_fd) })
                    .map_err(|e| format!("tcgetattr failed: {e}"))?;

                let mut raw = saved.clone();
                cfmakeraw(&mut raw);

                tcsetattr(
                    unsafe { BorrowedFd::borrow_raw(stdin_fd) },
                    SetArg::TCSANOW,
                    &raw,
                )
                .map_err(|e| format!("tcsetattr(raw) failed: {e}"))?;

                // Install the SIGWINCH handler after raw mode is confirmed active.
                // SAFETY: the handler only touches an AtomicBool.
                unsafe {
                    libc::signal(
                        libc::SIGWINCH,
                        sigwinch_handler as *const () as libc::sighandler_t,
                    );
                }

                // Immediately propagate the current window size to the PTY.
                forward_winsize(stdout_fd, master_fd);

                Some(TerminalGuard { fd: stdin_fd, saved })
            } else {
                None
            };

        let mut buf = [0u8; BUF];

        // ── Bidirectional forwarding loop ─────────────────────────────────────
        //
        // select(2) multiplexes stdin and the PTY master fd. When stdin has
        // data we forward it to the child (user keystrokes); when the master
        // has data we forward it to stdout (child output).
        loop {
            // Propagate any pending window resize before blocking in select.
            if SIGWINCH_RECEIVED.swap(false, Ordering::Relaxed) {
                forward_winsize(stdout_fd, master_fd);
            }

            let nfds = if stdin_is_tty { stdin_fd.max(master_fd) } else { master_fd } + 1;
            let mut readfds = FdSet::new();
            // Only monitor stdin when it is a real TTY; piped/null stdin would
            // immediately return EOF and terminate the loop before child output
            // is forwarded.
            if stdin_is_tty {
                readfds.insert(unsafe { std::os::fd::BorrowedFd::borrow_raw(stdin_fd) });
            }
            readfds.insert(unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) });

            match select(nfds, Some(&mut readfds), None, None, None) {
                // EINTR is normal: SIGWINCH interrupted the select. Re-enter
                // the loop so we check SIGWINCH_RECEIVED and forward the new size.
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(format!("select failed: {e}")),
                Ok(_) => {}
            }

            // ── stdin → master  (user → child) ───────────────────────────────
            if readfds.contains(unsafe { std::os::fd::BorrowedFd::borrow_raw(stdin_fd) }) {
                let n = unsafe {
                    libc::read(
                        stdin_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                match n.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        write_all(master_fd, &buf[..n as usize])?;
                    }
                    std::cmp::Ordering::Equal => break, // EOF on stdin
                    std::cmp::Ordering::Less => {
                        if Errno::last() != Errno::EINTR {
                            break; // Closed or unrecoverable error
                        }
                    }
                }
            }

            // ── master → stdout  (child → user) ──────────────────────────────
            if readfds.contains(unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) }) {
                let n = unsafe {
                    libc::read(
                        master_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                match n.cmp(&0) {
                    std::cmp::Ordering::Greater => {
                        write_all(stdout_fd, &buf[..n as usize])?;
                    }
                    std::cmp::Ordering::Equal => break, // PTY EOF
                    std::cmp::Ordering::Less => {
                        let e = Errno::last();
                        // EIO is the canonical Linux signal that the child has
                        // closed the slave end of the PTY — treat it as EOF.
                        // Any error other than EINTR also terminates the loop.
                        if e == Errno::EIO || e != Errno::EINTR {
                            break;
                        }
                    }
                }
            }
        }

        // Restore terminal state here, *before* waitpid, so the shell prompt
        // is displayed in the correct (cooked) mode.
        drop(_guard);

        // Collect the child's exit status and translate it to a numeric code.
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => Ok(code),
            // Mimic shell convention: 128 + signal number for signal deaths.
            Ok(WaitStatus::Signaled(_, sig, _)) => Ok(128 + sig as i32),
            Ok(_) => Ok(0),
            Err(e) => Err(format!("waitpid failed: {e}")),
        }
    }
}

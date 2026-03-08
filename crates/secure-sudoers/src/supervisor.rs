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

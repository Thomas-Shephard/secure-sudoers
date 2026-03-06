#[macro_export]
macro_rules! require_root {
    () => {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("  [SKIP] test requires root");
            return;
        }
    };
}

use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};

/// # Safety
/// This function is unsafe because it performs a `fork` and then `std::process::exit` in the child.
pub unsafe fn in_fork(child_fn: fn() -> bool) -> bool {
    match unsafe { fork().expect("fork failed") } {
        ForkResult::Child => {
            let ok = child_fn();
            std::process::exit(if ok { 0 } else { 1 });
        }
        ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid failed") {
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

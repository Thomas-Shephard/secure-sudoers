use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use secure_sudoers_common::models::IsolationSettings;
use std::os::unix::fs::OpenOptionsExt;

const CAP_DAC_OVERRIDE: libc::c_int = 1;
const CAP_KILL: libc::c_int = 5;
const CAP_NET_ADMIN: libc::c_int = 12;
const CAP_NET_RAW: libc::c_int = 13;
const CAP_SYS_MODULE: libc::c_int = 16;
const CAP_SYS_RAWIO: libc::c_int = 17;
const CAP_SYS_PTRACE: libc::c_int = 19;
const CAP_SYS_ADMIN: libc::c_int = 21;
const CAP_SYS_BOOT: libc::c_int = 22;
const CAP_MKNOD: libc::c_int = 27;
const CAP_AUDIT_WRITE: libc::c_int = 29;

const DANGEROUS_CAPS: &[libc::c_int] = &[
    CAP_SYS_ADMIN,
    CAP_SYS_PTRACE,
    CAP_SYS_MODULE,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_SYS_RAWIO,
    CAP_MKNOD,
    CAP_DAC_OVERRIDE,
    CAP_SYS_BOOT,
    CAP_AUDIT_WRITE,
    CAP_KILL,
];

pub fn setup_isolation(
    settings: &IsolationSettings,
    blocked_paths: &[String],
    cmd_binary: &str,
    cmd_args: &[String],
) -> Result<(), String> {
    unshare_namespaces(settings)?;
    make_root_private()?;
    apply_private_mounts(&settings.private_mounts)?;
    apply_blocked_paths(blocked_paths)?;

    for arg in cmd_args {
        if arg.starts_with('/') || arg.contains('/') {
            validate_path_isolated(arg, blocked_paths)?;
        }
    }
    validate_path_isolated(cmd_binary, blocked_paths)?;

    apply_readonly_mounts(&settings.readonly_mounts)?;
    drop_capabilities()?;
    Ok(())
}

fn validate_path_isolated(path_str: &str, blocked_paths: &[String]) -> Result<(), String> {
    secure_sudoers_common::fs::check_path(path_str, "isolated", blocked_paths).map(|_| ())
}

fn apply_blocked_paths(paths: &[String]) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    for path_str in paths {
        let file: std::fs::File = match std::fs::OpenOptions::new()
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path_str)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("Security failure: cannot anchor blocked path '{}': {e}", path_str)),
        };

        let fd = file.as_raw_fd();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(format!("Security failure: fstat failed on blocked path '{}'", path_str));
        }

        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let proc_fd_path = format!("/proc/self/fd/{}", fd);

        if is_dir {
            mount(Some("tmpfs"), proc_fd_path.as_str(), Some("tmpfs"), MsFlags::empty(), None::<&str>)
                .map_err(|e| format!("Security failure: tmpfs mount on blocked dir '{}' failed: {e}", path_str))?;
        } else {
            mount(Some("/dev/null"), proc_fd_path.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
                .map_err(|e| format!("Security failure: bind mount /dev/null on blocked file '{}' failed: {e}", path_str))?;
        }
    }
    Ok(())
}

fn unshare_namespaces(settings: &IsolationSettings) -> Result<(), String> {
    let mut flags = CloneFlags::CLONE_NEWNS;
    if settings.unshare_network { flags |= CloneFlags::CLONE_NEWNET; }
    if settings.unshare_pid { flags |= CloneFlags::CLONE_NEWPID; }
    if settings.unshare_ipc { flags |= CloneFlags::CLONE_NEWIPC; }
    if settings.unshare_uts { flags |= CloneFlags::CLONE_NEWUTS; }
    unshare(flags).map_err(|e| format!("unshare({flags:?}) failed: {e}"))
}

fn make_root_private() -> Result<(), String> {
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>)
        .map_err(|e| format!("remount '/' as MS_PRIVATE|MS_REC failed: {e}"))
}

fn apply_private_mounts(paths: &[String]) -> Result<(), String> {
    for path in paths {
        mount(Some("tmpfs"), path.as_str(), Some("tmpfs"), MsFlags::empty(), None::<&str>)
            .map_err(|e| format!("tmpfs mount on '{path}' failed: {e}"))?;
    }
    Ok(())
}

fn apply_readonly_mounts(paths: &[String]) -> Result<(), String> {
    for path in paths {
        mount(Some(path.as_str()), path.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .map_err(|e| format!("bind mount on '{path}' failed: {e}"))?;
        mount(Some(path.as_str()), path.as_str(), None::<&str>, MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>)
            .map_err(|e| format!("remount '{path}' read-only failed: {e}"))?;
    }
    Ok(())
}

pub fn drop_capabilities() -> Result<(), String> {
    for &cap in DANGEROUS_CAPS {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if ret != 0 {
            let err = Errno::last();
            if err == Errno::EINVAL { continue; }
            return Err(format!("prctl(PR_CAPBSET_DROP, CAP={cap}) failed: {err}"));
        }
    }
    Ok(())
}

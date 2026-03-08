use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use secure_sudoers_common::models::{IsolationSettings, ValidationContext};

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
        if std::path::Path::new(arg).exists() || arg.contains('/') {
            validate_path_isolated(arg, blocked_paths)?;
        }
    }
    validate_path_isolated(cmd_binary, blocked_paths)?;

    apply_readonly_mounts(&settings.readonly_mounts)?;
    drop_capabilities()?;
    Ok(())
}

fn validate_path_isolated(path_str: &str, blocked_paths: &[String]) -> Result<(), String> {
    secure_sudoers_common::fs::check_path(path_str, &ValidationContext::Positional, blocked_paths).map(|_| ())
}

fn apply_blocked_paths(paths: &[String]) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    for path_str in paths {
        let path = std::path::Path::new(path_str);
        
        let mut current_fd = match std::fs::File::open("/") {
            Ok(f) => f,
            Err(e) => return Err(format!("Security failure: cannot open root: {e}")),
        };

        let components: Vec<_> = path.components().skip(1).collect();
        for (i, comp) in components.iter().enumerate() {
            let comp_str = comp.as_os_str().to_str().ok_or("Invalid path component")?;
            let is_last = i == components.len() - 1;

            let next_fd_res = std::fs::OpenOptions::new()
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(format!("/proc/self/fd/{}/{}", current_fd.as_raw_fd(), comp_str));

            match next_fd_res {
                Ok(f) => { current_fd = f; }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let c_comp = std::ffi::CString::new(comp_str).map_err(|_| "Nul byte in path component")?;
                    if is_last && !path_str.ends_with('/') {
                        let fd = unsafe {
                            libc::openat(current_fd.as_raw_fd(), 
                                c_comp.as_ptr(),
                                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                                0o000)
                        };
                        if fd < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.kind() != std::io::ErrorKind::AlreadyExists {
                                return Err(format!("Security failure: cannot create mask file '{}': {}", path_str, err));
                            }
                        } else {
                            current_fd = unsafe { std::fs::File::from_raw_fd(fd) };
                            break; 
                        }
                    } else {
                        let ret = unsafe {
                            libc::mkdirat(current_fd.as_raw_fd(),
                                c_comp.as_ptr(),
                                0o000)
                        };
                        if ret != 0 {
                            let err = std::io::Error::last_os_error();
                            if err.kind() != std::io::ErrorKind::AlreadyExists {
                                return Err(format!("Security failure: cannot create mask dir '{}': {}", path_str, err));
                            }
                        }
                    }

                    current_fd = std::fs::OpenOptions::new()
                        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(format!("/proc/self/fd/{}/{}", current_fd.as_raw_fd(), comp_str))
                        .map_err(|e| format!("Security failure: cannot open component '{}' of '{}' after creation: {}", comp_str, path_str, e))?;
                }
                Err(e) => return Err(format!("Security failure: error traversing '{}' at '{}': {}", path_str, comp_str, e)),
            }
        }

        let fd = current_fd.as_raw_fd();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(format!("Security failure: fstat failed on '{}'", path_str));
        }

        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let proc_path = format!("/proc/self/fd/{}", fd);

        if is_dir {
            mount(Some("tmpfs"), proc_path.as_str(), Some("tmpfs"), MsFlags::empty(), None::<&str>)
                .map_err(|e| format!("Security failure: tmpfs mount on blocked dir '{}' failed: {e}", path_str))?;
        } else {
            mount(Some("/dev/null"), proc_path.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
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
    for cap in 0..64 {
        let _ = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];

    let ret = unsafe {
        libc::syscall(libc::SYS_capset, &header as *const CapHeader, &data as *const CapData)
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("Security failure: capset failed: {err}"));
    }

    Ok(())
}

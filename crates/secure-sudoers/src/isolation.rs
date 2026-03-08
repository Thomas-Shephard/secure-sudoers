use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use secure_sudoers_common::models::IsolationSettings;

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
    for path_str in paths {
        let st = match std::fs::metadata(path_str) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("Security failure: cannot stat blocked path '{}': {e}", path_str)),
        };

        if st.is_dir() {
            mount(Some("tmpfs"), path_str.as_str(), Some("tmpfs"), MsFlags::empty(), None::<&str>)
                .map_err(|e| format!("Security failure: tmpfs mount on blocked dir '{}' failed: {e}", path_str))?;
        } else {
            mount(Some("/dev/null"), path_str.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
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

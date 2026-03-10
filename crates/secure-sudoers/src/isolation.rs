use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use secure_sudoers_common::models::{IsolationSettings, SecurePath};
use secure_sudoers_common::validator::ValidatedArg;
pub use std::os::fd::AsRawFd;

pub fn setup_isolation(
    settings: &IsolationSettings,
    blocked_paths: &[String],
    _cmd_binary: &SecurePath,
    _cmd_args: &[ValidatedArg],
) -> Result<(), String> {
    unshare_namespaces(settings)?;
    make_root_private()?;
    apply_private_mounts(&settings.private_mounts)?;
    apply_blocked_paths(blocked_paths)?;

    apply_readonly_mounts(&settings.readonly_mounts)?;
    drop_capabilities()?;
    Ok(())
}

fn mount_shadow_fd(fd: i32, original_path: &str) -> Result<(), String> {
    let proc_path = format!("/proc/self/fd/{}", fd);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!(
            "fstat failed on fd {}: {}",
            fd,
            std::io::Error::last_os_error()
        ));
    }
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;

    if is_dir {
        mount(
            Some("tmpfs"),
            proc_path.as_str(),
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| {
            format!(
                "Security failure: tmpfs mount on blocked dir '{}' via {} failed: {e}",
                original_path, proc_path
            )
        })?;
    } else {
        mount(
            Some("/dev/null"),
            proc_path.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            format!(
                "Security failure: bind mount /dev/null on blocked file '{}' via {} failed: {e}",
                original_path, proc_path
            )
        })?;
    }
    Ok(())
}

fn apply_blocked_paths(paths: &[String]) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    for path_str in paths {
        let path = std::path::Path::new(path_str);

        let root_c = std::ffi::CString::new("/").unwrap();
        let root_raw = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(format!(
                "Security failure: cannot open root: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut current_fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(root_raw) };

        let components: Vec<_> = path.components().skip(1).collect();
        for (i, comp) in components.iter().enumerate() {
            let comp_str = comp.as_os_str().to_str().ok_or("Invalid path component")?;
            let c_comp =
                std::ffi::CString::new(comp_str).map_err(|_| "Nul byte in path component")?;
            let is_last = i == components.len() - 1;

            let next_raw = unsafe {
                libc::openat(
                    current_fd.as_raw_fd(),
                    c_comp.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };

            if next_raw >= 0 {
                current_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(format!(
                        "Security failure: error traversing '{}' at '{}': {}",
                        path_str, comp_str, err
                    ));
                }

                if is_last && !path_str.ends_with('/') {
                    let fd = unsafe {
                        libc::openat(
                            current_fd.as_raw_fd(),
                            c_comp.as_ptr(),
                            libc::O_WRONLY
                                | libc::O_CREAT
                                | libc::O_EXCL
                                | libc::O_NOFOLLOW
                                | libc::O_CLOEXEC,
                            0o000u32,
                        )
                    };
                    if fd < 0 {
                        let e2 = std::io::Error::last_os_error();
                        if e2.kind() != std::io::ErrorKind::AlreadyExists {
                            return Err(format!(
                                "Security failure: cannot create mask file '{}': {}",
                                path_str, e2
                            ));
                        }
                    } else {
                        unsafe { libc::close(fd) };
                    }
                } else {
                    let ret =
                        unsafe { libc::mkdirat(current_fd.as_raw_fd(), c_comp.as_ptr(), 0o000) };
                    if ret != 0 {
                        let e2 = std::io::Error::last_os_error();
                        if e2.kind() != std::io::ErrorKind::AlreadyExists {
                            return Err(format!(
                                "Security failure: cannot create mask dir '{}': {}",
                                path_str, e2
                            ));
                        }
                    }
                }

                let next_raw2 = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_comp.as_ptr(),
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_raw2 < 0 {
                    return Err(format!(
                        "Security failure: cannot open component '{}' of '{}' after creation: {}",
                        comp_str,
                        path_str,
                        std::io::Error::last_os_error()
                    ));
                }
                current_fd = unsafe { OwnedFd::from_raw_fd(next_raw2) };
            }
        }

        mount_shadow_fd(current_fd.as_raw_fd(), path_str)?;
    }
    Ok(())
}

fn unshare_namespaces(settings: &IsolationSettings) -> Result<(), String> {
    let mut flags = CloneFlags::CLONE_NEWNS;
    if settings.unshare_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if settings.unshare_pid {
        flags |= CloneFlags::CLONE_NEWPID;
    }
    if settings.unshare_ipc {
        flags |= CloneFlags::CLONE_NEWIPC;
    }
    if settings.unshare_uts {
        flags |= CloneFlags::CLONE_NEWUTS;
    }
    unshare(flags).map_err(|e| format!("unshare({flags:?}) failed: {e}"))
}

fn make_root_private() -> Result<(), String> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| format!("remount '/' as MS_PRIVATE|MS_REC failed: {e}"))
}

fn apply_private_mounts(paths: &[String]) -> Result<(), String> {
    for path_str in paths {
        let c_path = std::ffi::CString::new(path_str.as_str()).map_err(|_| "Nul byte in path")?;
        let fd_raw = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd_raw < 0 {
            return Err(format!(
                "Security failure: cannot open private_mount path '{}': {}",
                path_str,
                std::io::Error::last_os_error()
            ));
        }
        let proc_path = format!("/proc/self/fd/{}", fd_raw);
        let res = mount(
            Some("tmpfs"),
            proc_path.as_str(),
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        );
        unsafe { libc::close(fd_raw) };
        res.map_err(|e| format!("tmpfs mount on '{path_str}' via {proc_path} failed: {e}"))?;
    }
    Ok(())
}

fn apply_readonly_mounts(paths: &[String]) -> Result<(), String> {
    for path_str in paths {
        let c_path = std::ffi::CString::new(path_str.as_str()).map_err(|_| "Nul byte in path")?;
        let fd_raw = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd_raw < 0 {
            return Err(format!(
                "Security failure: cannot open readonly_mount path '{}': {}",
                path_str,
                std::io::Error::last_os_error()
            ));
        }
        let proc_path = format!("/proc/self/fd/{}", fd_raw);
        let res1 = mount(
            Some(proc_path.as_str()),
            proc_path.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        );
        if let Err(e) = res1 {
            unsafe { libc::close(fd_raw) };
            return Err(format!(
                "bind mount on '{path_str}' via {proc_path} failed: {}",
                e
            ));
        }

        let res2 = mount(
            Some(proc_path.as_str()),
            proc_path.as_str(),
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        );
        unsafe { libc::close(fd_raw) };
        res2.map_err(|e| format!("remount '{path_str}' via {proc_path} read-only failed: {e}"))?;
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
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            &data as *const CapData,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("Security failure: capset failed: {err}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::models::IsolationSettings;
    use secure_sudoers_common::testing::fixtures::open_path;
    use std::os::fd::{FromRawFd, OwnedFd};

    fn mount_only_settings() -> IsolationSettings {
        IsolationSettings {
            unshare_network: false,
            unshare_pid: false,
            unshare_ipc: false,
            unshare_uts: false,
            private_mounts: vec![],
            readonly_mounts: vec![],
        }
    }

    use std::sync::Mutex;
    static GLOBAL_PATH: Mutex<Option<String>> = Mutex::new(None);

    #[test]
    fn test_setup_isolation_blocks_path() {
        require_root!();

        let secret_path = format!("/tmp/ss_isolation_secret_{}", std::process::id());
        let _ = std::fs::remove_file(&secret_path);
        std::fs::write(&secret_path, b"TOP SECRET CONTENT").expect("write temp file");

        *GLOBAL_PATH.lock().unwrap() = Some(secret_path.clone());

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let secret_path = guard.as_ref().unwrap();
            let settings = mount_only_settings();
            let binary = open_path("/usr/bin/true");
            match setup_isolation(&settings, std::slice::from_ref(secret_path), &binary, &[]) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => {
                    let content = std::fs::read(secret_path).unwrap_or_default();
                    content.is_empty()
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };

        let _ = std::fs::remove_file(&secret_path);
        assert!(ok, "setup_isolation should have masked the blocked file");
    }

    #[test]
    fn test_setup_isolation_readonly_mount() {
        require_root!();

        let dir = tempfile::TempDir::new().expect("tempdir");
        let dir_path = dir.path().to_str().unwrap().to_string();
        std::fs::write(format!("{dir_path}/existing.txt"), b"data").unwrap();

        *GLOBAL_PATH.lock().unwrap() = Some(dir_path);

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let dir_path = guard.as_ref().unwrap();
            let settings = IsolationSettings {
                unshare_network: false,
                unshare_pid: false,
                unshare_ipc: false,
                unshare_uts: false,
                private_mounts: vec![],
                readonly_mounts: vec![dir_path.clone()],
            };
            let binary = open_path("/usr/bin/true");
            match setup_isolation(&settings, &[], &binary, &[]) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => {
                    let write_result = std::fs::write(format!("{dir_path}/new.txt"), b"new");
                    write_result.is_err()
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(ok, "write to read-only mount should have failed");
    }

    #[test]
    fn test_drop_capabilities_clears_all_sets() {
        require_root!();

        fn child_fn() -> bool {
            match drop_capabilities() {
                Err(e) => {
                    eprintln!("  drop_capabilities failed: {e}");
                    false
                }
                Ok(()) => {
                    let status = std::fs::read_to_string("/proc/self/status")
                        .expect("read /proc/self/status");
                    let cap_eff = status
                        .lines()
                        .find(|l| l.starts_with("CapEff:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| u64::from_str_radix(v, 16).ok())
                        .unwrap_or(u64::MAX);
                    let cap_prm = status
                        .lines()
                        .find(|l| l.starts_with("CapPrm:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| u64::from_str_radix(v, 16).ok())
                        .unwrap_or(u64::MAX);
                    cap_eff == 0 && cap_prm == 0
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "drop_capabilities should zero all effective and permitted sets"
        );
    }

    #[test]
    fn test_setup_isolation_rejects_symlink_blocked_path() {
        require_root!();

        let link_path = format!("/tmp/ss_symlink_trap_{}", std::process::id());
        let _ = std::fs::remove_file(&link_path);
        std::os::unix::fs::symlink("/etc/hostname", &link_path).expect("create symlink");

        *GLOBAL_PATH.lock().unwrap() = Some(link_path.clone());

        fn child_fn() -> bool {
            let guard = GLOBAL_PATH.lock().unwrap();
            let link_path = guard.as_ref().unwrap();
            let settings = mount_only_settings();
            let binary = open_path("/usr/bin/true");
            matches!(
                setup_isolation(&settings, std::slice::from_ref(link_path), &binary, &[]),
                Err(ref e) if e.contains("symlink")
            )
        }

        let ok = unsafe { in_fork(child_fn) };
        let _ = std::fs::remove_file(&link_path);
        assert!(ok, "setup_isolation must reject symlinks in blocked_paths");
    }

    #[test]
    fn test_path_swapping_mitigation() {
        require_root!();

        let target_path = format!("/tmp/ss_swappable_{}", std::process::id());
        let _ = std::fs::remove_file(&target_path);
        std::fs::write(&target_path, b"ORIGINAL").unwrap();

        let swapper_path = target_path.clone();

        fn child_fn() -> bool {
            let target_path = format!("/tmp/ss_swappable_{}", nix::unistd::getppid());

            let c_path = std::ffi::CString::new(target_path.as_str()).unwrap();
            let fd_raw = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd_raw < 0 {
                return false;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };
            let secure_path = SecurePath::new_for_testing(&target_path, fd);

            let _ = std::fs::remove_file(&target_path);
            std::os::unix::fs::symlink("/etc/hostname", &target_path).unwrap();

            // If it follows the symlink to /etc/hostname, it's a security failure
            // If it masks the (now unlinked) original file, it's a success
            let proc_path = format!("/proc/self/fd/{}", secure_path.fd.as_raw_fd());
            let res = mount(
                Some("/dev/null"),
                proc_path.as_str(),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );

            if res.is_err() {
                return false;
            }

            // Verify: /etc/hostname should still be readable and not /dev/null
            let hostname_content = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
            !hostname_content.is_empty()
        }

        let ok = unsafe { in_fork(child_fn) };
        let _ = std::fs::remove_file(&swapper_path);
        assert!(
            ok,
            "FD-based mounting must not follow symlinks swapped in after FD acquisition"
        );
    }
}

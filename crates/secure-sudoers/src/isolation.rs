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
    Ok(())
}

fn proc_fd_path(fd: i32) -> String {
    format!("/proc/self/fd/{fd}")
}

fn fstat_for_fd(fd: i32, context_path: &str) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!(
            "fstat failed on '{}': {}",
            context_path,
            std::io::Error::last_os_error()
        ));
    }
    Ok(st)
}

fn ensure_path_matches_fd(path_str: &str, expected_fd: i32) -> Result<(), String> {
    let current_fd = safe_traverse(path_str, false)?;
    let expected = fstat_for_fd(expected_fd, path_str)?;
    let current = fstat_for_fd(current_fd.as_raw_fd(), path_str)?;

    if expected.st_dev != current.st_dev || expected.st_ino != current.st_ino {
        return Err(format!(
            "Security failure: path '{}' changed after verification",
            path_str
        ));
    }
    Ok(())
}

fn mount_shadow_fd(fd: i32, original_path: &str) -> Result<(), String> {
    let st = fstat_for_fd(fd, original_path)?;
    ensure_path_matches_fd(original_path, fd)?;
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;

    if is_dir {
        mount(
            Some("tmpfs"),
            original_path,
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| {
            format!(
                "Security failure: tmpfs mount on blocked dir '{}' failed: {e}",
                original_path
            )
        })?;
    } else {
        mount(
            Some("/dev/null"),
            original_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            format!(
                "Security failure: bind mount /dev/null on blocked file '{}' failed: {e}",
                original_path
            )
        })?;
    }
    Ok(())
}

fn safe_traverse(path_str: &str, create: bool) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let path = std::path::Path::new(path_str);
    if !path.is_absolute() {
        return Err(format!(
            "Security failure: path '{}' is not absolute",
            path_str
        ));
    }

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
        let c_comp = std::ffi::CString::new(comp_str).map_err(|_| "Nul byte in path component")?;
        let is_last = i == components.len() - 1;

        let next_raw = unsafe {
            libc::openat(
                current_fd.as_raw_fd(),
                c_comp.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if next_raw >= 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(next_raw, &mut st) } != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(next_raw) };
                return Err(format!(
                    "Security failure: fstat failed on component '{}' of '{}': {}",
                    comp_str, path_str, err
                ));
            }

            if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                unsafe { libc::close(next_raw) };
                return Err(format!(
                    "Security failure: symlink detected during traversal of '{}' at '{}'",
                    path_str, comp_str
                ));
            }

            current_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(format!(
                    "Security failure: symlink detected during traversal of '{}' at '{}'",
                    path_str, comp_str
                ));
            }

            if err.kind() != std::io::ErrorKind::NotFound || !create {
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
                let ret = unsafe { libc::mkdirat(current_fd.as_raw_fd(), c_comp.as_ptr(), 0o000) };
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
    Ok(current_fd)
}

fn apply_blocked_paths(paths: &[String]) -> Result<(), String> {
    for path_str in paths {
        let fd = safe_traverse(path_str, true)?;
        mount_shadow_fd(fd.as_raw_fd(), path_str)?;
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
        let fd = safe_traverse(path_str, false)?;
        ensure_path_matches_fd(path_str, fd.as_raw_fd())?;
        mount(
            Some("tmpfs"),
            path_str.as_str(),
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("tmpfs mount on '{path_str}' failed: {e}"))?;
    }
    Ok(())
}

fn apply_readonly_mounts(paths: &[String]) -> Result<(), String> {
    for path_str in paths {
        let fd = safe_traverse(path_str, false)?;
        ensure_path_matches_fd(path_str, fd.as_raw_fd())?;
        let mount_source = proc_fd_path(fd.as_raw_fd());
        mount(
            Some(mount_source.as_str()),
            path_str.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind mount on '{path_str}' failed via '{mount_source}': {e}"))?;

        mount(
            Some(path_str.as_str()),
            path_str.as_str(),
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("remount '{path_str}' read-only failed: {e}"))?;
    }
    Ok(())
}

pub fn drop_capabilities() -> Result<(), String> {
    let last_cap = read_cap_last_cap()?;
    drop_bounding_capabilities_with(last_cap, |cap| {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })?;

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

fn drop_bounding_capabilities_with<F>(last_cap: u32, mut drop_one: F) -> Result<(), String>
where
    F: FnMut(u32) -> Result<(), std::io::Error>,
{
    for cap in 0..=last_cap {
        if let Err(err) = drop_one(cap) {
            tracing::error!(
                capability = cap,
                error = %err,
                "Capability bounding-set drop failed"
            );
            return Err(format!(
                "Security failure: PR_CAPBSET_DROP failed for capability {cap}: {err}"
            ));
        }
    }
    Ok(())
}

fn read_cap_last_cap() -> Result<u32, String> {
    let cap_last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| format!("Security failure: cannot read /proc/sys/kernel/cap_last_cap: {e}"))?;
    parse_cap_last_cap(&cap_last_cap)
}

fn parse_cap_last_cap(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    trimmed.parse::<u32>().map_err(|e| {
        format!("Security failure: invalid /proc/sys/kernel/cap_last_cap value '{trimmed}': {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::require_root;
    use crate::testing::in_fork;
    use secure_sudoers_common::models::IsolationSettings;
    use secure_sudoers_common::testing::fixtures::open_path;

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
    fn test_setup_isolation_does_not_pre_drop_capabilities() {
        require_root!();

        fn child_fn() -> bool {
            let settings = mount_only_settings();
            let binary = open_path("/usr/bin/true");
            match setup_isolation(&settings, &[], &binary, &[]) {
                Err(e) => {
                    eprintln!("  setup_isolation failed: {e}");
                    false
                }
                Ok(()) => match drop_capabilities() {
                    Ok(()) => true,
                    Err(e) => {
                        eprintln!("  explicit drop_capabilities failed after setup_isolation: {e}");
                        false
                    }
                },
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "setup_isolation should not pre-drop capabilities before explicit drop"
        );
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
    fn test_drop_capabilities_fails_closed_on_bounding_drop_error() {
        require_root!();

        fn child_fn() -> bool {
            if let Err(e) = drop_capabilities() {
                eprintln!("  initial drop_capabilities failed unexpectedly: {e}");
                return false;
            }

            match drop_capabilities() {
                Ok(()) => {
                    eprintln!("  expected second drop_capabilities to fail");
                    false
                }
                Err(e) => e.contains("Security failure: PR_CAPBSET_DROP failed for capability 0"),
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        assert!(
            ok,
            "drop_capabilities should fail when PR_CAPBSET_DROP is denied"
        );
    }

    #[test]
    fn test_drop_bounding_capabilities_reports_failing_index() {
        let err = drop_bounding_capabilities_with(5, |cap| {
            if cap == 3 {
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        })
        .expect_err("drop_bounding_capabilities_with should fail on injected EPERM");
        assert!(err.contains("PR_CAPBSET_DROP failed for capability 3"));
    }

    #[test]
    fn test_parse_cap_last_cap_accepts_trimmed_numeric_values() {
        assert_eq!(parse_cap_last_cap("40\n").unwrap(), 40);
    }

    #[test]
    fn test_parse_cap_last_cap_rejects_invalid_values() {
        let err = parse_cap_last_cap("not-a-number")
            .expect_err("parse_cap_last_cap should reject non-numeric input");
        assert!(err.contains("invalid /proc/sys/kernel/cap_last_cap value"));
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
            let res = setup_isolation(&settings, std::slice::from_ref(link_path), &binary, &[]);
            matches!(
                res,
                Err(ref e) if e.contains("symlink detected")
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

            // Real isolation uses private mount namespace
            if let Err(e) = unshare(CloneFlags::CLONE_NEWNS) {
                eprintln!("unshare failed: {e}");
                return false;
            }
            if let Err(e) = mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                None::<&str>,
            ) {
                eprintln!("mount private failed: {e}");
                return false;
            }

            let fd = match safe_traverse(&target_path, false) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("safe_traverse failed: {e}");
                    return false;
                }
            };

            let _ = std::fs::remove_file(&target_path);
            std::os::unix::fs::symlink("/etc/hostname", &target_path).unwrap();

            match ensure_path_matches_fd(&target_path, fd.as_raw_fd()) {
                Err(e)
                    if e.contains("symlink detected")
                        || e.contains("changed after verification") =>
                {
                    true
                }
                Err(e) => {
                    eprintln!("unexpected error: {e}");
                    false
                }
                Ok(()) => {
                    eprintln!("path swap went undetected");
                    false
                }
            }
        }

        let ok = unsafe { in_fork(child_fn) };
        let _ = std::fs::remove_file(&swapper_path);
        assert!(ok, "Isolation must be safe in a private mount namespace");
    }
}

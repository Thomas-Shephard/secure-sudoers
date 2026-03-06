//! Linux namespace isolation and capability-dropping logic.
//!
//! All syscall operations in this module target Linux only.
//! On non-Linux platforms every public function returns an `Err` immediately,
//! so the binary can be compiled cross-platform while remaining correct at
//! runtime on the intended target.

use crate::models::IsolationSettings;

// ── Public surface ────────────────────────────────────────────────────────────

/// Applies the namespace isolation described by `settings`.
///
/// Must be called in the child process context, after `fork` but before
/// `exec`. The function performs the following steps in order:
///
/// 1. Unshare namespaces (mount is always included; net/pid/ipc/uts are
///    conditional on the booleans in `settings`).
/// 2. Remount `/` as `MS_PRIVATE|MS_REC` so subsequent mounts cannot
///    propagate back to the host mount namespace.
/// 3. Overlay each `private_mounts` path with an empty `tmpfs`.
/// 4. Bind-remount each `readonly_mounts` path as read-only.
/// 5. Drop dangerous capabilities from the bounding set.
///
/// Returns `Err` on the first failing syscall. Never panics or silently
/// continues — callers must treat an `Err` as a fatal pipeline abort.
pub fn setup_isolation(settings: &IsolationSettings, blocked_paths: &[String]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::apply(settings, blocked_paths)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = settings;
        let _ = blocked_paths;
        Err("Isolation requires Linux namespaces; this platform is unsupported.".to_string())
    }
}

/// Drops a hardcoded list of dangerous capabilities from the process bounding
/// set using `prctl(PR_CAPBSET_DROP, …)`.
///
/// Must be called after `unshare` and before `exec`.
/// `EINVAL` responses are silently ignored — they indicate the capability is
/// already absent or not recognised by this kernel version.
/// Any other kernel error causes an immediate `Err`.
pub fn drop_capabilities() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::drop_caps()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Capability dropping requires Linux; this platform is unsupported.".to_string())
    }
}

// ── Linux-only implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::IsolationSettings;
    use nix::errno::Errno;
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};

    /// Capabilities to unconditionally drop from the bounding set.
    ///
    /// Integers match the kernel's capability numbering in
    /// `linux/capability.h`. We use the `libc` constants so the values stay
    /// in sync with whatever kernel headers libc was built against.
    const DANGEROUS_CAPS: &[libc::c_int] = &[
        21, // CAP_SYS_ADMIN   - mount, ptrace namespaces, device access, …
        19, // CAP_SYS_PTRACE  - ptrace arbitrary processes
        16, // CAP_SYS_MODULE  - load / unload kernel modules
        12, // CAP_NET_ADMIN   - network interface configuration
        13, // CAP_NET_RAW     - raw sockets / packet capture
        17, // CAP_SYS_RAWIO   - iopl / ioperm port I/O
        27, // CAP_MKNOD       - create device files with mknod(2)
    ];

    /// Entry point: apply all isolation steps in the required order.
    pub fn apply(settings: &IsolationSettings, blocked_paths: &[String]) -> Result<(), String> {
        unshare_namespaces(settings)?;
        make_root_private()?;
        apply_private_mounts(&settings.private_mounts)?;
        apply_blocked_paths(blocked_paths)?;
        apply_readonly_mounts(&settings.readonly_mounts)?;
        drop_caps()?;
        Ok(())
    }

    /// Overlay each blocked path to prevent TOCTOU bypasses.
    /// Directories are overlaid with tmpfs; files are bind-mounted to /dev/null.
    fn apply_blocked_paths(paths: &[String]) -> Result<(), String> {
        for path_str in paths {
            let path = std::path::Path::new(path_str);
            if !path.exists() {
                continue;
            }
            if path.is_dir() {
                mount(
                    Some("tmpfs"),
                    path_str.as_str(),
                    Some("tmpfs"),
                    MsFlags::empty(),
                    None::<&str>,
                )
                .map_err(|e| format!("tmpfs mount on blocked dir '{path_str}' failed: {e}"))?;
            } else {
                mount(
                    Some("/dev/null"),
                    path_str.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .map_err(|e| format!("bind mount /dev/null on blocked file '{path_str}' failed: {e}"))?;
            }
        }
        Ok(())
    }

    /// Build the complete `CloneFlags` bitfield and make a *single* `unshare`
    /// syscall.
    ///
    /// A single call is both more efficient and more atomic than separate
    /// calls. `CLONE_NEWNS` (mount namespace) is **always** included — it is
    /// the prerequisite for every mount operation that follows. Without it,
    /// `make_root_private` and the mount helpers would modify the host's
    /// shared namespace instead of a private child copy.
    fn unshare_namespaces(settings: &IsolationSettings) -> Result<(), String> {
        let mut flags = CloneFlags::CLONE_NEWNS; // mandatory

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

    /// Remount the root filesystem with `MS_PRIVATE | MS_REC`.
    ///
    /// Without this step, any mounts we create inside our new mount namespace
    /// could propagate back to the host via shared or slave propagation.
    /// Making `/` private with `MS_REC` cascades the flag to every submount,
    /// creating a clean isolation boundary before we start overlaying paths.
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

    /// Overlay each path in `private_mounts` with an empty `tmpfs`.
    ///
    /// The real directory on the host is unmodified — it is simply hidden
    /// from the sandboxed process, which sees only an empty in-memory
    /// filesystem at that path.
    fn apply_private_mounts(paths: &[String]) -> Result<(), String> {
        for path in paths {
            mount(
                Some("tmpfs"),
                path.as_str(),
                Some("tmpfs"),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| format!("tmpfs mount on '{path}' failed: {e}"))?;
        }
        Ok(())
    }

    /// Bind-mount each path in `readonly_mounts` onto itself, then remount
    /// it read-only.
    ///
    /// The two-step sequence is a kernel requirement: `MS_RDONLY` cannot be
    /// added to a pre-existing mount in a single `mount(2)` call. The bind
    /// mount first creates an independent mount-table entry; the remount then
    /// strips write permission from that entry without touching the original.
    fn apply_readonly_mounts(paths: &[String]) -> Result<(), String> {
        for path in paths {
            // Step 1 — create an independent mount-table entry via bind mount.
            mount(
                Some(path.as_str()),
                path.as_str(),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| format!("bind mount on '{path}' failed: {e}"))?;

            // Step 2 — strip write permission by remounting with MS_RDONLY.
            // MS_BIND must be included again or the kernel rejects the call.
            mount(
                Some(path.as_str()),
                path.as_str(),
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| format!("remount '{path}' read-only failed: {e}"))?;
        }
        Ok(())
    }

    /// Drop each capability in `DANGEROUS_CAPS` from the process bounding set.
    ///
    /// `EINVAL` → the capability is already absent from the bounding set, or
    /// the kernel does not know about it. Either way the desired security
    /// outcome (cap is not available) is already met; continue silently.
    ///
    /// Any other errno → the drop failed unexpectedly; return `Err`
    /// immediately without processing remaining capabilities.
    pub fn drop_caps() -> Result<(), String> {
        for &cap in DANGEROUS_CAPS {
            // SAFETY: `prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)` is a
            // well-specified Linux syscall. The trailing zeroes are required
            // by the calling convention even though the kernel ignores them
            // for this particular operation.
            let ret = unsafe {
                libc::prctl(
                    libc::PR_CAPBSET_DROP,
                    cap as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };

            if ret != 0 {
                let err = Errno::last();
                if err == Errno::EINVAL {
                    // Cap already absent or unsupported — desired state achieved.
                    continue;
                }
                return Err(format!(
                    "prctl(PR_CAPBSET_DROP, CAP={cap}) failed: {err}"
                ));
            }
        }
        Ok(())
    }
}

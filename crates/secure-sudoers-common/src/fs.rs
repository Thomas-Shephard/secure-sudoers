use crate::models::{SecurePath, ValidationContext};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

const MAX_SYMLINK_DEPTH: u32 = 32;

pub fn check_path(
    arg: &str,
    context: &ValidationContext,
    blocked_paths: &[String],
) -> Result<SecurePath, String> {
    if arg.contains("..") {
        return Err(format!(
            "Path traversal detected in argument '{}' for '{}'",
            arg, context
        ));
    }

    let path = Path::new(arg);
    if !path.is_absolute() {
        return Err(format!("Security failure: path must be absolute: {}", arg));
    }

    let mut symlink_count = 0;
    resolve_securely(path, blocked_paths, &mut symlink_count)
}

fn resolve_securely(
    path: &Path,
    blocked_paths: &[String],
    symlink_count: &mut u32,
) -> Result<SecurePath, String> {
    let mut current_fd = open_root()?;
    let mut current_canonical = PathBuf::from("/");

    let components: Vec<_> = path.components().skip(1).collect();

    for (i, comp) in components.iter().enumerate() {
        let (comp_str, is_normal) = match comp {
            Component::Normal(s) => (s.to_str().ok_or("Invalid path component")?, true),
            Component::ParentDir => ("..", false),
            Component::CurDir => continue,
            _ => continue,
        };
        let c_comp = std::ffi::CString::new(comp_str).map_err(|_| "Nul byte in component")?;

        let fd_raw = unsafe {
            libc::openat(
                current_fd.as_raw_fd(),
                c_comp.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if fd_raw >= 0 {
            if is_normal {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd_raw, &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
                {
                    unsafe { libc::close(fd_raw) };

                    *symlink_count += 1;
                    if *symlink_count > MAX_SYMLINK_DEPTH {
                        return Err("Security failure: too many symlinks".to_string());
                    }

                    let link_target = read_link_at(current_fd.as_raw_fd(), &c_comp)?;
                    let link_path = Path::new(&link_target);

                    let mut new_path = if link_path.is_absolute() {
                        link_path.to_path_buf()
                    } else {
                        current_canonical.join(link_path)
                    };

                    for rem in &components[i + 1..] {
                        new_path.push(rem);
                    }
                    return resolve_securely(&new_path, blocked_paths, symlink_count);
                }
                current_canonical.push(comp_str);
            } else {
                current_canonical.pop();
            }

            current_fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };
            check_blocked(&current_canonical.to_string_lossy(), blocked_paths)?;
        } else {
            let err = std::io::Error::last_os_error();
            return Err(format!(
                "Security failure: cannot open component '{}' of '{}': {}",
                comp_str,
                path.display(),
                err
            ));
        }
    }

    let proc_fd_path = format!("/proc/self/fd/{}", current_fd.as_raw_fd());
    let canonical_path = std::fs::read_link(&proc_fd_path).map_err(|e| {
        format!(
            "Security failure: cannot read magic symlink '{}' to get canonical path: {}",
            proc_fd_path, e
        )
    })?;

    Ok(SecurePath {
        path: canonical_path.to_string_lossy().into_owned(),
        fd: current_fd,
    })
}

fn open_root() -> Result<OwnedFd, String> {
    let c_root = std::ffi::CString::new("/").unwrap();
    let fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Cannot open root: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_link_at(dir_fd: i32, c_name: &std::ffi::CStr) -> Result<String, String> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::readlinkat(
            dir_fd,
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(format!(
            "readlinkat failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let s = std::str::from_utf8(&buf[..n as usize]).map_err(|_| "Invalid UTF-8 in symlink")?;
    Ok(s.to_string())
}

fn check_blocked(path: &str, blocked_paths: &[String]) -> Result<(), String> {
    for blocked in blocked_paths {
        let bp = Path::new(blocked);
        let cp = Path::new(path);
        if cp == bp || cp.starts_with(bp) {
            return Err(format!("Access to blocked path '{}' is denied", path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ValidationContext;
    use tempfile::tempdir;

    #[test]
    fn test_check_path_blocks_traversal_via_symlink() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let secret_dir = base_path.join("secret");
        std::fs::create_dir(&secret_dir).unwrap();
        let secret_file = secret_dir.join("data.txt");
        std::fs::write(&secret_file, b"CONFIDENTIAL").unwrap();

        let public_dir = base_path.join("public");
        std::fs::create_dir(&public_dir).unwrap();

        // Create a malicious symlink: public/trap -> ../secret
        let trap_link = public_dir.join("trap");
        std::os::unix::fs::symlink("../secret", &trap_link).unwrap();

        let blocked_paths = vec![secret_dir.to_str().unwrap().to_string()];
        let context = ValidationContext::Positional;

        // Attempt to access public/trap/data.txt
        let target = trap_link.join("data.txt");
        let result = check_path(target.to_str().unwrap(), &context, &blocked_paths);

        assert!(result.is_err());
        assert!(
            result.as_ref().unwrap_err().contains("denied"),
            "Expected denial error, got {:?}",
            result
        );
    }

    #[test]
    fn test_check_path_blocks_traversal_via_explicit_dots() {
        let dir = tempdir().unwrap();
        let base_path = dir.path();

        let secret_dir = base_path.join("secret");
        std::fs::create_dir(&secret_dir).unwrap();

        let public_dir = base_path.join("public");
        std::fs::create_dir(&public_dir).unwrap();

        let blocked_paths = vec![secret_dir.to_str().unwrap().to_string()];
        let context = ValidationContext::Positional;

        let target = public_dir.join("..").join("secret");

        let result = check_path(target.to_str().unwrap(), &context, &blocked_paths);

        assert!(result.is_err());
    }
}

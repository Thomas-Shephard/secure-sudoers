use secure_sudoers_common::models::SecureSudoersPolicy;

pub const INSTALL_POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";
pub const INSTALL_BINARY: &str = "/usr/local/bin/secure-sudoers";
pub const INSTALL_UTILS_BINARY: &str = "/usr/local/bin/secure-sudoers-utils";
pub const INSTALL_SUDOERS_PATH: &str = "/etc/sudoers.d/secure-sudoers";
pub const SYMLINK_DIR: &str = "/usr/local/bin";

#[derive(Debug, Clone)]
pub struct InstallPaths<'a> {
    pub policy_path: &'a str,
    pub binary: &'a str,
    pub utils_binary: &'a str,
    pub sudoers_path: &'a str,
    pub symlink_dir: &'a str,
}

impl Default for InstallPaths<'static> {
    fn default() -> Self {
        InstallPaths {
            policy_path: INSTALL_POLICY_PATH,
            binary: INSTALL_BINARY,
            utils_binary: INSTALL_UTILS_BINARY,
            sudoers_path: INSTALL_SUDOERS_PATH,
            symlink_dir: SYMLINK_DIR,
        }
    }
}

pub fn cmd_install() -> Result<(), String> {
    install_with_paths(&InstallPaths::default())
}

pub fn cmd_unlock() -> Result<(), String> {
    unlock_with_paths(&InstallPaths::default())
}

pub fn generate_sudoers_content(tools: &[String]) -> String {
    generate_sudoers_content_with_dir(tools, SYMLINK_DIR)
}

fn generate_sudoers_content_with_dir(tools: &[String], symlink_dir: &str) -> String {
    if tools.is_empty() {
        return "# No tools authorized in policy. This file is intentionally empty.\n".to_string();
    }
    let mut sorted: Vec<&str> = tools.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let paths: Vec<String> = sorted
        .iter()
        .map(|t| format!("{symlink_dir}/{t}"))
        .collect();
    format!(
        "# Managed by secure-sudoers-utils - do not edit manually.\n\
         Defaults secure_path=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
         ALL ALL=(root) {}\n",
        paths.join(", ")
    )
}

fn load_policy(path: &str) -> Result<SecureSudoersPolicy, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    serde_json::from_str(&src).map_err(|e| format!("Invalid policy JSON at {path}: {e}"))
}

pub fn install_with_paths(paths: &InstallPaths<'_>) -> Result<(), String> {
    let mut policy = load_policy(paths.policy_path)?;
    policy
        .validate()
        .map_err(|e| format!("Policy validation failed: {e}"))?;

    let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
    tool_names.sort_unstable();
    println!("Installing {} tool(s)...", tool_names.len());

    let (successful_tools, symlink_errors) =
        install_symlinks_to(&tool_names, paths.binary, paths.symlink_dir);
    write_sudoers_file_to(&successful_tools, paths.sudoers_path, paths.symlink_dir)?;

    let mut targets: Vec<String> = vec![
        paths.binary.to_string(),
        paths.utils_binary.to_string(),
        paths.policy_path.to_string(),
        paths.sudoers_path.to_string(),
    ];
    targets.extend(
        successful_tools
            .iter()
            .map(|t| format!("{}/{t}", paths.symlink_dir)),
    );
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    for e in chattr_op("+i", &refs) {
        eprintln!("Warning: chattr +i failed: {e}");
    }

    println!("Installation complete.");
    if !symlink_errors.is_empty() {
        return Err(format!(
            "Installation completed with symlink errors:\n{}",
            symlink_errors.join("\n")
        ));
    }
    Ok(())
}

pub fn unlock_with_paths(paths: &InstallPaths<'_>) -> Result<(), String> {
    let mut policy = load_policy(paths.policy_path)?;
    let _ = policy.validate();

    let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
    tool_names.sort_unstable();
    let mut targets: Vec<String> = vec![
        paths.binary.to_string(),
        paths.utils_binary.to_string(),
        paths.policy_path.to_string(),
        paths.sudoers_path.to_string(),
    ];
    targets.extend(
        tool_names
            .iter()
            .map(|t| format!("{}/{t}", paths.symlink_dir)),
    );
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    let errors = chattr_op("-i", &refs);
    for e in &errors {
        eprintln!("Warning: chattr -i failed: {e}");
    }
    println!("Unlocked {} managed file(s).", refs.len());
    if !errors.is_empty() {
        return Err(format!(
            "Some files could not be unlocked:\n{}",
            errors.join("\n")
        ));
    }
    Ok(())
}

fn install_symlinks_to(
    tools: &[String],
    binary: &str,
    symlink_dir: &str,
) -> (Vec<String>, Vec<String>) {
    let mut successful = Vec::new();
    let mut errors = Vec::new();
    for tool in tools {
        if !secure_sudoers_common::models::is_valid_tool_name(tool) {
            errors.push(format!("Invalid tool name '{tool}'"));
            continue;
        }
        let link_path = std::path::Path::new(symlink_dir).join(tool);
        let mut skip = false;
        match std::fs::symlink_metadata(&link_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    if let Err(e) = std::fs::remove_file(&link_path) {
                        errors.push(format!(
                            "Cannot remove old symlink {}: {e}",
                            link_path.display()
                        ));
                        skip = true;
                    }
                } else if meta.file_type().is_file() {
                    let backup = format!("{}.bak", link_path.display());
                    if let Err(e) = std::fs::rename(&link_path, &backup) {
                        errors.push(format!("Cannot back up {}: {e}", link_path.display()));
                        skip = true;
                    } else {
                        println!("  Backed up {} -> {backup}", link_path.display());
                    }
                } else {
                    errors.push(format!(
                        "Skipping {}: not a regular file or symlink",
                        link_path.display()
                    ));
                    skip = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                errors.push(format!("Cannot stat {}: {e}", link_path.display()));
                skip = true;
            }
        }
        if skip {
            continue;
        }

        match std::os::unix::fs::symlink(binary, &link_path) {
            Ok(()) => {
                println!("  Symlinked {} -> {binary}", link_path.display());
                successful.push(tool.clone());
            }
            Err(e) => errors.push(format!(
                "Cannot create symlink {} -> {binary}: {e}",
                link_path.display()
            )),
        }
    }
    (successful, errors)
}

fn write_sudoers_file_to(
    tools: &[String],
    sudoers_path: &str,
    symlink_dir: &str,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    struct TempFileCleanupGuard {
        path: std::path::PathBuf,
        armed: bool,
    }

    impl TempFileCleanupGuard {
        fn new(path: std::path::PathBuf) -> Self {
            Self { path, armed: true }
        }

        fn disarm(&mut self) {
            self.armed = false;
        }
    }

    impl Drop for TempFileCleanupGuard {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            if let Err(e) = std::fs::remove_file(&self.path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "Warning: failed to clean up temporary sudoers file {}: {e}",
                        self.path.display()
                    );
                }
            }
        }
    }

    let content = generate_sudoers_content_with_dir(tools, symlink_dir);
    let sudoers = std::path::Path::new(sudoers_path);
    let sudoers_file_name = sudoers.file_name().ok_or_else(|| {
        format!("Invalid sudoers destination path {sudoers_path}: missing file name")
    })?;
    let temp_path = sudoers.with_file_name(format!("{}.tmp", sudoers_file_name.to_string_lossy()));
    let mut temp_cleanup_guard = TempFileCleanupGuard::new(temp_path.clone());

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o440)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| {
            format!(
                "Cannot create temporary sudoers file {} for destination {}: {e}",
                temp_path.display(),
                sudoers_path
            )
        })?;
    f.set_permissions(std::fs::Permissions::from_mode(0o440))
        .map_err(|e| {
            format!(
                "Cannot set permissions on temporary sudoers file {}: {e}",
                temp_path.display()
            )
        })?;
    f.write_all(content.as_bytes()).map_err(|e| {
        format!(
            "Cannot write temporary sudoers file {} for destination {}: {e}",
            temp_path.display(),
            sudoers_path
        )
    })?;
    f.sync_all().map_err(|e| {
        format!(
            "Cannot flush temporary sudoers file {} for destination {}: {e}",
            temp_path.display(),
            sudoers_path
        )
    })?;
    drop(f);

    let visudo_output = std::process::Command::new("/usr/sbin/visudo")
        .arg("-c")
        .arg("-f")
        .arg(&temp_path)
        .output()
        .map_err(|e| {
            format!(
                "Cannot execute 'visudo -c -f {}' while validating sudoers destination {}: {e}",
                temp_path.display(),
                sudoers_path
            )
        })?;
    if !visudo_output.status.success() {
        let stderr = String::from_utf8_lossy(&visudo_output.stderr)
            .trim()
            .to_string();
        let stdout = String::from_utf8_lossy(&visudo_output.stdout)
            .trim()
            .to_string();
        let mut command_output = String::new();
        if !stderr.is_empty() {
            command_output.push_str(&format!("stderr: {stderr}"));
        }
        if !stdout.is_empty() {
            if !command_output.is_empty() {
                command_output.push_str("; ");
            }
            command_output.push_str(&format!("stdout: {stdout}"));
        }
        if command_output.is_empty() {
            command_output = "no command output".to_string();
        }

        return Err(format!(
            "visudo validation failed for temporary sudoers file {} (target {}): {command_output}",
            temp_path.display(),
            sudoers_path
        ));
    }

    std::fs::rename(&temp_path, sudoers).map_err(|e| {
        format!(
            "Cannot atomically replace sudoers destination {} with temporary file {}: {e}",
            sudoers_path,
            temp_path.display()
        )
    })?;
    temp_cleanup_guard.disarm();

    println!("  Wrote sudoers drop-in: {sudoers_path}");
    Ok(())
}

pub(crate) fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    for path in paths {
        match std::process::Command::new("/usr/bin/chattr")
            .arg(flag)
            .arg("--")
            .arg(path)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => errors.push(format!("/usr/bin/chattr {flag} -- {path}: exited with {s}")),
            Err(e) => errors.push(format!("/usr/bin/chattr {flag} -- {path}: {e}")),
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_policy(path: &str, tools: &[(&str, &str)]) {
        let mut tools_json = String::from("{");
        for (i, (name, binary)) in tools.iter().enumerate() {
            if i > 0 {
                tools_json.push(',');
            }
            tools_json.push_str(&format!(
                r#""{name}":{{"real_binary":"{binary}","help_description":"{name}","parameters":{{}}}}"#
            ));
        }
        tools_json.push('}');
        let json = format!(r#"{{"version":"1.0","global_settings":{{}},"tools":{tools_json}}}"#);
        std::fs::write(path, json).unwrap();
    }

    #[test]
    fn test_sudoers_content_empty_tools_is_safe() {
        let content = generate_sudoers_content(&[]);
        assert!(content.contains("No tools authorized"));
        assert!(!content.contains("ALL ALL="));
    }

    #[test]
    fn test_sudoers_content_contains_required_sections() {
        let tools = vec!["apt".to_string()];
        let content = generate_sudoers_content(&tools);
        assert!(content.contains("Defaults secure_path="));
        assert!(content.contains("/usr/local/bin/apt"));
    }

    #[test]
    fn test_sudoers_content_with_dir_uses_custom_path() {
        let tools = vec!["apt".to_string(), "tail".to_string()];
        let content = generate_sudoers_content_with_dir(&tools, "/opt/bin");
        assert!(content.contains("/opt/bin/apt"));
        assert!(content.contains("/opt/bin/tail"));
        let apt_pos = content.find("/opt/bin/apt").unwrap();
        let tail_pos = content.find("/opt/bin/tail").unwrap();
        assert!(apt_pos < tail_pos, "tools must be alphabetically sorted");
    }

    #[test]
    fn test_install_symlinks_creates_links_in_custom_dir() {
        let dir = TempDir::new().unwrap();
        let (ok, errs) = install_symlinks_to(
            &["mytool".to_string()],
            "/nonexistent/target",
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
        assert_eq!(ok, vec!["mytool"]);
        let link = dir.path().join("mytool");
        assert!(
            link.exists() || std::fs::symlink_metadata(&link).is_ok(),
            "symlink should exist"
        );
        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_str().unwrap(), "/nonexistent/target");
    }

    #[test]
    fn test_install_symlinks_replaces_existing_symlink() {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("mytool");
        std::os::unix::fs::symlink("/old/target", &link).unwrap();

        let (ok, errs) = install_symlinks_to(
            &["mytool".to_string()],
            "/new/target",
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty());
        assert_eq!(ok, vec!["mytool"]);
        let new_target = std::fs::read_link(&link).unwrap();
        assert_eq!(new_target.to_str().unwrap(), "/new/target");
    }

    #[test]
    fn test_install_symlinks_backs_up_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("mytool");
        std::fs::write(&file_path, b"original binary").unwrap();

        let (ok, errs) = install_symlinks_to(
            &["mytool".to_string()],
            "/new/target",
            dir.path().to_str().unwrap(),
        );
        assert!(errs.is_empty(), "errors: {errs:?}");
        assert_eq!(ok, vec!["mytool"]);
        assert!(
            dir.path().join("mytool.bak").exists(),
            "backup should exist"
        );
        assert!(std::fs::symlink_metadata(dir.path().join("mytool")).is_ok());
    }

    #[test]
    fn test_install_symlinks_rejects_invalid_name() {
        let dir = TempDir::new().unwrap();
        let (ok, errs) = install_symlinks_to(
            &["bad/name".to_string()],
            "/target",
            dir.path().to_str().unwrap(),
        );
        assert!(ok.is_empty());
        assert!(!errs.is_empty());
        assert!(errs[0].contains("Invalid tool name"));
    }

    #[test]
    fn test_write_sudoers_file_to_creates_correct_content() {
        let dir = TempDir::new().unwrap();
        let sudoers = dir.path().join("sudoers");
        let tools = vec!["apt".to_string(), "docker".to_string()];
        write_sudoers_file_to(&tools, sudoers.to_str().unwrap(), "/usr/local/bin").unwrap();

        let content = std::fs::read_to_string(&sudoers).unwrap();
        assert!(content.contains("/usr/local/bin/apt"));
        assert!(content.contains("/usr/local/bin/docker"));
        assert!(content.contains("Defaults secure_path="));
    }

    #[test]
    fn test_write_sudoers_file_to_validation_failure_keeps_destination_and_cleans_temp() {
        let dir = TempDir::new().unwrap();
        let sudoers = dir.path().join("sudoers");
        std::fs::write(&sudoers, "ORIGINAL\n").unwrap();

        let err = write_sudoers_file_to(
            &["bad\ntool".to_string()],
            sudoers.to_str().unwrap(),
            "/usr/local/bin",
        )
        .expect_err("invalid sudoers content should fail visudo validation");
        assert!(
            err.contains("visudo validation failed"),
            "unexpected error: {err}"
        );

        let content_after = std::fs::read_to_string(&sudoers).unwrap();
        assert_eq!(content_after, "ORIGINAL\n");
        assert!(
            !dir.path().join("sudoers.tmp").exists(),
            "temporary file should be removed after validation failure"
        );
    }

    struct TestEnv {
        _root: TempDir,
        pub policy_path: String,
        pub sudoers_path: String,
        pub symlink_dir: String,
    }

    impl TestEnv {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let symlink_dir = root.path().join("bin");
            std::fs::create_dir(&symlink_dir).unwrap();
            let sudoers_dir = root.path().join("sudoers.d");
            std::fs::create_dir(&sudoers_dir).unwrap();
            let policy_path = root.path().join("policy.json");
            let sudoers_path = sudoers_dir.join("secure-sudoers");

            Self {
                _root: root,
                policy_path: policy_path.to_str().unwrap().to_string(),
                sudoers_path: sudoers_path.to_str().unwrap().to_string(),
                symlink_dir: symlink_dir.to_str().unwrap().to_string(),
            }
        }

        fn paths(&self) -> InstallPaths<'_> {
            InstallPaths {
                policy_path: &self.policy_path,
                binary: "/nonexistent/secure-sudoers",
                utils_binary: "/nonexistent/secure-sudoers-utils",
                sudoers_path: &self.sudoers_path,
                symlink_dir: &self.symlink_dir,
            }
        }
    }

    #[test]
    fn test_install_with_paths_full_flow() {
        let env = TestEnv::new();
        write_policy(&env.policy_path, &[("apt", "/usr/bin/apt")]);
        install_with_paths(&env.paths()).unwrap();

        let link = std::path::Path::new(&env.symlink_dir).join("apt");
        assert!(std::fs::symlink_metadata(&link).is_ok());
        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_str().unwrap(), "/nonexistent/secure-sudoers");

        let content = std::fs::read_to_string(&env.sudoers_path).unwrap();
        assert!(content.contains(&format!("{}/apt", env.symlink_dir)));
        assert!(content.contains("Defaults secure_path="));
    }

    #[test]
    fn test_unlock_with_paths_runs_without_error_on_valid_policy() {
        let env = TestEnv::new();
        write_policy(&env.policy_path, &[("tail", "/usr/bin/tail")]);
        let _ = unlock_with_paths(&env.paths());
    }

    #[test]
    fn test_chattr_op_handles_missing_binary() {
        let errors = chattr_op("+i", &["/tmp/nonexistent_secure_sudoers_test_file"]);
        let _ = errors;
    }
}

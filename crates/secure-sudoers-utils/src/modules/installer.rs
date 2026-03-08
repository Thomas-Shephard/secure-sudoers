use secure_sudoers_common::models::SecureSudoersPolicy;

pub const INSTALL_POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";
pub const INSTALL_BINARY: &str = "/usr/local/bin/secure-sudoers";
pub const INSTALL_UTILS_BINARY: &str = "/usr/local/bin/secure-sudoers-utils";
pub const INSTALL_SUDOERS_PATH: &str = "/etc/sudoers.d/secure-sudoers";
pub const SYMLINK_DIR: &str = "/usr/local/bin";

pub fn cmd_install() -> Result<(), String> {
    install()
}

pub fn cmd_unlock() -> Result<(), String> {
    unlock()
}

pub fn generate_sudoers_content(tools: &[String]) -> String {
    let mut sorted: Vec<&str> = tools.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let paths: Vec<String> = sorted.iter().map(|t| format!("{SYMLINK_DIR}/{t}")).collect();
    format!(
        "# Managed by secure-sudoers-utils - do not edit manually.\n\
         Defaults secure_path=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
         ALL ALL=(root) {}\n",
        paths.join(", ")
    )
}

fn require_root() -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 {
        return Err("Root privileges required.".to_string());
    }
    Ok(())
}

fn load_policy(path: &str) -> Result<SecureSudoersPolicy, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    serde_json::from_str(&src).map_err(|e| format!("Invalid policy JSON at {path}: {e}"))
}

fn install() -> Result<(), String> {
    require_root()?;
    let policy = load_policy(INSTALL_POLICY_PATH)?;
    policy.validate().map_err(|e| format!("Policy validation failed: {e}"))?;

    let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
    tool_names.sort_unstable();
    println!("Installing {} tool(s)...", tool_names.len());

    let (successful_tools, symlink_errors) = install_symlinks(&tool_names, INSTALL_BINARY);
    write_sudoers_file(&successful_tools)?;

    let mut targets: Vec<String> = vec![
        INSTALL_BINARY.to_string(), INSTALL_UTILS_BINARY.to_string(),
        INSTALL_POLICY_PATH.to_string(), INSTALL_SUDOERS_PATH.to_string(),
    ];
    targets.extend(successful_tools.iter().map(|t| format!("{SYMLINK_DIR}/{t}")));
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    for e in chattr_op("+i", &refs) {
        eprintln!("Warning: chattr +i failed: {e}");
    }

    println!("Installation complete.");
    if !symlink_errors.is_empty() {
        return Err(format!("Installation completed with symlink errors:\n{}", symlink_errors.join("\n")));
    }
    Ok(())
}

fn unlock() -> Result<(), String> {
    require_root()?;
    let policy = load_policy(INSTALL_POLICY_PATH)?;
    let _ = policy.validate();

    let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
    tool_names.sort_unstable();
    let mut targets: Vec<String> = vec![
        INSTALL_BINARY.to_string(), INSTALL_UTILS_BINARY.to_string(),
        INSTALL_POLICY_PATH.to_string(), INSTALL_SUDOERS_PATH.to_string(),
    ];
    targets.extend(tool_names.iter().map(|t| format!("{SYMLINK_DIR}/{t}")));
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    let errors = chattr_op("-i", &refs);
    for e in &errors {
        eprintln!("Warning: chattr -i failed: {e}");
    }
    println!("Unlocked {} managed file(s).", refs.len());
    if !errors.is_empty() {
        return Err(format!("Some files could not be unlocked:\n{}", errors.join("\n")));
    }
    Ok(())
}

fn install_symlinks(tools: &[String], binary: &str) -> (Vec<String>, Vec<String>) {
    let mut successful = Vec::new();
    let mut errors = Vec::new();
    for tool in tools {
        if !secure_sudoers_common::models::is_valid_tool_name(tool) {
            errors.push(format!("Invalid tool name '{tool}'"));
            continue;
        }
        let link_path = std::path::Path::new(SYMLINK_DIR).join(tool);
        let mut skip = false;
        match std::fs::symlink_metadata(&link_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    if let Err(e) = std::fs::remove_file(&link_path) {
                        errors.push(format!("Cannot remove old symlink {}: {e}", link_path.display()));
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
                    errors.push(format!("Skipping {}: not a regular file or symlink", link_path.display()));
                    skip = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                errors.push(format!("Cannot stat {}: {e}", link_path.display()));
                skip = true;
            }
        }
        if skip { continue; }

        match std::os::unix::fs::symlink(binary, &link_path) {
            Ok(()) => {
                println!("  Symlinked {} -> {binary}", link_path.display());
                successful.push(tool.clone());
            }
            Err(e) => errors.push(format!("Cannot create symlink {} -> {binary}: {e}", link_path.display())),
        }
    }
    (successful, errors)
}

fn write_sudoers_file(tools: &[String]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let content = generate_sudoers_content(tools);
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o440)
        .custom_flags(libc::O_NOFOLLOW)
        .open(INSTALL_SUDOERS_PATH).map_err(|e| format!("Cannot create {INSTALL_SUDOERS_PATH}: {e}"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("Cannot write {INSTALL_SUDOERS_PATH}: {e}"))?;
    println!("  Wrote sudoers drop-in: {INSTALL_SUDOERS_PATH}");
    Ok(())
}

fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    for path in paths {
        match std::process::Command::new("chattr").arg(flag).arg(path).status() {
            Ok(s) if s.success() => {}
            Ok(s) => errors.push(format!("chattr {flag} {path}: exited with {s}")),
            Err(e) => errors.push(format!("chattr {flag} {path}: {e}")),
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sudoers_content_contains_required_sections() {
        let tools = vec!["apt".to_string()];
        let content = generate_sudoers_content(&tools);
        assert!(content.contains("Defaults secure_path="));
        assert!(content.contains("/usr/local/bin/apt"));
    }
}

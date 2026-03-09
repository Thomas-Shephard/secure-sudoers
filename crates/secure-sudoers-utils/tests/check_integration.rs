use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_check_command_on_valid_policy() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.json");

    let dummy_binary = dir.path().join("dummy_bin");
    std::fs::write(&dummy_binary, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dummy_binary).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dummy_binary, perms).unwrap();
    }

    let policy_json = format!(
        r#"{{
        "version": "1.0",
        "serial": 1,
        "global_settings": {{
            "admin_contact": "admin@example.com",
            "blocked_paths": ["/etc/shadow"]
        }},
        "tools": {{
            "test": {{
                "real_binary": "{}",
                "help_description": "A test tool",
                "positional": {{ "type": "string" }}
            }}
        }}
    }}"#,
        dummy_binary.to_str().unwrap()
    );

    std::fs::write(&policy_path, policy_json).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "secure-sudoers-utils",
            "--",
            "check",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute command");

    assert!(
        output.status.success(),
        "check command should succeed for valid policy. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("is valid"));
}

#[test]
fn test_check_command_on_invalid_policy_missing_binary() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.json");

    let policy_json = r#"{
        "version": "1.0",
        "serial": 1,
        "global_settings": {
            "admin_contact": "admin@example.com",
            "blocked_paths": ["/etc/shadow"]
        },
        "tools": {
            "test": {
                "real_binary": "/nonexistent/binary/path",
                "help_description": "A test tool",
                "positional": { "type": "string" }
            }
        }
    }"#;

    std::fs::write(&policy_path, policy_json).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "secure-sudoers-utils",
            "--",
            "check",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute command");

    assert!(
        !output.status.success(),
        "check command should fail for policy with missing binary"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not exist on the filesystem"));
}

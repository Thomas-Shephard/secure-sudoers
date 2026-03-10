use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::validate_command;

#[test]
fn test_policy_parsing_and_validation() {
    let ls_bin = std::fs::canonicalize("/bin/ls").unwrap_or_else(|_| "/usr/bin/ls".into());
    let ls_bin_str = ls_bin.to_str().unwrap();

    let json = format!(
        r#"{{
        "version": "1.0",
        "serial": 100,
        "global_settings": {{
            "admin_contact": "security@example.com",
            "blocked_paths": ["/etc/shadow", "/root"]
        }},
        "tools": {{
            "ls": {{
                "real_binary": "{}",
                "help_description": "List files",
                "parameters": {{
                    "-l": {{ "type": "bool" }},
                    "-a": {{ "type": "bool" }}
                }}
            }}
        }}
    }}"#,
        ls_bin_str
    );

    let policy_res: Result<SecureSudoersPolicy, _> = serde_json::from_str(&json);
    let mut policy = policy_res.expect("Failed to parse policy JSON");
    policy.validate().unwrap();

    let args = vec!["-l".to_string(), "/tmp".to_string()];
    let cmd = validate_command(&policy, "ls", args).unwrap();

    assert_eq!(cmd.binary().path, ls_bin_str);

    let arg_strs: Vec<String> = cmd.args().iter().map(|a| a.as_str().to_string()).collect();
    assert_eq!(arg_strs, vec!["-l", "/tmp"]);
}

#[test]
fn test_policy_rejects_blocked_path() {
    let cat_bin = std::fs::canonicalize("/bin/cat").unwrap_or_else(|_| "/usr/bin/cat".into());
    let cat_bin_str = cat_bin.to_str().unwrap();

    let json = format!(
        r#"{{
        "version": "1.0",
        "global_settings": {{ "blocked_paths": ["/etc/shadow"] }},
        "tools": {{
            "cat": {{
                "real_binary": "{}",
                "help_description": "Read files",
                "positional": {{ "type": "path" }}
            }}
        }}
    }}"#,
        cat_bin_str
    );
    let mut policy: SecureSudoersPolicy = serde_json::from_str(&json).unwrap();
    policy.validate().unwrap();

    let args = vec!["/etc/shadow".to_string()];
    assert!(validate_command(&policy, "cat", args).is_err());
}

#[test]
fn test_policy_enforces_flag_rules() {
    let json = r#"{
        "version": "1.0",
        "global_settings": {},
        "tools": {
            "service": {
                "real_binary": "/usr/sbin/service",
                "help_description": "Manage services",
                "parameters": {
                    "--action": {
                        "type": "string",
                        "choices": ["start", "stop"]
                    }
                }
            }
        }
    }"#;
    let mut policy: SecureSudoersPolicy = serde_json::from_str(json).unwrap();
    policy.validate().unwrap();

    assert!(
        validate_command(
            &policy,
            "service",
            vec!["--action".to_string(), "start".to_string()]
        )
        .is_ok()
    );
    assert!(
        validate_command(
            &policy,
            "service",
            vec!["--action".to_string(), "restart".to_string()]
        )
        .is_err()
    );
}

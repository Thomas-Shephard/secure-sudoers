use secure_sudoers_common::models::SecureSudoersPolicy;
use secure_sudoers_common::validator::validate_command;

#[test]
fn test_policy_parsing_and_validation() {
    let json = r#"{
        "version": "1.0",
        "serial": 100,
        "global_settings": {
            "admin_contact": "security@example.com",
            "blocked_paths": ["/etc/shadow", "/root"]
        },
        "tools": {
            "ls": {
                "real_binary": "/bin/ls",
                "help_description": "List files",
                "flags": ["-l", "-a"]
            }
        }
    }"#;

    let policy: SecureSudoersPolicy = serde_json::from_str(json).unwrap();
    policy.validate().unwrap();

    let args = vec!["-l".to_string(), "/tmp".to_string()];
    let cmd = validate_command(&policy, "ls", args).unwrap();
    assert_eq!(cmd.binary(), "/bin/ls");
    assert_eq!(cmd.args(), &["-l", "/tmp"]);
}

#[test]
fn test_policy_rejects_blocked_path() {
    let json = r#"{
        "version": "1.0",
        "global_settings": { "blocked_paths": ["/etc/shadow"] },
        "tools": {
            "cat": {
                "real_binary": "/bin/cat",
                "help_description": "Read files",
                "validate_positional_args_as_paths": true
            }
        }
    }"#;
    let policy: SecureSudoersPolicy = serde_json::from_str(json).unwrap();
    
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
                "flag_rules": {
                    "--action": ["start", "stop"]
                }
            }
        }
    }"#;
    let policy: SecureSudoersPolicy = serde_json::from_str(json).unwrap();

    assert!(validate_command(&policy, "service", vec!["--action".to_string(), "start".to_string()]).is_ok());
    assert!(validate_command(&policy, "service", vec!["--action".to_string(), "restart".to_string()]).is_err());
}

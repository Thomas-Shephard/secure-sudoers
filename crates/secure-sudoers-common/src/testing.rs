#[cfg(feature = "testing")]
pub mod fixtures {
    use crate::models::{GlobalSettings, IsolationSettings, SecureSudoersPolicy, ToolPolicy};
    use std::collections::HashMap;

    pub fn make_policy() -> SecureSudoersPolicy {
        let mut tools = HashMap::new();
        tools.insert("tail".to_string(), ToolPolicy {
            real_binary: "/usr/bin/tail".to_string(),
            verbs: vec![],
            flags: vec!["-v".to_string(), "-q".to_string(), "-f".to_string()],
            flags_with_args: vec!["-n".to_string(), "-c".to_string()],
            flags_with_path_args: vec![],
            disallowed_positional_args: vec![],
            validate_positional_args_as_paths: true,
            sensitive_flags: vec![],
            help_description: "tail".to_string(),
            isolation: None,
            env_whitelist: vec![],
            flag_rules: HashMap::new(),
        });
        tools.insert("apt".to_string(), ToolPolicy {
            real_binary: "/usr/bin/apt".to_string(),
            verbs: vec!["update".to_string(), "install".to_string()],
            flags: vec!["-y".to_string(), "-a".to_string()],
            flags_with_args: vec![],
            flags_with_path_args: vec![],
            disallowed_positional_args: vec![],
            validate_positional_args_as_paths: false,
            sensitive_flags: vec![],
            help_description: "apt".to_string(),
            isolation: Some(IsolationSettings { unshare_network: false, unshare_pid: false, ..IsolationSettings::default() }),
            env_whitelist: vec![],
            flag_rules: HashMap::new(),
        });

        SecureSudoersPolicy {
            version: "1.0".to_string(),
            serial: 1,
            global_settings: GlobalSettings {
                log_destination: "syslog".to_string(),
                log_format: "text".to_string(),
                admin_contact: "Please contact your administrator.".to_string(),
                safe_arg_regex: r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string(),
                common_env_whitelist: vec![],
                dry_run: false,
                blocked_paths: vec!["/etc/shadow".to_string(), "/root".to_string()],
                bypass_groups: vec!["sudo".to_string()],
                default_isolation: None,
            },
            tools,
        }
    }

    pub fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
}

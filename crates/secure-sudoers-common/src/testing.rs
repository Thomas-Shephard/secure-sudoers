#[cfg(feature = "testing")]
pub mod fixtures {
    use crate::models::{
        GlobalSettings, IsolationSettings, ParameterConfig, SecureSudoersPolicy, ToolPolicy,
        UnauthorizedAuditMode,
    };
    use std::collections::HashMap;

    pub fn make_policy() -> SecureSudoersPolicy {
        let mut tools = HashMap::new();
        let mut tail_params = HashMap::new();
        tail_params.insert("-v".to_string(), ParameterConfig::bool());
        tail_params.insert("-q".to_string(), ParameterConfig::bool());
        tail_params.insert("-f".to_string(), ParameterConfig::bool());
        tail_params.insert("-n".to_string(), ParameterConfig::string());
        tail_params.insert("-c".to_string(), ParameterConfig::string());

        tools.insert(
            "tail".to_string(),
            ToolPolicy {
                real_binary: "/usr/bin/tail".to_string(),
                verbs: vec![],
                parameters: tail_params,
                disallowed_positional_args: vec![],
                positional: Some(ParameterConfig::path()),
                help_description: "tail".to_string(),
                isolation: None,
                env_whitelist: vec![],
            },
        );

        let mut apt_params = HashMap::new();
        apt_params.insert("-y".to_string(), ParameterConfig::bool());
        apt_params.insert("-a".to_string(), ParameterConfig::bool());

        tools.insert(
            "apt".to_string(),
            ToolPolicy {
                real_binary: "/usr/bin/apt".to_string(),
                verbs: vec!["update".to_string(), "install".to_string()],
                parameters: apt_params,
                disallowed_positional_args: vec![],
                positional: None,
                help_description: "apt".to_string(),
                isolation: Some(IsolationSettings {
                    unshare_network: false,
                    unshare_pid: false,
                    ..IsolationSettings::default()
                }),
                env_whitelist: vec![],
            },
        );

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
                unauthorized_audit_mode: UnauthorizedAuditMode::Minimal,
                default_isolation: None,
            },
            tools,
        }
    }

    pub fn make_valid_policy() -> SecureSudoersPolicy {
        SecureSudoersPolicy {
            version: "1.0".to_string(),
            serial: 1,
            global_settings: GlobalSettings {
                log_destination: "syslog".to_string(),
                log_format: "text".to_string(),
                admin_contact: "contact admin".to_string(),
                safe_arg_regex: r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string(),
                common_env_whitelist: vec![],
                dry_run: false,
                blocked_paths: vec!["/etc/shadow".to_string()],
                bypass_groups: vec![],
                unauthorized_audit_mode: UnauthorizedAuditMode::Minimal,
                default_isolation: None,
            },
            tools: HashMap::new(),
        }
    }

    pub fn make_tool(real_binary: &str) -> ToolPolicy {
        ToolPolicy {
            real_binary: real_binary.to_string(),
            verbs: vec![],
            parameters: HashMap::new(),
            disallowed_positional_args: vec![],
            positional: Some(ParameterConfig::path()),
            help_description: "test tool".to_string(),
            isolation: None,
            env_whitelist: vec![],
        }
    }

    pub fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
}

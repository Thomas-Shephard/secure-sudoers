#[cfg(any(feature = "testing", test))]
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

        let tail_bin =
            std::fs::canonicalize("/usr/bin/tail").unwrap_or_else(|_| "/bin/tail".into());
        let tail_bin_str = tail_bin.to_str().unwrap().to_string();

        tools.insert(
            "tail".to_string(),
            ToolPolicy {
                id: None,
                real_binary: tail_bin_str,
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

        let apt_bin = std::fs::canonicalize("/usr/bin/apt").unwrap_or_else(|_| "/bin/apt".into());
        let apt_bin_str = apt_bin.to_str().unwrap().to_string();

        tools.insert(
            "apt".to_string(),
            ToolPolicy {
                id: None,
                real_binary: apt_bin_str,
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
                blocked_paths: vec!["/etc/shadow".to_string(), "/root".to_string()],
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
                blocked_paths: vec!["/etc/shadow".to_string()],
                unauthorized_audit_mode: UnauthorizedAuditMode::Minimal,
                default_isolation: None,
            },
            tools: HashMap::new(),
        }
    }

    pub fn make_tool(real_binary: &str) -> ToolPolicy {
        ToolPolicy {
            id: None,
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

    pub fn open_path(p: &str) -> crate::models::SecurePath {
        use std::os::fd::{FromRawFd, OwnedFd};
        let c_path = std::ffi::CString::new(p).unwrap();
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            panic!("failed to open {}: {}", p, std::io::Error::last_os_error());
        }
        crate::models::SecurePath::new_for_testing(p, unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

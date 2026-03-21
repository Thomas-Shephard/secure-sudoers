use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::fd::OwnedFd;

pub struct SecurePath {
    pub path: String,
    pub fd: OwnedFd,
}

impl PartialEq for SecurePath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl PartialEq<str> for SecurePath {
    fn eq(&self, other: &str) -> bool {
        self.path == other
    }
}

impl PartialEq<&str> for SecurePath {
    fn eq(&self, other: &&str) -> bool {
        self.path == *other
    }
}

impl PartialEq<String> for SecurePath {
    fn eq(&self, other: &String) -> bool {
        self.path == *other
    }
}

impl SecurePath {
    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_testing(path: &str, fd: OwnedFd) -> Self {
        Self {
            path: path.to_string(),
            fd,
        }
    }
}

impl std::fmt::Debug for SecurePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurePath")
            .field("path", &self.path)
            .field("fd", &self.fd)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    Bool,
    String,
    Path,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterConfig {
    #[serde(rename = "type")]
    pub param_type: ParameterType,
    #[serde(default)]
    pub sensitive: bool,
    pub regex: Option<String>,
    pub choices: Option<Vec<String>>,
    pub help: Option<String>,
}

impl ParameterConfig {
    pub fn matches(&self, val: &str) -> bool {
        if let Some(ref choices) = self.choices
            && !choices.contains(&val.to_string())
        {
            return false;
        }
        if let Some(ref regex_str) = self.regex {
            if let Ok(re) = regex::Regex::new(regex_str) {
                if !re.is_match(val) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    pub fn any(t: ParameterType) -> Self {
        Self {
            param_type: t,
            sensitive: false,
            regex: None,
            choices: None,
            help: None,
        }
    }

    pub fn bool() -> Self {
        Self::any(ParameterType::Bool)
    }

    pub fn string() -> Self {
        Self::any(ParameterType::String)
    }

    pub fn path() -> Self {
        Self::any(ParameterType::Path)
    }

    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    pub fn regex(mut self, r: String) -> Self {
        self.regex = Some(r);
        self
    }

    pub fn choices(mut self, c: Vec<String>) -> Self {
        self.choices = Some(c);
        self
    }
}

fn default_unshare_ipc() -> bool {
    true
}
fn default_unshare_uts() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationSettings {
    #[serde(default)]
    pub unshare_network: bool,
    #[serde(default)]
    pub unshare_pid: bool,
    #[serde(default = "default_unshare_ipc")]
    pub unshare_ipc: bool,
    #[serde(default = "default_unshare_uts")]
    pub unshare_uts: bool,
    #[serde(default)]
    pub private_mounts: Vec<String>,
    #[serde(default)]
    pub readonly_mounts: Vec<String>,
}

impl Default for IsolationSettings {
    fn default() -> Self {
        IsolationSettings {
            unshare_network: false,
            unshare_pid: false,
            unshare_ipc: true,
            unshare_uts: true,
            private_mounts: Vec::new(),
            readonly_mounts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    #[serde(default)]
    pub id: Option<String>,
    pub real_binary: String,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default)]
    pub parameters: HashMap<String, ParameterConfig>,
    #[serde(default)]
    pub disallowed_positional_args: Vec<String>,
    pub positional: Option<ParameterConfig>,
    pub help_description: String,
    pub isolation: Option<IsolationSettings>,
    #[serde(default)]
    pub env_whitelist: Vec<String>,
}

fn default_log_destination() -> String {
    "syslog".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_admin_contact() -> String {
    "Please contact your administrator.".to_string()
}
fn default_safe_arg_regex() -> String {
    r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string()
}
fn default_common_env_whitelist() -> Vec<String> {
    vec![
        "TERM".to_string(),
        "LANG".to_string(),
        "LC_ALL".to_string(),
        "LS_COLORS".to_string(),
    ]
}
fn default_blocked_paths() -> Vec<String> {
    vec![
        "/etc/shadow".to_string(),
        "/etc/gshadow".to_string(),
        "/etc/sudoers".to_string(),
        "/etc/secure-sudoers".to_string(),
        "/etc/ssh".to_string(),
        "/etc/pam.d".to_string(),
        "/root".to_string(),
        "/dev/mem".to_string(),
        "/dev/kmem".to_string(),
        "/dev/port".to_string(),
        "/proc/kcore".to_string(),
    ]
}
fn default_bypass_groups() -> Vec<String> {
    vec!["sudo".to_string(), "wheel".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnauthorizedAuditMode {
    #[default]
    Minimal,
    KeysOnly,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalSettings {
    #[serde(default = "default_log_destination")]
    pub log_destination: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_admin_contact")]
    pub admin_contact: String,
    #[serde(default = "default_safe_arg_regex")]
    pub safe_arg_regex: String,
    #[serde(default = "default_common_env_whitelist")]
    pub common_env_whitelist: Vec<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_blocked_paths")]
    pub blocked_paths: Vec<String>,
    #[serde(default = "default_bypass_groups")]
    pub bypass_groups: Vec<String>,
    #[serde(default)]
    pub unauthorized_audit_mode: UnauthorizedAuditMode,
    pub default_isolation: Option<IsolationSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureSudoersPolicy {
    pub version: String,
    #[serde(default)]
    pub serial: i32,
    pub global_settings: GlobalSettings,
    pub tools: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationContext {
    Positional,
    DelimitedPositional,
    Flag(String),
}

impl std::fmt::Display for ValidationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationContext::Positional => write!(f, "positional"),
            ValidationContext::DelimitedPositional => write!(f, "delimited positional"),
            ValidationContext::Flag(s) => write!(f, "flag '{}'", s),
        }
    }
}

pub fn is_valid_tool_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }

    match regex::Regex::new(r"^[a-zA-Z0-9._+-]+$") {
        Ok(re) => re.is_match(name),
        Err(_) => false,
    }
}

impl SecureSudoersPolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        if regex::Regex::new(&self.global_settings.safe_arg_regex).is_err() {
            return Err("Invalid regex in safe_arg_regex".to_string());
        }

        let mut canonicalized_blocked = Vec::new();
        for path in &self.global_settings.blocked_paths {
            if !path.starts_with('/') {
                return Err(format!("Blocked path must be absolute: {}", path));
            }
            match std::fs::canonicalize(path) {
                Ok(p) => canonicalized_blocked.push(p.to_string_lossy().into_owned()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    canonicalized_blocked.push(path.clone());
                }
                Err(e) => {
                    return Err(format!(
                        "Security failure: cannot canonicalize blocked path '{}': {}",
                        path, e
                    ));
                }
            }
        }
        self.global_settings.blocked_paths = canonicalized_blocked;

        for (name, tool) in &self.tools {
            if !is_valid_tool_name(name) {
                return Err(format!("Invalid tool name in policy: '{}'", name));
            }
            if !tool.real_binary.starts_with('/') {
                return Err(format!(
                    "real_binary for tool '{}' must be an absolute path",
                    name
                ));
            }
            for (flag, config) in &tool.parameters {
                if let Some(ref regex_str) = config.regex
                    && regex::Regex::new(regex_str).is_err()
                {
                    return Err(format!(
                        "Invalid regex '{}' in parameter '{}' for tool '{}'",
                        regex_str, flag, name
                    ));
                }
            }
            if let Some(ref pos_config) = tool.positional
                && let Some(ref regex_str) = pos_config.regex
                && regex::Regex::new(regex_str).is_err()
            {
                return Err(format!(
                    "Invalid regex '{}' in positional config for tool '{}'",
                    regex_str, name
                ));
            }
        }
        Ok(())
    }

    pub fn lint(&mut self) -> Vec<String> {
        let mut results = Vec::new();

        if let Err(e) = self.validate() {
            results.push(format!("Validation failed: {}", e));
            return results;
        }

        for (name, tool) in &self.tools {
            let path = std::path::Path::new(&tool.real_binary);
            if !path.exists() {
                results.push(format!(
                    "Tool '{}': real_binary '{}' does not exist on the filesystem",
                    name, tool.real_binary
                ));
            } else if !path.is_file() {
                results.push(format!(
                    "Tool '{}': real_binary '{}' exists but is not a file",
                    name, tool.real_binary
                ));
            } else {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = path.metadata()
                    && metadata.permissions().mode() & 0o111 == 0
                {
                    results.push(format!(
                        "Tool '{}': real_binary '{}' exists but is not executable",
                        name, tool.real_binary
                    ));
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_field_in_policy_rejected() {
        let json = r#"{ "version": "1.0", "global_settings": {}, "tools": {}, "surprise": "X" }"#;
        assert!(serde_json::from_str::<SecureSudoersPolicy>(json).is_err());
    }

    #[test]
    fn test_typo_in_isolation_settings_rejected() {
        let json = r#"{ "version": "1.0", "global_settings": {}, "tools": { "apt": { "real_binary": "/usr/bin/apt", "help_description": "x", "isolation": { "unshare_netwrk": true } } } }"#;
        assert!(serde_json::from_str::<SecureSudoersPolicy>(json).is_err());
    }

    #[test]
    fn test_is_valid_tool_name() {
        assert!(is_valid_tool_name("apt"));
        assert!(is_valid_tool_name("docker-compose"));
        assert!(is_valid_tool_name("my_tool"));
        assert!(is_valid_tool_name("tool123"));
        assert!(is_valid_tool_name("a"));
        assert!(is_valid_tool_name("g++"));

        assert!(!is_valid_tool_name(""), "empty string should be invalid");
        assert!(!is_valid_tool_name("."), ". should be invalid");
        assert!(!is_valid_tool_name(".."), ".. should be invalid");
        assert!(!is_valid_tool_name("my/tool"), "slash should be invalid");
        assert!(
            !is_valid_tool_name("tool\0name"),
            "null byte should be invalid"
        );
        assert!(!is_valid_tool_name("tool,name"), "comma should be invalid");
        assert!(!is_valid_tool_name("tool name"), "space should be invalid");
        assert!(!is_valid_tool_name("tool\ttab"), "tab should be invalid");
        assert!(
            !is_valid_tool_name("tool\nnewline"),
            "newline should be invalid"
        );

        assert!(!is_valid_tool_name("tool*"));
        assert!(!is_valid_tool_name("tool?"));
        assert!(!is_valid_tool_name("tool["));
        assert!(!is_valid_tool_name("tool]"));
    }

    #[test]
    fn test_parameter_config_matches_choices() {
        let config = ParameterConfig {
            param_type: ParameterType::String,
            sensitive: false,
            regex: None,
            choices: Some(vec!["prod".into(), "stage".into()]),
            help: None,
        };
        assert!(config.matches("prod"));
        assert!(config.matches("stage"));
        assert!(!config.matches("dev"));
    }

    #[test]
    fn test_parameter_config_matches_regex() {
        let config = ParameterConfig {
            param_type: ParameterType::String,
            sensitive: false,
            regex: Some(r"^\d+$".into()),
            choices: None,
            help: None,
        };
        assert!(config.matches("123"));
        assert!(!config.matches("abc"));
    }

    use crate::testing::fixtures::{make_tool, make_valid_policy};

    #[test]
    fn test_policy_validate_ok() {
        let mut p = make_valid_policy();
        assert!(
            p.validate().is_ok(),
            "baseline valid policy must pass validation"
        );
    }

    #[test]
    fn test_policy_validate_invalid_safe_arg_regex() {
        let mut p = make_valid_policy();
        p.global_settings.safe_arg_regex = "[unclosed bracket".to_string();
        let err = p.validate().unwrap_err();
        assert!(
            err.contains("Invalid regex in safe_arg_regex"),
            "got: {err}"
        );
    }

    #[test]
    fn test_policy_validate_relative_blocked_path() {
        let mut p = make_valid_policy();
        p.global_settings.blocked_paths = vec!["etc/shadow".to_string()];
        let err = p.validate().unwrap_err();
        assert!(err.contains("Blocked path must be absolute"), "got: {err}");
    }

    #[test]
    fn test_policy_validate_invalid_tool_name() {
        let mut p = make_valid_policy();
        p.tools
            .insert("bad/name".to_string(), make_tool("/usr/bin/tool"));
        let err = p.validate().unwrap_err();
        assert!(err.contains("Invalid tool name"), "got: {err}");
    }

    #[test]
    fn test_policy_validate_relative_real_binary() {
        let mut p = make_valid_policy();
        p.tools.insert("mytool".to_string(), make_tool("bin/ls"));
        let err = p.validate().unwrap_err();
        assert!(err.contains("must be an absolute path"), "got: {err}");
    }

    #[test]
    fn test_policy_validate_invalid_parameter_regex() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.parameters.insert(
            "--format".to_string(),
            ParameterConfig {
                param_type: ParameterType::String,
                sensitive: false,
                regex: Some("[unclosed".to_string()),
                choices: None,
                help: None,
            },
        );
        p.tools.insert("mytool".to_string(), tool);
        let err = p.validate().unwrap_err();
        assert!(err.contains("Invalid regex"), "got: {err}");
    }
}

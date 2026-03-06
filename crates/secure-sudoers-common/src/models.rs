use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagRule {
    List(Vec<FlagRule>),
    Regex { regex: String },
    Constant(String),
}

impl FlagRule {
    pub fn matches(&self, arg: &str) -> bool {
        match self {
            FlagRule::List(rules) => rules.iter().any(|r| r.matches(arg)),
            FlagRule::Regex { regex } => regex::Regex::new(regex)
                .map(|re| re.is_match(arg))
                .unwrap_or(false),
            FlagRule::Constant(s) => s == "any" || s == arg,
        }
    }

    pub(crate) fn collect_regexes<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            FlagRule::List(rules) => rules.iter().for_each(|r| r.collect_regexes(out)),
            FlagRule::Regex { regex } => out.push(regex.as_str()),
            FlagRule::Constant(_) => {}
        }
    }
}

fn default_unshare_ipc() -> bool {
    true
}
fn default_unshare_uts() -> bool {
    true
}
fn default_true() -> bool {
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
    pub real_binary: String,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub flags_with_args: Vec<String>,
    #[serde(default)]
    pub flags_with_path_args: Vec<String>,
    #[serde(default)]
    pub disallowed_positional_args: Vec<String>,
    #[serde(default = "default_true")]
    pub validate_positional_args_as_paths: bool,
    pub help_description: String,
    pub isolation: Option<IsolationSettings>,
    #[serde(default)]
    pub env_whitelist: Vec<String>,
    #[serde(default)]
    pub sensitive_flags: Vec<String>,
    #[serde(default)]
    pub flag_rules: HashMap<String, FlagRule>,
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
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.contains(',')
        || name.chars().any(|c| c.is_whitespace()))
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
            for (flag, rule) in &tool.flag_rules {
                let mut patterns: Vec<&str> = Vec::new();
                rule.collect_regexes(&mut patterns);
                for pattern in patterns {
                    if regex::Regex::new(pattern).is_err() {
                        return Err(format!(
                            "Invalid regex '{}' in flag_rules['{}'] for tool '{}'",
                            pattern, flag, name
                        ));
                    }
                }
            }
        }
        Ok(())
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
    }

    #[test]
    fn test_flag_rule_matches_constant() {
        let rule = FlagRule::Constant("debug".to_string());
        assert!(rule.matches("debug"), "exact match should succeed");
        assert!(!rule.matches("any"), "non-matching value should fail");
        assert!(!rule.matches("release"), "non-matching value should fail");
        assert!(!rule.matches(""), "empty string should fail");

        let any_rule = FlagRule::Constant("any".to_string());
        assert!(
            any_rule.matches("debug"),
            "'any' rule must match arbitrary args"
        );
        assert!(
            any_rule.matches("release"),
            "'any' rule must match arbitrary args"
        );
        assert!(any_rule.matches(""), "'any' rule must match empty arg");
    }

    #[test]
    fn test_flag_rule_matches_list() {
        let rule = FlagRule::List(vec![
            FlagRule::Constant("one".to_string()),
            FlagRule::Constant("two".to_string()),
        ]);
        assert!(rule.matches("one"));
        assert!(rule.matches("two"));
        assert!(!rule.matches("three"));
        assert!(!rule.matches(""));
    }

    #[test]
    fn test_flag_rule_matches_regex() {
        let rule = FlagRule::Regex {
            regex: r"^\d+$".to_string(),
        };
        assert!(rule.matches("123"));
        assert!(rule.matches("0"));
        assert!(!rule.matches("abc"));
        assert!(!rule.matches("12a"));
        assert!(!rule.matches(""));
    }

    #[test]
    fn test_flag_rule_matches_invalid_regex_returns_false() {
        let rule = FlagRule::Regex {
            regex: "[unclosed".to_string(),
        };
        assert!(
            !rule.matches("anything"),
            "invalid regex should return false, not panic"
        );
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
    fn test_policy_validate_invalid_flag_rule_regex() {
        let mut p = make_valid_policy();
        let mut tool = make_tool("/usr/bin/tool");
        tool.flag_rules.insert(
            "--format".to_string(),
            FlagRule::Regex {
                regex: "[unclosed".to_string(),
            },
        );
        p.tools.insert("mytool".to_string(), tool);
        let err = p.validate().unwrap_err();
        assert!(err.contains("Invalid regex"), "got: {err}");
    }
}

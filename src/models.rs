use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_unshare_ipc() -> bool { true }
fn default_unshare_uts() -> bool { true }
fn default_true() -> bool { true }

// ── Polymorphic flag-argument rule ────────────────────────────────────────────

/// Constrains the value of a flag's argument via one of three mechanisms.
///
/// `#[serde(untagged)]` means the JSON shape determines the variant:
///
/// | JSON                                | Variant    |
/// |-------------------------------------|------------|
/// | `["PROD", {"regex": "^[0-9]+$"}]`  | `List`     |
/// | `{"regex": "^[0-9]+$"}`            | `Regex`    |
/// | `"STAGING"` / `"any"`              | `Constant` |
///
/// **Variant order matters**: serde tries each in declaration order.
/// `List` (array) must precede `Regex` (object) which must precede
/// `Constant` (string) to avoid ambiguity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagRule {
    /// Logical OR: accepted if **any** rule in the list matches.
    /// Supports infinite nesting — a `List` may contain other `List`s.
    List(Vec<FlagRule>),
    /// Accepted if the argument matches the compiled regular expression.
    /// Case-sensitive by default; embed `(?i)` for case-insensitive matching.
    Regex { regex: String },
    /// Exact string match, or the special sentinel `"any"` which always
    /// returns `true` regardless of the argument value.
    Constant(String),
}

impl FlagRule {
    /// Returns `true` if `arg` is accepted by this rule.
    ///
    /// `List` uses short-circuit OR. An invalid `Regex` pattern **fails
    /// closed** (returns `false`) rather than panicking; `validate()` ensures
    /// all patterns are valid before any command is processed.
    pub fn matches(&self, arg: &str) -> bool {
        match self {
            FlagRule::List(rules) => rules.iter().any(|r| r.matches(arg)),
            FlagRule::Regex { regex } => regex::Regex::new(regex)
                .map(|re| re.is_match(arg))
                .unwrap_or(false),
            FlagRule::Constant(s) => s == "any" || s == arg,
        }
    }

    /// Recursively collects every regex pattern string anywhere in this rule
    /// tree. Used by [`SSDFPolicy::validate`] for eager compile-time checking.
    pub(crate) fn collect_regexes<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            FlagRule::List(rules) => rules.iter().for_each(|r| r.collect_regexes(out)),
            FlagRule::Regex { regex } => out.push(regex.as_str()),
            FlagRule::Constant(_) => {}
        }
    }
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
    /// Per-flag argument constraints.  Key is the flag string (e.g. `"--target"`);
    /// value is a [`FlagRule`] that must accept the flag's argument.
    #[serde(default)]
    pub flag_rules: HashMap<String, FlagRule>,
}

fn default_log_destination() -> String { "syslog".to_string() }
fn default_log_format() -> String { "text".to_string() }
fn default_admin_contact() -> String { "sysadmin@company.com".to_string() }
fn default_safe_arg_regex() -> String { r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string() }
fn default_common_env_whitelist() -> Vec<String> {
    vec!["TERM".to_string(), "LANG".to_string(), "LC_ALL".to_string(), "LS_COLORS".to_string()]
}
fn default_blocked_paths() -> Vec<String> {
    vec![
        "/etc/shadow".to_string(), "/etc/gshadow".to_string(), "/etc/sudoers".to_string(),
        "/etc/ssdf".to_string(), "/etc/ssh".to_string(), "/etc/pam.d".to_string(),
        "/root".to_string(), "/dev/mem".to_string(), "/dev/kmem".to_string(),
        "/dev/port".to_string(), "/proc/kcore".to_string()
    ]
}
fn default_bypass_groups() -> Vec<String> {
    vec!["sudo".to_string(), "wheel".to_string()]
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
    #[serde(default = "default_true")]
    pub require_toctou_protection: bool,
    #[serde(default = "default_bypass_groups")]
    pub bypass_groups: Vec<String>,
    pub default_isolation: Option<IsolationSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SSDFPolicy {
    pub version: String,
    #[serde(default)]
    pub serial: i32,
    pub global_settings: GlobalSettings,
    pub tools: HashMap<String, ToolPolicy>,
}

impl Default for IsolationSettings {
    /// Fail-closed defaults: unshare IPC and UTS namespaces (matches serde defaults),
    /// leave network/PID sharing and mount lists to explicit policy.
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

pub fn is_valid_tool_name(name: &str) -> bool {
    // Protect against path traversal: a valid tool name is exactly one path component.
    // On Unix, filenames can contain almost any character except '/' and the null byte.
    // We explicitly reject whitespace and commas to prevent sudoers file injection.
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.contains(',')
        || name.chars().any(|c| c.is_whitespace()))
}

impl SSDFPolicy {
    pub fn validate(&self) -> Result<(), String> {
        // Validate regex
        if let Err(_) = regex::Regex::new(&self.global_settings.safe_arg_regex) {
            return Err("Invalid regex in safe_arg_regex".to_string());
        }

        // Validate blocked_paths are absolute
        for path in &self.global_settings.blocked_paths {
            if !path.starts_with('/') {
                return Err(format!("Blocked path must be absolute: {}", path));
            }
        }

        if let Some(isolation) = &self.global_settings.default_isolation {
            for path in &isolation.private_mounts {
                if !path.starts_with('/') {
                    return Err(format!("global default_isolation private_mounts path must be absolute: {}", path));
                }
            }
            for path in &isolation.readonly_mounts {
                if !path.starts_with('/') {
                    return Err(format!("global default_isolation readonly_mounts path must be absolute: {}", path));
                }
            }
        }

        // Validate tool real_binary paths and tool names
        for (name, tool) in &self.tools {
            if !is_valid_tool_name(name) {
                return Err(format!("Invalid tool name in policy: '{}'", name));
            }
            if !tool.real_binary.starts_with('/') {
                return Err(format!("real_binary for tool '{}' must be an absolute path", name));
            }
            if let Some(isolation) = &tool.isolation {
                for path in &isolation.private_mounts {
                    if !path.starts_with('/') {
                        return Err(format!("private_mounts path for tool '{}' must be absolute: {}", name, path));
                    }
                }
                for path in &isolation.readonly_mounts {
                    if !path.starts_with('/') {
                        return Err(format!("readonly_mounts path for tool '{}' must be absolute: {}", name, path));
                    }
                }
            }

            // Validate every regex embedded in flag_rules, recursively.
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

    // Helper: build a minimal valid SSDFPolicy from JSON, panics if deserialization fails.
    fn parse(json: &str) -> SSDFPolicy {
        serde_json::from_str(json).expect("test JSON should deserialize")
    }

    // ── deny_unknown_fields ──────────────────────────────────────────────────

    #[test]
    fn test_unknown_field_in_policy_rejected() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {},
            "surprise_field": "attacker-value"
        }"#;
        assert!(
            serde_json::from_str::<SSDFPolicy>(json).is_err(),
            "SSDFPolicy must reject unknown top-level fields"
        );
    }

    #[test]
    fn test_unknown_field_in_global_settings_rejected() {
        let json = r#"{
            "version": "1.0",
            "global_settings": { "not_a_real_key": true },
            "tools": {}
        }"#;
        assert!(
            serde_json::from_str::<SSDFPolicy>(json).is_err(),
            "GlobalSettings must reject unknown fields"
        );
    }

    #[test]
    fn test_unknown_field_in_tool_policy_rejected() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "apt": {
                    "real_binary": "/usr/bin/apt",
                    "help_description": "pkg mgr",
                    "typo_flag": true
                }
            }
        }"#;
        assert!(
            serde_json::from_str::<SSDFPolicy>(json).is_err(),
            "ToolPolicy must reject unknown fields"
        );
    }

    /// Exercises the exact motivating security example from the spec:
    /// a typo'd isolation field (`unshare_netwrk`) must be caught.
    #[test]
    fn test_typo_in_isolation_settings_rejected() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "apt": {
                    "real_binary": "/usr/bin/apt",
                    "help_description": "pkg mgr",
                    "isolation": { "unshare_netwrk": true }
                }
            }
        }"#;
        assert!(
            serde_json::from_str::<SSDFPolicy>(json).is_err(),
            "IsolationSettings must reject the typo'd field 'unshare_netwrk'"
        );
    }

    // ── validate(): regex ────────────────────────────────────────────────────

    #[test]
    fn test_validate_rejects_invalid_regex() {
        let json = r#"{
            "version": "1.0",
            "global_settings": { "safe_arg_regex": "[unclosed_bracket" },
            "tools": {}
        }"#;
        let result = parse(json).validate();
        assert!(result.is_err(), "Invalid regex must cause validate() to fail");
        assert!(
            result.unwrap_err().to_lowercase().contains("regex"),
            "Error message should mention 'regex'"
        );
    }

    #[test]
    fn test_validate_accepts_valid_regex() {
        let json = r#"{
            "version": "1.0",
            "global_settings": { "safe_arg_regex": "^[a-zA-Z0-9]+$" },
            "tools": {}
        }"#;
        assert!(parse(json).validate().is_ok());
    }

    // ── validate(): blocked_paths ────────────────────────────────────────────

    #[test]
    fn test_validate_rejects_relative_blocked_path() {
        let json = r#"{
            "version": "1.0",
            "global_settings": { "blocked_paths": ["etc/shadow"] },
            "tools": {}
        }"#;
        let result = parse(json).validate();
        assert!(result.is_err(), "Relative blocked_path must cause validate() to fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("etc/shadow"),
            "Error should name the offending path, got: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_mixed_blocked_paths() {
        // One absolute, one relative — the relative one must be caught.
        let json = r#"{
            "version": "1.0",
            "global_settings": {
                "blocked_paths": ["/etc/shadow", "relative/path"]
            },
            "tools": {}
        }"#;
        assert!(parse(json).validate().is_err());
    }

    #[test]
    fn test_validate_accepts_all_absolute_blocked_paths() {
        let json = r#"{
            "version": "1.0",
            "global_settings": { "blocked_paths": ["/etc/shadow", "/root"] },
            "tools": {}
        }"#;
        assert!(parse(json).validate().is_ok());
    }

    // ── validate(): tool names ───────────────────────────────────────────────

    #[test]
    fn test_validate_rejects_invalid_tool_name() {
        let json_newline = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "mytool\nALL=(ALL)": { "real_binary": "/usr/bin/tool", "help_description": "test" }
            }
        }"#;
        assert!(parse(json_newline).validate().is_err(), "Tool name with newline must fail validate()");

        let json_slash = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "../evil": { "real_binary": "/usr/bin/tool", "help_description": "test" }
            }
        }"#;
        assert!(parse(json_slash).validate().is_err(), "Tool name with slash must fail validate()");

        let json_comma = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "apt, ALL ALL=(ALL) NOPASSWD: ALL": { "real_binary": "/usr/bin/tool", "help_description": "test" }
            }
        }"#;
        assert!(parse(json_comma).validate().is_err(), "Tool name with comma must fail validate()");
    }

    // ── validate(): tool real_binary ─────────────────────────────────────────

    #[test]
    fn test_validate_rejects_relative_real_binary() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "apt": {
                    "real_binary": "bin/apt",
                    "help_description": "pkg mgr"
                }
            }
        }"#;
        let result = parse(json).validate();
        assert!(result.is_err(), "Relative real_binary must cause validate() to fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("apt"),
            "Error should name the offending tool, got: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_at_least_one_relative_binary_among_many() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "ls":  { "real_binary": "/bin/ls",     "help_description": "list" },
                "bad": { "real_binary": "usr/bin/bad", "help_description": "bad"  }
            }
        }"#;
        assert!(parse(json).validate().is_err());
    }

    #[test]
    fn test_validate_accepts_absolute_real_binary() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "apt": { "real_binary": "/usr/bin/apt", "help_description": "pkg mgr" }
            }
        }"#;
        assert!(parse(json).validate().is_ok());
    }

    // ── end-to-end: fully valid minimal policy ───────────────────────────────

    #[test]
    fn test_validate_accepts_complete_valid_policy() {
        let json = r#"{
            "version": "1.0",
            "serial": 42,
            "global_settings": {
                "blocked_paths": ["/etc/shadow", "/root"],
                "safe_arg_regex": "^[a-zA-Z0-9._/+\\-=:,@]+$"
            },
            "tools": {
                "apt": {
                    "real_binary": "/usr/bin/apt",
                    "help_description": "pkg mgr",
                    "isolation": { "unshare_network": true }
                }
            }
        }"#;
        let policy = parse(json);
        assert!(policy.validate().is_ok());
    }

    // ── FlagRule: matches() ──────────────────────────────────────────────────

    #[test]
    fn test_flag_rule_constant_exact_match() {
        let rule = FlagRule::Constant("PROD".to_string());
        assert!(rule.matches("PROD"));
        assert!(!rule.matches("prod"), "constant match is case-sensitive");
        assert!(!rule.matches("PRODUCTION"), "constant must be exact");
    }

    #[test]
    fn test_flag_rule_constant_any_matches_everything() {
        let rule = FlagRule::Constant("any".to_string());
        assert!(rule.matches("PROD"));
        assert!(rule.matches(""));
        assert!(rule.matches("anything-at-all-1234"));
    }

    #[test]
    fn test_flag_rule_regex_matches_pattern() {
        let rule = FlagRule::Regex { regex: r"^[0-9]+$".to_string() };
        assert!(rule.matches("42"));
        assert!(rule.matches("0"));
        assert!(!rule.matches("abc"));
        assert!(!rule.matches("1a"), "partial numeric must not match ^[0-9]+$");
    }

    #[test]
    fn test_flag_rule_list_or_semantics() {
        let rule = FlagRule::List(vec![
            FlagRule::Constant("DEFAULT".to_string()),
            FlagRule::Regex { regex: r"^[0-9]+$".to_string() },
        ]);
        assert!(rule.matches("DEFAULT"), "constant arm must match");
        assert!(rule.matches("42"),      "regex arm must match");
        assert!(!rule.matches("abc"),    "neither arm matches");
    }

    #[test]
    fn test_flag_rule_invalid_regex_fails_closed() {
        // An invalid regex in a rule must not panic; it fails closed.
        let rule = FlagRule::Regex { regex: "[unclosed".to_string() };
        assert!(!rule.matches("anything"), "invalid regex must return false");
    }

    // ── FlagRule: JSON round-trip ─────────────────────────────────────────────

    #[test]
    fn test_flag_rule_deserializes_complex_list() {
        let rule: FlagRule = serde_json::from_str(
            r#"["PROD", "STAGING", {"regex": "^DEV-[0-9]+$"}]"#,
        )
        .expect("list rule must deserialize");
        assert!(rule.matches("PROD"));
        assert!(rule.matches("STAGING"));
        assert!(rule.matches("DEV-99"));
        assert!(!rule.matches("UNKNOWN"));
        assert!(!rule.matches("dev-99"), "regex is case-sensitive by default");
    }

    #[test]
    fn test_flag_rule_deserializes_any_constant() {
        let rule: FlagRule = serde_json::from_str(r#""any""#).unwrap();
        assert!(rule.matches("literally anything"));
    }

    // ── validate(): flag_rules regex checking ────────────────────────────────

    #[test]
    fn test_validate_rejects_invalid_regex_in_flag_rules() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "deploy": {
                    "real_binary": "/usr/local/bin/deploy",
                    "help_description": "deploy tool",
                    "flag_rules": { "--target": {"regex": "[unclosed"} }
                }
            }
        }"#;
        let result = parse(json).validate();
        assert!(result.is_err(), "Invalid regex in flag_rules must fail validate()");
        let err = result.unwrap_err();
        assert!(err.contains("--target"), "error must name the offending flag, got: {err}");
        assert!(err.contains("deploy"),   "error must name the offending tool, got: {err}");
    }

    #[test]
    fn test_validate_rejects_invalid_regex_nested_in_list_rule() {
        // The bad regex is buried inside a List — validate() must still find it.
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "deploy": {
                    "real_binary": "/usr/local/bin/deploy",
                    "help_description": "deploy tool",
                    "flag_rules": {
                        "--target": ["PROD", {"regex": "[bad"}]
                    }
                }
            }
        }"#;
        let result = parse(json).validate();
        assert!(result.is_err(), "Nested invalid regex must fail validate()");
    }

    #[test]
    fn test_validate_accepts_valid_flag_rules() {
        let json = r#"{
            "version": "1.0",
            "global_settings": {},
            "tools": {
                "deploy": {
                    "real_binary": "/usr/local/bin/deploy",
                    "help_description": "deploy tool",
                    "flag_rules": {
                        "--target": ["PROD", "STAGING", {"regex": "^DEV-[0-9]+$"}]
                    }
                }
            }
        }"#;
        assert!(parse(json).validate().is_ok());
    }
}

use crate::models::{SecureSudoersPolicy, ValidationContext};
use regex::Regex;

mod helpers;

#[derive(Debug)]
pub struct ValidatedCommand {
    binary: String,
    args: Vec<String>,
    isolation: crate::models::IsolationSettings,
    env_whitelist: Vec<String>,
}

impl ValidatedCommand {
    pub fn binary(&self) -> &str { &self.binary }
    pub fn args(&self) -> &[String] { &self.args }
    pub fn isolation(&self) -> &crate::models::IsolationSettings { &self.isolation }
    pub fn env_whitelist(&self) -> &[String] { &self.env_whitelist }
}

pub fn validate_command(
    policy: &SecureSudoersPolicy,
    tool_name: &str,
    raw_args: Vec<String>,
) -> Result<ValidatedCommand, String> {
    let tool = policy.tools.get(tool_name)
        .ok_or_else(|| format!("Tool '{}' is not permitted by policy", tool_name))?;

    let safe_re = Regex::new(&policy.global_settings.safe_arg_regex)
        .map_err(|_| "Policy contains invalid safe_arg_regex".to_string())?;

    let mut out: Vec<String> = Vec::new();
    let mut iter = raw_args.into_iter().peekable();

    if !tool.verbs.is_empty() {
        let verb = iter.next().ok_or_else(|| format!("Tool '{}' requires a verb", tool_name))?;
        if !tool.verbs.contains(&verb) {
            return Err(format!("Verb '{}' is not permitted for tool '{}'", verb, tool_name));
        }
        out.push(verb);
    }

    loop {
        let arg = match iter.next() {
            Some(a) => a,
            None => break,
        };

        if arg == "--" {
            for rem in iter {
                helpers::push_positional(
                    rem, tool_name, &ValidationContext::DelimitedPositional, &tool.disallowed_positional_args, &safe_re,
                    tool.validate_positional_args_as_paths, &policy.global_settings.blocked_paths, &mut out,
                )?;
            }
            break;
        } else if arg.starts_with("--") {
            helpers::process_long_flag(
                arg, tool_name, &tool.flags, &tool.flags_with_args, &tool.flags_with_path_args,
                &tool.flag_rules, &mut iter, &policy.global_settings.blocked_paths, &mut out,
            )?;
        } else if arg.starts_with('-') && arg.len() > 1 {
            helpers::process_short_flag(
                arg, tool_name, &tool.flags, &tool.flags_with_args, &tool.flags_with_path_args,
                &tool.flag_rules, &mut iter, &policy.global_settings.blocked_paths, &mut out,
            )?;
        } else {
            helpers::push_positional(
                arg, tool_name, &ValidationContext::Positional, &tool.disallowed_positional_args, &safe_re,
                tool.validate_positional_args_as_paths, &policy.global_settings.blocked_paths, &mut out,
            )?;
        }
    }

    let isolation = tool.isolation.clone()
        .or_else(|| policy.global_settings.default_isolation.clone())
        .unwrap_or_default();

    let env_whitelist = {
        let mut seen = std::collections::HashSet::new();
        let mut merged: Vec<String> = Vec::new();
        for key in policy.global_settings.common_env_whitelist.iter().chain(tool.env_whitelist.iter()) {
            if seen.insert(key.as_str()) { merged.push(key.clone()); }
        }
        merged
    };

    Ok(ValidatedCommand { binary: tool.real_binary.clone(), args: out, isolation, env_whitelist })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ToolPolicy;
    use crate::testing::fixtures::{make_policy, args};
    use std::collections::HashMap;

    #[test]
    fn test_unknown_tool_rejected() {
        assert!(validate_command(&make_policy(), "nonexistent", vec![]).is_err());
    }

    #[test]
    fn test_valid_verb_accepted() {
        let cmd = validate_command(&make_policy(), "apt", args(&["install"])).unwrap();
        assert_eq!(cmd.binary(), "/usr/bin/apt");
    }

    #[test]
    fn test_clustered_flags_deconstructed() {
        let cmd = validate_command(&make_policy(), "apt", args(&["install", "-ya"])).unwrap();
        assert!(cmd.args().contains(&"-y".to_string()));
        assert!(cmd.args().contains(&"-a".to_string()));
    }

    #[test]
    fn test_blocked_path_directly_rejected() {
        let r = validate_command(&make_policy(), "tail", args(&["/etc/shadow"]));
        assert!(r.is_err());
    }

    #[test]
    fn test_flag_with_equals_syntax() {
        use crate::models::{FlagRule, ToolPolicy};
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert("--target".to_string(), FlagRule::Constant("any".to_string()));
        flag_rules.insert("-p".to_string(), FlagRule::Constant("any".to_string()));
        
        p.tools.insert("deploy".to_string(), ToolPolicy {
            real_binary: "/usr/local/bin/deploy".to_string(),
            verbs: vec![], flags: vec![], flags_with_args: vec![], flags_with_path_args: vec![],
            disallowed_positional_args: vec![], validate_positional_args_as_paths: false,
            sensitive_flags: vec![], help_description: "Deploy.".to_string(),
            isolation: None, env_whitelist: vec![], flag_rules,
        });

        // Long flag with =
        let cmd1 = validate_command(&p, "deploy", args(&["--target=PROD"])).unwrap();
        assert_eq!(cmd1.args(), args(&["--target", "PROD"]));

        // Short flag with =
        let cmd2 = validate_command(&p, "deploy", args(&["-p=HELLO"])).unwrap();
        assert_eq!(cmd2.args(), args(&["-p", "HELLO"]));
    }

    #[test]
    fn test_flag_injection_via_delimiter_rejected() {
        let p = make_policy();
        // -- followed by something that looks like a flag should be rejected if not a path
        let args = args(&["--", "-exec", "id"]);
        assert!(validate_command(&p, "ls", args).is_err());
    }

    #[test]
    fn test_path_blocking_with_trailing_slash() {
        let mut p = make_policy();
        p.global_settings.blocked_paths = vec!["/etc/sudoers/".to_string()];
        p.tools.insert("cat".to_string(), ToolPolicy {
            real_binary: "/bin/cat".to_string(),
            verbs: vec![], flags: vec![], flags_with_args: vec![], flags_with_path_args: vec![],
            disallowed_positional_args: vec![], validate_positional_args_as_paths: true,
            sensitive_flags: vec![], help_description: "x".to_string(),
            isolation: None, env_whitelist: vec![], flag_rules: HashMap::new(),
        });

        // This should be blocked even if policy has trailing slash
        assert!(validate_command(&p, "cat", args(&["/etc/sudoers"])).is_err());
        // And subpaths should be blocked
        assert!(validate_command(&p, "cat", args(&["/etc/sudoers/rules"])).is_err());
    }

    #[test]
    fn test_root_path_blocking() {
        let mut p = make_policy();
        p.global_settings.blocked_paths = vec!["/".to_string()];
        p.tools.insert("ls".to_string(), ToolPolicy {
            real_binary: "/bin/ls".to_string(),
            verbs: vec![], flags: vec![], flags_with_args: vec![], flags_with_path_args: vec![],
            disallowed_positional_args: vec![], validate_positional_args_as_paths: true,
            sensitive_flags: vec![], help_description: "x".to_string(),
            isolation: None, env_whitelist: vec![], flag_rules: HashMap::new(),
        });

        assert!(validate_command(&p, "ls", args(&["/etc"])).is_err());
    }
}

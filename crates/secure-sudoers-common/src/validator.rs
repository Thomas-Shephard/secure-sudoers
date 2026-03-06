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
    pub fn binary(&self) -> &str {
        &self.binary
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
    pub fn isolation(&self) -> &crate::models::IsolationSettings {
        &self.isolation
    }
    pub fn env_whitelist(&self) -> &[String] {
        &self.env_whitelist
    }
}

#[cfg(feature = "testing")]
impl ValidatedCommand {
    pub fn new_for_testing(
        binary: &str,
        args: Vec<String>,
        isolation: crate::models::IsolationSettings,
        env_whitelist: Vec<String>,
    ) -> Self {
        ValidatedCommand {
            binary: binary.to_string(),
            args,
            isolation,
            env_whitelist,
        }
    }
}

pub fn validate_command(
    policy: &SecureSudoersPolicy,
    tool_name: &str,
    raw_args: Vec<String>,
) -> Result<ValidatedCommand, String> {
    let tool = policy
        .tools
        .get(tool_name)
        .ok_or_else(|| format!("Tool '{}' is not permitted by policy", tool_name))?;

    let safe_re = Regex::new(&policy.global_settings.safe_arg_regex)
        .map_err(|_| "Policy contains invalid safe_arg_regex".to_string())?;

    let mut out: Vec<String> = Vec::new();
    let mut iter = raw_args.into_iter().peekable();

    if !tool.verbs.is_empty() {
        let verb = iter
            .next()
            .ok_or_else(|| format!("Tool '{}' requires a verb", tool_name))?;
        if !tool.verbs.contains(&verb) {
            return Err(format!(
                "Verb '{}' is not permitted for tool '{}'",
                verb, tool_name
            ));
        }
        out.push(verb);
    }

    let v_params = helpers::ValidationParams {
        tool_name,
        flags: &tool.flags,
        flags_with_args: &tool.flags_with_args,
        flags_with_path_args: &tool.flags_with_path_args,
        flag_rules: &tool.flag_rules,
        blocked_paths: &policy.global_settings.blocked_paths,
        sensitive_flags: &tool.sensitive_flags,
    };

    while let Some(arg) = iter.next() {
        if arg == "--" {
            let p_params = helpers::PositionalParams {
                tool_name,
                context: &ValidationContext::DelimitedPositional,
                disallowed: &tool.disallowed_positional_args,
                safe_re: &safe_re,
                validate_as_path: tool.validate_positional_args_as_paths,
                blocked_paths: &policy.global_settings.blocked_paths,
            };
            for rem in iter {
                helpers::push_positional(rem, &p_params, &mut out)?;
            }
            break;
        } else if arg.starts_with("--") {
            helpers::process_long_flag(arg, &v_params, &mut iter, &mut out)?;
        } else if arg.starts_with('-') && arg.len() > 1 {
            helpers::process_short_flag(arg, &v_params, &mut iter, &mut out)?;
        } else {
            let p_params = helpers::PositionalParams {
                tool_name,
                context: &ValidationContext::Positional,
                disallowed: &tool.disallowed_positional_args,
                safe_re: &safe_re,
                validate_as_path: tool.validate_positional_args_as_paths,
                blocked_paths: &policy.global_settings.blocked_paths,
            };
            helpers::push_positional(arg, &p_params, &mut out)?;
        }
    }

    let isolation = tool
        .isolation
        .clone()
        .or_else(|| policy.global_settings.default_isolation.clone())
        .unwrap_or_default();

    let env_whitelist = {
        let mut seen = std::collections::HashSet::new();
        let mut merged: Vec<String> = Vec::new();
        for key in policy
            .global_settings
            .common_env_whitelist
            .iter()
            .chain(tool.env_whitelist.iter())
        {
            if seen.insert(key.as_str()) {
                merged.push(key.clone());
            }
        }
        merged
    };

    Ok(ValidatedCommand {
        binary: tool.real_binary.clone(),
        args: out,
        isolation,
        env_whitelist,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixtures::{args, make_policy, make_tool};
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
    fn test_attached_short_flags() {
        use crate::models::FlagRule;
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert("-p".to_string(), FlagRule::Constant("any".to_string()));

        let mut tool = make_tool("/usr/bin/test");
        tool.flags = vec!["-v".to_string()];
        tool.flags_with_path_args = vec!["-P".to_string()];
        tool.validate_positional_args_as_paths = false;
        tool.help_description = "test".to_string();
        tool.flag_rules = flag_rules;

        p.tools.insert("test".to_string(), tool);

        let cmd1 = validate_command(&p, "test", args(&["-pVALUE"])).unwrap();
        assert_eq!(cmd1.args(), args(&["-p", "VALUE"]));

        let cmd2 = validate_command(&p, "test", args(&["-vpVALUE"])).unwrap();
        assert_eq!(cmd2.args(), args(&["-v", "-p", "VALUE"]));

        assert!(validate_command(&p, "test", args(&["-P/etc/shadow"])).is_err());
    }

    #[test]
    fn test_flag_with_equals_syntax() {
        use crate::models::FlagRule;
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert(
            "--target".to_string(),
            FlagRule::Constant("any".to_string()),
        );
        flag_rules.insert("-p".to_string(), FlagRule::Constant("any".to_string()));

        let mut tool = make_tool("/usr/local/bin/deploy");
        tool.validate_positional_args_as_paths = false;
        tool.help_description = "Deploy.".to_string();
        tool.flag_rules = flag_rules;

        p.tools.insert("deploy".to_string(), tool);

        let cmd1 = validate_command(&p, "deploy", args(&["--target=PROD"])).unwrap();
        assert_eq!(cmd1.args(), args(&["--target", "PROD"]));

        let cmd2 = validate_command(&p, "deploy", args(&["-p=HELLO"])).unwrap();
        assert_eq!(cmd2.args(), args(&["-p", "HELLO"]));
    }

    #[test]
    fn test_flag_injection_via_delimiter_rejected() {
        let p = make_policy();
        let args = args(&["--", "-exec", "id"]);
        assert!(validate_command(&p, "ls", args).is_err());
    }

    #[test]
    fn test_path_blocking_with_trailing_slash() {
        let mut p = make_policy();
        p.global_settings.blocked_paths = vec!["/etc/sudoers/".to_string()];
        p.tools.insert("cat".to_string(), make_tool("/bin/cat"));

        assert!(validate_command(&p, "cat", args(&["/etc/sudoers"])).is_err());
        assert!(validate_command(&p, "cat", args(&["/etc/sudoers/rules"])).is_err());
    }

    #[test]
    fn test_blocked_path_canonicalization() {
        let mut p = make_policy();
        let tmp = std::env::temp_dir();
        let real_dir = tmp.join("secure_sudoers_test_real");
        let symlink_dir = tmp.join("secure_sudoers_test_symlink");

        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&symlink_dir);

        std::fs::create_dir(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        p.global_settings.blocked_paths = vec![symlink_dir.to_string_lossy().into_owned()];

        p.validate().unwrap();

        p.tools.insert("ls".to_string(), make_tool("/bin/ls"));

        assert!(validate_command(&p, "ls", args(&[real_dir.to_str().unwrap()])).is_err());

        let _ = std::fs::remove_file(&symlink_dir);
        let _ = std::fs::remove_dir_all(&real_dir);
    }

    #[test]
    fn test_flag_argument_redaction() {
        use crate::models::FlagRule;
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert(
            "--secret".to_string(),
            FlagRule::Constant("allowed".to_string()),
        );

        let mut tool = make_tool("/usr/bin/login");
        tool.flags_with_args = vec!["--secret".to_string()];
        tool.validate_positional_args_as_paths = false;
        tool.sensitive_flags = vec!["--secret".to_string()];
        tool.help_description = "Login".to_string();
        tool.flag_rules = flag_rules;

        p.tools.insert("login".to_string(), tool);

        let err = validate_command(&p, "login", args(&["--secret", "my_super_secret_value"]))
            .unwrap_err();
        assert!(
            err.contains("[REDACTED]"),
            "Error message should redact the sensitive flag value"
        );
        assert!(
            !err.contains("my_super_secret_value"),
            "Error message should not leak the plain text secret"
        );
    }

    #[test]
    fn test_root_path_blocking() {
        let mut p = make_policy();
        p.global_settings.blocked_paths = vec!["/".to_string()];
        p.tools.insert("ls".to_string(), make_tool("/bin/ls"));

        assert!(validate_command(&p, "ls", args(&["/etc"])).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::testing::fixtures::make_policy;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn validator_never_panics_random_tool(
            tool in ".*",
            args in proptest::collection::vec(".*", 0..=4),
        ) {
            let policy = make_policy();
            let _ = validate_command(&policy, &tool, args);
        }

        #[test]
        fn validator_apt_random_args_no_panic(
            args in proptest::collection::vec(any::<String>(), 0..=4),
        ) {
            let policy = make_policy();
            let _ = validate_command(&policy, "apt", args);
        }

        #[test]
        fn validator_tail_random_path_args_no_panic(
            args in proptest::collection::vec(any::<String>(), 0..=4),
        ) {
            let policy = make_policy();
            let _ = validate_command(&policy, "tail", args);
        }
    }
}

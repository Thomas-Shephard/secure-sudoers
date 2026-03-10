use crate::models::{SecurePath, SecureSudoersPolicy, ValidationContext};
use regex::Regex;

mod helpers;

#[derive(Debug)]
pub enum ValidatedArg {
    String(String),
    Path(SecurePath),
}

impl PartialEq<str> for ValidatedArg {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ValidatedArg {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for ValidatedArg {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl ValidatedArg {
    pub fn as_str(&self) -> &str {
        match self {
            ValidatedArg::String(s) => s,
            ValidatedArg::Path(p) => &p.path,
        }
    }

    pub fn path(&self) -> Option<&SecurePath> {
        match self {
            ValidatedArg::Path(p) => Some(p),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ValidatedCommand {
    binary: SecurePath,
    args: Vec<ValidatedArg>,
    isolation: crate::models::IsolationSettings,
    env_whitelist: Vec<String>,
}

impl ValidatedCommand {
    pub fn binary(&self) -> &SecurePath {
        &self.binary
    }
    pub fn args(&self) -> &[ValidatedArg] {
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
        binary: SecurePath,
        args: Vec<ValidatedArg>,
        isolation: crate::models::IsolationSettings,
        env_whitelist: Vec<String>,
    ) -> Self {
        ValidatedCommand {
            binary,
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

    let binary_path = crate::fs::check_path(
        &tool.real_binary,
        &ValidationContext::Positional,
        &policy.global_settings.blocked_paths,
    )?;

    let safe_re = Regex::new(&policy.global_settings.safe_arg_regex)
        .map_err(|_| "Policy contains invalid safe_arg_regex".to_string())?;

    let mut out: Vec<ValidatedArg> = Vec::new();
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
        out.push(ValidatedArg::String(verb));
    }

    let v_params = helpers::ValidationParams {
        tool_name,
        parameters: &tool.parameters,
        blocked_paths: &policy.global_settings.blocked_paths,
    };

    while let Some(arg) = iter.next() {
        if arg == "--" {
            let p_params = helpers::PositionalParams {
                tool_name,
                context: &ValidationContext::DelimitedPositional,
                disallowed: &tool.disallowed_positional_args,
                safe_re: &safe_re,
                config: &tool.positional,
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
                config: &tool.positional,
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
        binary: binary_path,
        args: out,
        isolation,
        env_whitelist,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ParameterConfig;
    use crate::testing::fixtures::{args, make_policy, make_tool};

    #[test]
    fn test_unknown_tool_rejected() {
        assert!(validate_command(&make_policy(), "nonexistent", vec![]).is_err());
    }

    #[test]
    fn test_valid_verb_accepted() {
        let cmd = validate_command(&make_policy(), "apt", args(&["install"])).unwrap();
        assert!(
            cmd.binary().path.ends_with("/usr/bin/apt") || cmd.binary().path.ends_with("/bin/apt")
        );
    }

    #[test]
    fn test_clustered_flags_deconstructed() {
        let cmd = validate_command(&make_policy(), "apt", args(&["install", "-ya"])).unwrap();
        let arg_strs: Vec<String> = cmd.args().iter().map(|a| a.as_str().to_string()).collect();
        assert!(arg_strs.contains(&"-y".to_string()));
        assert!(arg_strs.contains(&"-a".to_string()));
    }

    #[test]
    fn test_blocked_path_directly_rejected() {
        let r = validate_command(&make_policy(), "tail", args(&["/etc/shadow"]));
        assert!(r.is_err());
    }

    #[test]
    fn test_attached_short_flags() {
        let mut p = make_policy();
        let mut tool = make_tool("/usr/bin/true");
        tool.parameters.insert("-v".into(), ParameterConfig::bool());
        tool.parameters
            .insert("-p".into(), ParameterConfig::string());
        tool.parameters.insert("-P".into(), ParameterConfig::path());
        tool.positional = None;

        p.tools.insert("test".to_string(), tool);

        let cmd1 = validate_command(&p, "test", args(&["-pVALUE"])).unwrap();
        let arg_strs: Vec<String> = cmd1.args().iter().map(|a| a.as_str().to_string()).collect();
        assert_eq!(arg_strs, args(&["-p", "VALUE"]));

        let cmd2 = validate_command(&p, "test", args(&["-vpVALUE"])).unwrap();
        let arg_strs2: Vec<String> = cmd2.args().iter().map(|a| a.as_str().to_string()).collect();
        assert_eq!(arg_strs2, args(&["-v", "-p", "VALUE"]));

        assert!(validate_command(&p, "test", args(&["-P/etc/shadow"])).is_err());
    }

    #[test]
    fn test_flag_with_equals_syntax() {
        let mut p = make_policy();
        let mut tool = make_tool("/usr/bin/true");
        tool.parameters
            .insert("--target".into(), ParameterConfig::string());
        tool.parameters
            .insert("-p".into(), ParameterConfig::string());
        tool.positional = None;

        p.tools.insert("deploy".to_string(), tool);

        let cmd1 = validate_command(&p, "deploy", args(&["--target=PROD"])).unwrap();
        let arg_strs: Vec<String> = cmd1.args().iter().map(|a| a.as_str().to_string()).collect();
        assert_eq!(arg_strs, args(&["--target", "PROD"]));

        let cmd2 = validate_command(&p, "deploy", args(&["-p=HELLO"])).unwrap();
        let arg_strs2: Vec<String> = cmd2.args().iter().map(|a| a.as_str().to_string()).collect();
        assert_eq!(arg_strs2, args(&["-p", "HELLO"]));
    }

    #[test]
    fn test_flag_injection_via_delimiter_rejected() {
        let p = make_policy();
        let args = args(&["--", "-exec", "id"]);
        assert!(validate_command(&p, "tail", args).is_err());
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
        let mut p = make_policy();
        let mut tool = make_tool("/usr/bin/true");
        tool.parameters.insert(
            "--secret".into(),
            ParameterConfig::string()
                .regex("allowed".to_string())
                .sensitive(),
        );
        tool.positional = None;

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

    #[test]
    fn test_path_regex_validation() {
        let mut p = make_policy();
        let ls_bin = std::fs::canonicalize("/bin/ls").unwrap_or_else(|_| "/usr/bin/ls".into());
        let mut tool = make_tool(ls_bin.to_str().unwrap());
        let tmp = std::env::temp_dir();
        // Construct a path that will be under /tmp or /private/tmp
        let path_buf = tmp.join("secure_sudoers_test_foo");
        let path = path_buf.to_str().unwrap();
        std::fs::write(path, "test").unwrap();

        // Get the path as it will be returned by check_path
        let dummy_context = ValidationContext::Positional;
        let secure_path = crate::fs::check_path(path, &dummy_context, &[]).unwrap();

        // Use that exact path in the regex
        let regex = format!("^{}$", regex::escape(&secure_path.path));
        tool.positional = Some(ParameterConfig::path().regex(regex));
        p.tools.insert("ls".to_string(), tool);

        assert!(validate_command(&p, "ls", args(&[path])).is_ok());
        assert!(validate_command(&p, "ls", args(&["/etc/passwd"])).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_canonical_path_regex_validation() {
        let mut p = make_policy();
        let tmp = std::env::temp_dir();
        let real_file = tmp.join("secure_sudoers_regex_real");
        let symlink_file = tmp.join("secure_sudoers_regex_symlink");
        let dummy_bin = tmp.join("secure_sudoers_dummy_bin");

        let _ = std::fs::remove_file(&real_file);
        let _ = std::fs::remove_file(&symlink_file);
        let _ = std::fs::remove_file(&dummy_bin);

        std::fs::write(&real_file, "test").unwrap();
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();
        // Create a regular file for the tool binary
        std::fs::write(&dummy_bin, "bin").unwrap();

        let dummy_bin_str = dummy_bin.to_str().unwrap();
        let mut tool = make_tool(dummy_bin_str);

        // Get the canonical path of the real file
        let secure_real = crate::fs::check_path(
            real_file.to_str().unwrap(),
            &ValidationContext::Positional,
            &[],
        )
        .unwrap();

        // Regex should match the canonical path
        let regex = format!("^{}$", regex::escape(&secure_real.path));
        tool.positional = Some(ParameterConfig::path().regex(regex));
        p.tools.insert("cat".to_string(), tool);

        let result = validate_command(&p, "cat", args(&[symlink_file.to_str().unwrap()]));
        assert!(
            result.is_ok(),
            "Failed to validate command: {:?}",
            result.err()
        );

        let mut tool2 = make_tool(dummy_bin_str);
        // This should fail because the canonical path will not end in 'symlink'
        tool2.positional = Some(ParameterConfig::path().regex(".+symlink$".to_string()));
        p.tools.insert("cat2".to_string(), tool2);

        assert!(validate_command(&p, "cat2", args(&[symlink_file.to_str().unwrap()])).is_err());

        let _ = std::fs::remove_file(&symlink_file);
        let _ = std::fs::remove_file(&real_file);
        let _ = std::fs::remove_file(&dummy_bin);
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

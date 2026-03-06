use crate::models::{FlagRule, IsolationSettings, SSDFPolicy};
use regex::Regex;
use std::collections::HashMap;
use std::iter::Peekable;
use std::vec::IntoIter;

// ── Type-state: immutable validated command ───────────────────────────────────

/// A fully-validated, immutable command ready for execution.
///
/// Fields are private and accessible only through getters. The only way to
/// construct this type is via a successful call to `validate_command`, giving
/// callers a compile-time guarantee that the binary, arguments, and isolation
/// policy have all passed policy checks.
#[derive(Debug)]
pub struct ValidatedCommand {
    binary: String,
    args: Vec<String>,
    isolation: IsolationSettings,
    /// Merged, deduplicated environment whitelist (global ∪ tool-specific).
    env_whitelist: Vec<String>,
}

impl ValidatedCommand {
    /// Absolute path to the real binary to execute.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// Final, policy-validated argument list (verb + flags + positionals).
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Effective isolation settings resolved from tool → global default → built-in default.
    pub fn isolation(&self) -> &IsolationSettings {
        &self.isolation
    }

    /// Merged, deduplicated env whitelist: global `common_env_whitelist` ∪ tool `env_whitelist`.
    pub fn env_whitelist(&self) -> &[String] {
        &self.env_whitelist
    }
}

// ── Public validation entry point ─────────────────────────────────────────────

/// Validates `raw_args` for `tool_name` against `policy`.
///
/// Returns an immutable [`ValidatedCommand`] on success, or a human-readable
/// error string describing the first policy violation encountered.
/// The function fails closed: any ambiguity or unknown input yields an error.
pub fn validate_command(
    policy: &SSDFPolicy,
    tool_name: &str,
    raw_args: Vec<String>,
) -> Result<ValidatedCommand, String> {
    // 1. Tool must exist in policy — reject immediately if not.
    let tool = policy
        .tools
        .get(tool_name)
        .ok_or_else(|| format!("Tool '{}' is not permitted by policy", tool_name))?;

    // 2. Compile the safe_arg_regex once so every positional can be checked.
    let safe_re = Regex::new(&policy.global_settings.safe_arg_regex)
        .map_err(|_| "Policy contains invalid safe_arg_regex".to_string())?;

    let mut out: Vec<String> = Vec::new();
    let mut iter = raw_args.into_iter().peekable();

    // 3. Verb: if the tool declares verbs the very first argument must be one of them.
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

    // 4. Remaining args: flags then positionals.
    loop {
        let arg = match iter.next() {
            Some(a) => a,
            None => break,
        };

        if arg == "--" {
            // End-of-options marker: everything that follows is positional.
            for rem in iter {
                push_positional(
                    rem,
                    tool_name,
                    &tool.disallowed_positional_args,
                    &safe_re,
                    tool.validate_positional_args_as_paths,
                    &policy.global_settings.blocked_paths,
                    &mut out,
                )?;
            }
            break;
        } else if arg.starts_with("--") {
            process_long_flag(
                arg,
                tool_name,
                &tool.flags,
                &tool.flags_with_args,
                &tool.flags_with_path_args,
                &tool.flag_rules,
                &mut iter,
                &policy.global_settings.blocked_paths,
                &mut out,
            )?;
        } else if arg.starts_with('-') && arg.len() > 1 {
            process_short_flag(
                arg,
                tool_name,
                &tool.flags,
                &tool.flags_with_args,
                &tool.flags_with_path_args,
                &tool.flag_rules,
                &mut iter,
                &policy.global_settings.blocked_paths,
                &mut out,
            )?;
        } else {
            push_positional(
                arg,
                tool_name,
                &tool.disallowed_positional_args,
                &safe_re,
                tool.validate_positional_args_as_paths,
                &policy.global_settings.blocked_paths,
                &mut out,
            )?;
        }
    }

    // 5. Resolve isolation: tool-level → global default → built-in default.
    let isolation = tool
        .isolation
        .clone()
        .or_else(|| policy.global_settings.default_isolation.clone())
        .unwrap_or_default();

    // 6. Merge env whitelists: global ∪ tool-specific, deduplicated.
    //    Preserves global ordering first, then appends tool-only keys.
    //    Uses a HashSet of &str to avoid cloning during the duplicate check.
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

// ── Internal helpers ──────────────────────────────────────────────────────────

fn process_long_flag(
    flag: String,
    tool_name: &str,
    flags: &[String],
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    // flag_rules takes highest priority: the rule decides what values are allowed.
    if let Some(rule) = flag_rules.get(&flag) {
        let val = iter
            .next()
            .ok_or_else(|| format!("Flag '{}' requires an argument", flag))?;
        if !rule.matches(&val) {
            return Err(format!(
                "Flag '{}' argument '{}' is not permitted by policy",
                flag, val
            ));
        }
        if flags_with_path_args.contains(&flag) {
            let canonical = check_path(&val, &flag, blocked_paths)?;
            out.push(flag);
            out.push(canonical);
        } else {
            out.push(flag);
            out.push(val);
        }
    } else if flags_with_args.contains(&flag) {
        let val = iter
            .next()
            .ok_or_else(|| format!("Flag '{}' requires an argument", flag))?;
        out.push(flag);
        out.push(val);
    } else if flags_with_path_args.contains(&flag) {
        let val = iter
            .next()
            .ok_or_else(|| format!("Flag '{}' requires a path argument", flag))?;
        let canonical = check_path(&val, &flag, blocked_paths)?;
        out.push(flag);
        out.push(canonical);
    } else if flags.contains(&flag) {
        out.push(flag);
    } else {
        return Err(format!(
            "Flag '{}' is not permitted for tool '{}'",
            flag, tool_name
        ));
    }
    Ok(())
}

fn process_short_flag(
    arg: String,
    tool_name: &str,
    flags: &[String],
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    let chars: Vec<char> = arg[1..].chars().collect();

    if chars.len() > 1 {
        // ── Double-check: whole-string match takes priority ───────────────────
        // Tools like tcpdump define `-tt` as a distinct flag (different from
        // two `-t` flags), and ssh uses `-vvv` for verbosity levels.  Before
        // deconstruction, check whether the full token is explicitly listed.
        if let Some(rule) = flag_rules.get(&arg) {
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires an argument", arg))?;
            if !rule.matches(&val) {
                return Err(format!(
                    "Flag '{}' argument '{}' is not permitted by policy",
                    arg, val
                ));
            }
            if flags_with_path_args.contains(&arg) {
                let canonical = check_path(&val, &arg, blocked_paths)?;
                out.push(arg);
                out.push(canonical);
            } else {
                out.push(arg);
                out.push(val);
            }
            return Ok(());
        }
        if flags_with_args.contains(&arg) {
            // e.g. `-tt` is a flag-with-arg (unlikely but supported)
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires an argument", arg))?;
            out.push(arg);
            out.push(val);
            return Ok(());
        }
        if flags_with_path_args.contains(&arg) {
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires a path argument", arg))?;
            let canonical = check_path(&val, &arg, blocked_paths)?;
            out.push(arg);
            out.push(canonical);
            return Ok(());
        }
        if flags.contains(&arg) {
            out.push(arg);
            return Ok(());
        }

        // ── Deconstruction: clustered short flags (e.g. `-ya` → `-y`, `-a`) ──
        // Flags-with-args and flag_rules flags cannot appear inside a cluster
        // because it would be ambiguous which char consumes the next token.
        for c in &chars {
            let s = format!("-{}", c);
            if flags_with_args.contains(&s)
                || flags_with_path_args.contains(&s)
                || flag_rules.contains_key(&s)
            {
                return Err(format!(
                    "Flag '{}' takes an argument and cannot be clustered in '{}'",
                    s, arg
                ));
            }
            if !flags.contains(&s) {
                return Err(format!(
                    "Flag '{}' (from '{}') is not permitted for tool '{}'",
                    s, arg, tool_name
                ));
            }
        }
        for c in chars {
            out.push(format!("-{}", c));
        }
    } else {
        // Single short flag.
        if let Some(rule) = flag_rules.get(&arg) {
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires an argument", arg))?;
            if !rule.matches(&val) {
                return Err(format!(
                    "Flag '{}' argument '{}' is not permitted by policy",
                    arg, val
                ));
            }
            if flags_with_path_args.contains(&arg) {
                let canonical = check_path(&val, &arg, blocked_paths)?;
                out.push(arg);
                out.push(canonical);
            } else {
                out.push(arg);
                out.push(val);
            }
        } else if flags_with_args.contains(&arg) {
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires an argument", arg))?;
            out.push(arg);
            out.push(val);
        } else if flags_with_path_args.contains(&arg) {
            let val = iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires a path argument", arg))?;
            let canonical = check_path(&val, &arg, blocked_paths)?;
            out.push(arg);
            out.push(canonical);
        } else if flags.contains(&arg) {
            out.push(arg);
        } else {
            return Err(format!(
                "Flag '{}' is not permitted for tool '{}'",
                arg, tool_name
            ));
        }
    }
    Ok(())
}

fn push_positional(
    arg: String,
    tool_name: &str,
    disallowed: &[String],
    safe_re: &Regex,
    validate_as_path: bool,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    // Explicit deny-list.
    if disallowed.contains(&arg) {
        return Err(format!(
            "Positional argument '{}' is explicitly disallowed for tool '{}'",
            arg, tool_name
        ));
    }

    // All positionals must match the safe_arg_regex (catches metacharacters).
    if !safe_re.is_match(&arg) {
        return Err(format!(
            "Positional argument '{}' contains illegal characters",
            arg
        ));
    }

    if validate_as_path {
        let canonical = check_path(&arg, "positional", blocked_paths)?;
        out.push(canonical);
    } else {
        out.push(arg);
    }

    Ok(())
}

/// Validates a path argument for traversal sequences and blocked-path membership.
///
/// Uses `std::fs::canonicalize` to resolve symlinks where the path already
/// exists on disk. If the path does not exist yet (e.g. a new file being
/// created), falls back to the raw argument string for the blocked-path check,
/// giving conservative protection without hard-failing on new paths.
fn check_path(arg: &str, context: &str, blocked_paths: &[String]) -> Result<String, String> {
    // Reject `..` sequences before anything else — canonicalize is not enough
    // because we also want to catch non-existent traversal attempts.
    if arg.contains("..") {
        return Err(format!(
            "Path traversal detected in argument '{}' for '{}'",
            arg, context
        ));
    }

    let canonical = std::fs::canonicalize(arg)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| arg.to_string());

    for blocked in blocked_paths {
        // Match exact path or any child (e.g. /root matches /root/.ssh/authorized_keys).
        if canonical == *blocked || canonical.starts_with(&format!("{}/", blocked)) {
            return Err(format!("Access to blocked path '{}' is denied", arg));
        }
    }

    Ok(canonical)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{GlobalSettings, IsolationSettings, SSDFPolicy, ToolPolicy};
    use std::collections::HashMap;

    // ── Test fixture ─────────────────────────────────────────────────────────

    fn make_policy() -> SSDFPolicy {
        let mut tools = HashMap::new();

        // "tail" — path-validated positionals, flags-with-args for -n/-c
        tools.insert(
            "tail".to_string(),
            ToolPolicy {
                real_binary: "/usr/bin/tail".to_string(),
                verbs: vec![],
                flags: vec!["-v".to_string(), "-q".to_string(), "-f".to_string()],
                flags_with_args: vec!["-n".to_string(), "-c".to_string()],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: true,
                sensitive_flags: vec![],
                help_description: "Output the last part of files.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules: HashMap::new(),
            },
        );

        // "apt" — verbs required, no path validation, clusterable short flags
        tools.insert(
            "apt".to_string(),
            ToolPolicy {
                real_binary: "/usr/bin/apt".to_string(),
                verbs: vec![
                    "update".to_string(),
                    "install".to_string(),
                    "remove".to_string(),
                ],
                flags: vec![
                    "-y".to_string(),
                    "--quiet".to_string(),
                    "-a".to_string(),
                ],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Package manager.".to_string(),
                isolation: Some(IsolationSettings {
                    unshare_network: false,
                    unshare_pid: false,
                    ..IsolationSettings::default()
                }),
                env_whitelist: vec![],
                flag_rules: HashMap::new(),
            },
        );

        // "systemctl" — verbs + explicit disallowed positional args
        tools.insert(
            "systemctl".to_string(),
            ToolPolicy {
                real_binary: "/usr/bin/systemctl".to_string(),
                verbs: vec![
                    "start".to_string(),
                    "stop".to_string(),
                    "status".to_string(),
                ],
                flags: vec!["--no-pager".to_string()],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![
                    "sshd".to_string(),
                    "sshd.service".to_string(),
                ],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Service controller.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules: HashMap::new(),
            },
        );

        SSDFPolicy {
            version: "1.0".to_string(),
            serial: 1,
            global_settings: GlobalSettings {
                log_destination: "syslog".to_string(),
                log_format: "text".to_string(),
                admin_contact: "admin@example.com".to_string(),
                safe_arg_regex: r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string(),
                common_env_whitelist: vec![],
                dry_run: false,
                blocked_paths: vec!["/etc/shadow".to_string(), "/root".to_string()],
                require_toctou_protection: true,
                bypass_groups: vec!["sudo".to_string()],
                default_isolation: None,
            },
            tools,
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── Binary match ─────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_tool_rejected() {
        let r = validate_command(&make_policy(), "nonexistent", vec![]);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("nonexistent"));
    }

    // ── Verb validation ──────────────────────────────────────────────────────

    #[test]
    fn test_valid_verb_accepted() {
        let cmd = validate_command(&make_policy(), "apt", args(&["install"])).unwrap();
        assert_eq!(cmd.binary(), "/usr/bin/apt");
        assert_eq!(cmd.args(), &["install"]);
    }

    #[test]
    fn test_invalid_verb_rejected() {
        let r = validate_command(&make_policy(), "apt", args(&["purge"]));
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("purge"));
    }

    #[test]
    fn test_missing_verb_rejected() {
        let r = validate_command(&make_policy(), "apt", vec![]);
        assert!(r.is_err(), "apt requires a verb; empty args must fail");
    }

    #[test]
    fn test_tool_without_verbs_accepts_no_verb() {
        // tail declares no verbs, so zero args is fine
        let r = validate_command(&make_policy(), "tail", vec![]);
        assert!(r.is_ok());
    }

    // ── Flag validation ──────────────────────────────────────────────────────

    #[test]
    fn test_valid_flag_accepted() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "-y", "curl"]));
        assert!(r.is_ok());
    }

    #[test]
    fn test_unknown_flag_rejected() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "--classic", "curl"]));
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("--classic"));
    }

    // ── Clustered flags ──────────────────────────────────────────────────────

    #[test]
    fn test_clustered_flags_deconstructed() {
        // "-ya" → "-y" and "-a", both in apt's `flags`
        let cmd = validate_command(&make_policy(), "apt", args(&["install", "-ya"]))
            .expect("clustered -ya should be accepted");
        assert!(cmd.args().contains(&"-y".to_string()), "must contain -y");
        assert!(cmd.args().contains(&"-a".to_string()), "must contain -a");
        // Crucially, "-ya" itself must NOT appear — it was expanded.
        assert!(!cmd.args().contains(&"-ya".to_string()));
    }

    #[test]
    fn test_clustered_flags_with_unknown_char_rejected() {
        // "-yz": -y OK, -z not in policy
        let r = validate_command(&make_policy(), "apt", args(&["install", "-yz"]));
        assert!(r.is_err());
    }

    #[test]
    fn test_clustered_flags_cannot_include_flag_with_arg() {
        // -n takes an arg for tail; clustering it is ambiguous and must fail
        let r = validate_command(&make_policy(), "tail", args(&["-vn"]));
        assert!(r.is_err(), "-vn clusters a flag-with-arg which is forbidden");
    }

    // ── Multi-character short flags (double-check / repeated-flag logic) ──────

    fn make_tcpdump_policy() -> SSDFPolicy {
        let mut p = make_policy();
        p.tools.insert(
            "tcpdump".to_string(),
            ToolPolicy {
                real_binary: "/usr/sbin/tcpdump".to_string(),
                verbs: vec![],
                // Both the single flag -t and the doubled form -tt are listed.
                // tcpdump's manpage: -t = no timestamp, -tt = raw unix timestamp.
                flags: vec!["-t".to_string(), "-tt".to_string(), "-v".to_string()],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Packet analyser.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules: HashMap::new(),
            },
        );
        p
    }

    #[test]
    fn test_whole_string_flag_not_deconstructed() {
        // "-tt" is explicitly listed as a flag; it must NOT be split into ["-t", "-t"].
        let cmd = validate_command(&make_tcpdump_policy(), "tcpdump", args(&["-tt"]))
            .expect("-tt is in the policy and must be accepted as a unit");
        assert_eq!(
            cmd.args(),
            &["-tt"],
            "args must contain exactly \"-tt\", not two \"-t\" tokens"
        );
    }

    #[test]
    fn test_cluster_deconstruction_still_works_when_no_whole_string_match() {
        // apt has -y and -a but NOT -ya.  Input "-ya" must still be split.
        let cmd = validate_command(&make_policy(), "apt", args(&["install", "-ya"]))
            .expect("-ya deconstruction should still work");
        assert!(cmd.args().contains(&"-y".to_string()), "must contain -y");
        assert!(cmd.args().contains(&"-a".to_string()), "must contain -a");
        assert!(
            !cmd.args().contains(&"-ya".to_string()),
            "\"-ya\" must not survive as a unit"
        );
    }

    // ── Flags with arguments ─────────────────────────────────────────────────

    #[test]
    fn test_flag_with_arg_consumes_next_token() {
        // -n consumes "50"; "50" must NOT be treated as a positional path
        let cmd = validate_command(&make_policy(), "tail", args(&["-n", "50"]))
            .expect("-n 50 should be accepted");
        assert!(cmd.args().contains(&"-n".to_string()));
        assert!(cmd.args().contains(&"50".to_string()));
        // exactly two elements in the output
        assert_eq!(cmd.args().len(), 2);
    }

    #[test]
    fn test_flag_with_missing_arg_rejected() {
        let r = validate_command(&make_policy(), "tail", args(&["-n"]));
        assert!(r.is_err(), "-n with no following value must fail");
    }

    // ── Positional argument regex validation ─────────────────────────────────

    #[test]
    fn test_safe_positional_arg_accepted() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "curl"]));
        assert!(r.is_ok());
    }

    #[test]
    fn test_positional_with_semicolon_rejected() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "curl;rm"]));
        assert!(r.is_err());
        let err = r.unwrap_err().to_lowercase();
        assert!(
            err.contains("illegal") || err.contains("character"),
            "error should describe illegal characters, got: {err}"
        );
    }

    #[test]
    fn test_positional_with_pipe_rejected() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "curl|bash"]));
        assert!(r.is_err());
    }

    #[test]
    fn test_positional_with_backtick_rejected() {
        let r = validate_command(&make_policy(), "apt", args(&["install", "`id`"]));
        assert!(r.is_err());
    }

    // ── Directory traversal ──────────────────────────────────────────────────

    #[test]
    fn test_directory_traversal_rejected() {
        let r = validate_command(&make_policy(), "tail", args(&["../../etc/shadow"]));
        assert!(r.is_err(), "directory traversal must be rejected");
        let err = r.unwrap_err().to_lowercase();
        assert!(
            err.contains("traversal") || err.contains(".."),
            "error should mention traversal, got: {err}"
        );
    }

    #[test]
    fn test_traversal_skipped_when_path_validation_disabled() {
        // apt has validate_positional_args_as_paths: false, so `..` check is skipped.
        // The safe_arg_regex (^[a-zA-Z0-9._+\-=:,@/]+$) allows `.` and `/`, so this passes.
        let r = validate_command(
            &make_policy(),
            "apt",
            args(&["install", "../../etc/shadow"]),
        );
        assert!(
            r.is_ok(),
            "traversal check must be skipped for tools with path validation disabled"
        );
    }

    // ── Blocked paths ────────────────────────────────────────────────────────

    #[test]
    fn test_blocked_path_directly_rejected() {
        // /etc/shadow is in the policy blocked_paths; tail has path validation on.
        let r = validate_command(&make_policy(), "tail", args(&["/etc/shadow"]));
        assert!(r.is_err(), "direct access to a blocked path must be rejected");
    }

    #[test]
    fn test_blocked_path_child_rejected() {
        // /root is blocked; /root/.ssh/authorized_keys is a child and must also be blocked.
        let r = validate_command(&make_policy(), "tail", args(&["/root/.ssh/authorized_keys"]));
        assert!(r.is_err(), "child of a blocked path must be rejected");
    }

    // ── Disallowed positional args ────────────────────────────────────────────

    #[test]
    fn test_disallowed_positional_arg_rejected() {
        let r = validate_command(&make_policy(), "systemctl", args(&["stop", "sshd"]));
        assert!(r.is_err(), "explicitly disallowed arg 'sshd' must be rejected");
        assert!(r.unwrap_err().contains("sshd"));
    }

    #[test]
    fn test_allowed_positional_arg_accepted() {
        let r = validate_command(&make_policy(), "systemctl", args(&["status", "nginx"]));
        assert!(r.is_ok());
    }

    // ── ValidatedCommand getters ─────────────────────────────────────────────

    #[test]
    fn test_getter_binary() {
        let cmd = validate_command(&make_policy(), "apt", args(&["update"])).unwrap();
        assert_eq!(cmd.binary(), "/usr/bin/apt");
    }

    #[test]
    fn test_getter_args() {
        let cmd = validate_command(&make_policy(), "apt", args(&["update", "-y"])).unwrap();
        assert_eq!(cmd.args(), &["update", "-y"]);
    }

    #[test]
    fn test_tool_isolation_used_when_present() {
        // apt policy sets unshare_network: false explicitly
        let cmd = validate_command(&make_policy(), "apt", args(&["update"])).unwrap();
        assert!(!cmd.isolation().unshare_network);
    }

    #[test]
    fn test_global_default_isolation_inherited_when_tool_has_none() {
        let mut policy = make_policy();
        policy.global_settings.default_isolation = Some(IsolationSettings {
            unshare_network: true,
            ..IsolationSettings::default()
        });
        // tail has no tool-level isolation → inherits global default
        let cmd = validate_command(&policy, "tail", vec![]).unwrap();
        assert!(cmd.isolation().unshare_network);
    }

    #[test]
    fn test_builtin_default_isolation_when_neither_tool_nor_global_set() {
        let mut policy = make_policy();
        policy.global_settings.default_isolation = None;
        // tail has no tool isolation; global is also None → built-in default
        let cmd = validate_command(&policy, "tail", vec![]).unwrap();
        // Built-in default: unshare_ipc and unshare_uts are true, rest false
        assert!(cmd.isolation().unshare_ipc);
        assert!(cmd.isolation().unshare_uts);
        assert!(!cmd.isolation().unshare_network);
    }

    // ── Polymorphic flag validation ──────────────────────────────────────────

    /// Build a policy with a `deploy` tool that uses a polymorphic `--target` rule:
    /// `["PROD", "STAGING", {"regex": "^DEV-[0-9]+$"}]`
    fn make_deploy_policy() -> SSDFPolicy {
        use crate::models::FlagRule;

        let mut p = make_policy();
        let target_rule: FlagRule = serde_json::from_str(
            r#"["PROD", "STAGING", {"regex": "^DEV-[0-9]+$"}]"#,
        )
        .expect("deploy policy fixture must parse");

        let mut flag_rules = HashMap::new();
        flag_rules.insert("--target".to_string(), target_rule);

        p.tools.insert(
            "deploy".to_string(),
            ToolPolicy {
                real_binary: "/usr/local/bin/deploy".to_string(),
                verbs: vec![],
                flags: vec![],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Deployment tool.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules,
            },
        );
        p
    }

    #[test]
    fn test_polymorphic_flag_validation() {
        let p = make_deploy_policy();

        // ── ALLOW cases ──────────────────────────────────────────────────────

        // Constant "PROD" matches exactly.
        let cmd = validate_command(&p, "deploy", args(&["--target", "PROD"]))
            .expect("--target PROD should be accepted");
        assert_eq!(cmd.args(), &["--target", "PROD"]);

        // Constant "STAGING" matches exactly.
        let cmd = validate_command(&p, "deploy", args(&["--target", "STAGING"]))
            .expect("--target STAGING should be accepted");
        assert_eq!(cmd.args(), &["--target", "STAGING"]);

        // Regex arm: DEV- followed by one or more digits.
        let cmd = validate_command(&p, "deploy", args(&["--target", "DEV-123"]))
            .expect("--target DEV-123 should be accepted by the regex arm");
        assert_eq!(cmd.args(), &["--target", "DEV-123"]);

        // Edge: single-digit suffix still valid.
        let cmd = validate_command(&p, "deploy", args(&["--target", "DEV-0"]))
            .expect("--target DEV-0 should be accepted");
        assert_eq!(cmd.args(), &["--target", "DEV-0"]);

        // ── DENY cases ───────────────────────────────────────────────────────

        // Completely unknown environment name.
        let err = validate_command(&p, "deploy", args(&["--target", "UNKNOWN"]))
            .expect_err("--target UNKNOWN must be denied");
        assert!(
            err.contains("--target") && err.contains("UNKNOWN"),
            "error must name the flag and the bad argument, got: {err}"
        );

        // Regex is case-sensitive: lowercase prefix must not match `^DEV-[0-9]+$`.
        let err = validate_command(&p, "deploy", args(&["--target", "dev-123"]))
            .expect_err("--target dev-123 (lowercase) must be denied");
        assert!(
            err.contains("dev-123"),
            "error must name the rejected argument, got: {err}"
        );

        // Partial match of a constant should not pass.
        let err = validate_command(&p, "deploy", args(&["--target", "PROD-extra"]))
            .expect_err("--target PROD-extra must be denied");
        assert!(err.contains("PROD-extra"), "got: {err}");

        // DEV- without a numeric suffix must not satisfy `^DEV-[0-9]+$`.
        assert!(
            validate_command(&p, "deploy", args(&["--target", "DEV-"])).is_err(),
            "DEV- with empty suffix must be denied"
        );
    }

    #[test]
    fn test_flag_rule_missing_argument_rejected() {
        // --target with no following token must fail, not panic.
        let p = make_deploy_policy();
        let err = validate_command(&p, "deploy", args(&["--target"]))
            .expect_err("flag_rules flag with no argument must fail");
        assert!(err.contains("--target"), "got: {err}");
    }

    #[test]
    fn test_flag_rule_short_flag_allowed() {
        use crate::models::FlagRule;

        // A tool with a short-flag rule: `-e <env>` accepts "prod" or "staging".
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert(
            "-e".to_string(),
            FlagRule::List(vec![
                FlagRule::Constant("prod".to_string()),
                FlagRule::Constant("staging".to_string()),
            ]),
        );
        p.tools.insert(
            "myapp".to_string(),
            ToolPolicy {
                real_binary: "/usr/local/bin/myapp".to_string(),
                verbs: vec![],
                flags: vec![],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Custom app.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules,
            },
        );

        // Allowed value.
        let cmd = validate_command(&p, "myapp", args(&["-e", "prod"])).unwrap();
        assert_eq!(cmd.args(), &["-e", "prod"]);

        // Disallowed value.
        assert!(validate_command(&p, "myapp", args(&["-e", "DEV"])).is_err());
    }

    #[test]
    fn test_flag_rule_short_flag_cannot_be_clustered() {
        use crate::models::FlagRule;

        // A tool where `-e` is in flag_rules (takes an arg) and `-v` is a plain flag.
        // Clustering them as `-ve` must be rejected.
        let mut p = make_policy();
        let mut flag_rules = HashMap::new();
        flag_rules.insert(
            "-e".to_string(),
            FlagRule::Constant("any".to_string()),
        );
        p.tools.insert(
            "myapp2".to_string(),
            ToolPolicy {
                real_binary: "/usr/local/bin/myapp2".to_string(),
                verbs: vec![],
                flags: vec!["-v".to_string()],
                flags_with_args: vec![],
                flags_with_path_args: vec![],
                disallowed_positional_args: vec![],
                validate_positional_args_as_paths: false,
                sensitive_flags: vec![],
                help_description: "Custom app 2.".to_string(),
                isolation: None,
                env_whitelist: vec![],
                flag_rules,
            },
        );

        // `-ve` clusters a flag_rules flag → must be rejected.
        assert!(
            validate_command(&p, "myapp2", args(&["-ve"])).is_err(),
            "-ve must be rejected because -e takes an argument and cannot be clustered"
        );
    }

    // ── End-of-options marker ────────────────────────────────────────────────

    #[test]
    fn test_end_of_options_marker_treats_remainder_as_positional() {
        // For a no-verb tool; after `--` the next token goes to positional validation.
        // "/var/log/messages" passes regex + path validation (not blocked).
        let r = validate_command(&make_policy(), "tail", args(&["--", "/var/log/messages"]));
        assert!(r.is_ok());
        assert!(r.unwrap().args().contains(&"/var/log/messages".to_string()));
    }
}


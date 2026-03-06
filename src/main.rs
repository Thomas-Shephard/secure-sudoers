use secure_sudoers::{logging, models::SSDFPolicy, supervisor, validator};
use std::path::Path;
use tracing::{error, info, warn};

/// Default policy location; can be overridden at compile-time via the
/// `SSDF_POLICY_PATH` environment variable (useful for integration testing).
const POLICY_PATH: &str = "/etc/ssdf/policy.json";

/// The canonical binary name used to detect direct (non-symlink) invocation.
const BINARY_NAME: &str = "secure-sudoers";

fn main() {
    // 1. Determine tool name and raw arguments from argv.
    //    secure-sudoers supports two invocation styles:
    //    a) Symlink:  /usr/local/bin/apt -y install curl
    //       argv[0] = "apt"  →  tool="apt", args=["-y","install","curl"]
    //    b) Direct:   secure-sudoers apt -y install curl
    //       argv[0] = "secure-sudoers"  →  tool="apt", args=["-y","install","curl"]
    let raw_argv: Vec<String> = std::env::args().collect();
    let (tool_name, raw_args) = parse_invocation(&raw_argv);

    // 2. Load and deserialise the policy *before* initialising the logger,
    //    because the policy dictates the log destination and format.
    //    Allow the path to be overridden via SSDF_POLICY_PATH for integration
    //    testing without needing to modify /etc/ssdf/policy.json.
    #[cfg(debug_assertions)]
    let policy_path = std::env::var("SSDF_POLICY_PATH")
        .unwrap_or_else(|_| POLICY_PATH.to_string());

    #[cfg(not(debug_assertions))]
    let policy_path = POLICY_PATH.to_string();
    let policy = match load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            // Tracing is not yet initialised; write directly to stderr.
            eprintln!("FATAL: Cannot load policy from {policy_path}: {e}");
            std::process::exit(1);
        }
    };

    // 3. Initialise the tracing subscriber (syslog or stdout, text or JSON).
    logging::init_logging(&policy.global_settings);

    // 4. Validate the policy's internal consistency (regex, absolute paths).
    if let Err(e) = policy.validate() {
        error!(reason = %e, "Policy validation failed");
        eprintln!("FATAL: Policy validation failed: {e}");
        std::process::exit(1);
    }

    // 5. Identify the invoking user for audit records.
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());

    // 6. Validate the requested command against the loaded policy.
    let cmd = match validator::validate_command(&policy, &tool_name, raw_args.clone()) {
        Err(reason) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            warn!(
                tool = %tool_name,
                args = ?redacted,
                user = %user,
                reason = %reason,
                "Command denied by policy"
            );
            eprintln!("Access denied: {reason}");
            eprintln!(
                "For assistance contact: {}",
                policy.global_settings.admin_contact
            );
            std::process::exit(1);
        }
        Ok(cmd) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            info!(
                tool    = %tool_name,
                binary  = cmd.binary(),
                args    = ?redacted,
                user    = %user,
                "Command approved by policy"
            );
            cmd
        }
    };

    // 7. Hand off to the PTY supervisor, which forks the child process,
    //    manages isolation, and forwards I/O transparently.
    match supervisor::run_supervisor(&cmd, &policy) {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            error!(tool = %tool_name, reason = %e, "Supervisor failed");
            eprintln!("Execution failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Determines the tool name and argument list from raw `argv`.
///
/// If `argv[0]`'s basename is anything other than `"secure-sudoers"` or
/// `"secure_sudoers"` the process was invoked through a symlink — the basename
/// **is** the tool name and `argv[1..]` are its arguments.
///
/// If invoked directly, `argv[1]` is the tool name and `argv[2..]` are its
/// arguments.  Missing or empty tool names are passed through unchanged; the
/// validator will reject them with a clear error.
fn parse_invocation(argv: &[String]) -> (String, Vec<String>) {
    let argv0 = argv.first().map(String::as_str).unwrap_or(BINARY_NAME);
    let basename = Path::new(argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(BINARY_NAME);

    if basename == BINARY_NAME || basename == "secure_sudoers" {
        // Direct invocation: secure-sudoers <tool> [args…]
        let tool = argv.get(1).cloned().unwrap_or_default();
        let args = argv.get(2..).unwrap_or(&[]).to_vec();
        (tool, args)
    } else {
        // Symlink invocation: <tool> [args…]
        let args = argv.get(1..).unwrap_or(&[]).to_vec();
        (basename.to_string(), args)
    }
}

/// Read and deserialise the policy file at `path`.
fn load_policy(path: &str) -> Result<SSDFPolicy, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
    serde_json::from_str::<SSDFPolicy>(&content)
        .map_err(|e| format!("Failed to parse policy JSON: {e}"))
}

/// Redacts the values of sensitive flags in the argument list.
///
/// A flag is sensitive if it appears in the `sensitive_flags` list for the
/// given tool in the policy. If a sensitive flag is found, the *next* argument
/// in the list is replaced with `"[REDACTED]"`.
fn redact_args(args: &[String], policy: &SSDFPolicy, tool_name: &str) -> Vec<String> {
    let sensitive_flags = match policy.tools.get(tool_name) {
        Some(tool) => &tool.sensitive_flags,
        None => return args.to_vec(),
    };

    if sensitive_flags.is_empty() {
        return args.to_vec();
    }

    let mut redacted = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        redacted.push(arg.clone());

        if sensitive_flags.contains(arg) && i + 1 < args.len() {
            redacted.push("[REDACTED]".to_string());
            i += 2; // skip the sensitive value
        } else {
            i += 1;
        }
    }
    redacted
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn direct_invocation_extracts_tool_and_args() {
        let (tool, args) = parse_invocation(&argv(&["secure-sudoers", "apt", "-y", "install"]));
        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["-y", "install"]));
    }

    #[test]
    fn symlink_invocation_uses_basename_as_tool() {
        let (tool, args) =
            parse_invocation(&argv(&["/usr/local/bin/apt", "-y", "install", "curl"]));
        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["-y", "install", "curl"]));
    }

    #[test]
    fn direct_invocation_without_args_returns_empty() {
        let (tool, args) = parse_invocation(&argv(&["secure-sudoers"]));
        assert_eq!(tool, "");
        assert!(args.is_empty());
    }

    #[test]
    fn symlink_invocation_without_args_returns_empty_args() {
        let (tool, args) = parse_invocation(&argv(&["/usr/bin/tail"]));
        assert_eq!(tool, "tail");
        assert!(args.is_empty());
    }

    #[test]
    fn underscore_variant_treated_as_direct() {
        let (tool, args) =
            parse_invocation(&argv(&["secure_sudoers", "systemctl", "status"]));
        assert_eq!(tool, "systemctl");
        assert_eq!(args, argv(&["status"]));
    }
}


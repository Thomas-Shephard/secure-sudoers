#![cfg(target_os = "linux")]

use secure_sudoers::helpers::{load_policy, parse_invocation, redact_args};
use secure_sudoers::supervisor;
use secure_sudoers_common::{logging, validator};
use tracing::{error, info, warn};

const POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";

fn main() {
    let raw_argv: Vec<String> = std::env::args().collect();

    #[cfg(debug_assertions)]
    let policy_path =
        std::env::var("SECURE_SUDOERS_POLICY_PATH").unwrap_or_else(|_| POLICY_PATH.to_string());
    #[cfg(not(debug_assertions))]
    let policy_path = POLICY_PATH.to_string();

    let policy = match load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FATAL: Cannot load policy: {e}");
            std::process::exit(1);
        }
    };

    logging::init_logging(&policy.global_settings);

    let (tool_name, raw_args) = match parse_invocation(&raw_argv) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());

    let cmd = match validator::validate_command(&policy, &tool_name, raw_args.clone()) {
        Err(reason) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            warn!(tool = %tool_name, args = ?redacted, user = %user, reason = %reason, "Command denied");
            eprintln!("Access denied: {reason}");
            eprintln!("{}", policy.global_settings.admin_contact);
            std::process::exit(1);
        }
        Ok(cmd) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            info!(tool = %tool_name, binary = %cmd.binary().path, args = ?redacted, user = %user, "Command approved");
            cmd
        }
    };

    match supervisor::run_supervisor(&cmd, &policy) {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            error!(tool = %tool_name, reason = %e, "Supervisor failed");
            eprintln!("Execution failed: {e}");
            std::process::exit(1);
        }
    }
}

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

    let user = resolve_user();

    let (tool_name, raw_args) = match parse_invocation(&raw_argv) {
        Ok(res) => res,
        Err(e) => {
            error!(user = %user, "FATAL: {e}");
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

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
            error!(tool = %tool_name, user = %user, reason = %e, "Supervisor failed");
            eprintln!("Execution failed: {e}");
            std::process::exit(1);
        }
    }
}

fn resolve_user() -> String {
    use nix::unistd::{Uid, User, getuid};
    use std::env;

    let real_uid = getuid();

    let real_user = User::from_uid(real_uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| real_uid.to_string());

    if real_uid.as_raw() == 0 {
        let sudo_uid_str = env::var("SUDO_UID").ok();
        let sudo_user_env = env::var("SUDO_USER").ok();

        if let Some(uid_str) = sudo_uid_str {
            if let Ok(uid_num) = uid_str.parse::<u32>() {
                let sudo_uid = Uid::from_raw(uid_num);
                if let Ok(Some(u)) = User::from_uid(sudo_uid) {
                    return u.name;
                }
            }
        }

        if let Some(u) = sudo_user_env {
            return u;
        }

        warn!(
            uid = %real_uid,
            "Running as root but SUDO_USER/SUDO_UID missing; identifying as '{}'",
            real_user
        );
        real_user
    } else {
        real_user
    }
}

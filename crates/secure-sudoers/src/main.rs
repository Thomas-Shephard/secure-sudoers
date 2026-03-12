#![cfg(target_os = "linux")]

use secure_sudoers::exec::hash_binary_fd;
use secure_sudoers::helpers::{load_policy, parse_invocation, redact_args};
use secure_sudoers::supervisor;
use secure_sudoers_common::telemetry::{
    self, ContextInfo, IdentityInfo, PolicyInfo, SecurityEvent,
};
use secure_sudoers_common::{logging, validator};
use std::os::fd::AsRawFd;
use tracing::{error, info, warn};

const POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";

fn main() {
    let txn_id = generate_txn_id();
    let raw_argv: Vec<String> = std::env::args().collect();

    #[cfg(debug_assertions)]
    let policy_path =
        std::env::var("SECURE_SUDOERS_POLICY_PATH").unwrap_or_else(|_| POLICY_PATH.to_string());
    #[cfg(not(debug_assertions))]
    let policy_path = POLICY_PATH.to_string();

    logging::init_logging_fallback();

    let policy = match load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            error!(
                txn_id = %txn_id,
                reason = %e,
                "FATAL: policy load failed — possible configuration tampering or DoS"
            );
            eprintln!("FATAL: Cannot load policy: {e}");
            std::process::exit(1);
        }
    };

    logging::init_logging(&policy.global_settings);

    let identity = resolve_identity_triad();

    let (tool_name, raw_args) = match parse_invocation(&raw_argv) {
        Ok(res) => res,
        Err(e) => {
            let ev = SecurityEvent {
                event_id: telemetry::event_id::IDENTITY_SPOOFING.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: String::new(),
                    binary_path: String::new(),
                    binary_hash: String::new(),
                },
                policy: PolicyInfo {
                    status: "error".to_string(),
                    rule_id: None,
                    reason: Some("invocation_error".to_string()),
                },
                args: vec![],
            };
            error!(
                security_event_json = %ev.to_json_or_fallback(),
                "Invocation parse failure"
            );
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

    let validation = validator::validate_command(&policy, &tool_name, raw_args.clone());

    match validation {
        Err(denial) => {
            let redacted = redact_args(&raw_args, &policy, &tool_name);
            let ev = SecurityEvent {
                event_id: telemetry::event_id::POLICY_VIOLATION.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: tool_name.clone(),
                    binary_path: String::new(),
                    binary_hash: String::new(),
                },
                policy: PolicyInfo {
                    status: "denied".to_string(),
                    rule_id: denial.rule_id.clone(),
                    reason: Some(denial.reason_slug.clone()),
                },
                args: redacted.iter().map(|s| s.to_string()).collect(),
            };
            warn!(
                security_event_json = %ev.to_json_or_fallback(),
                "Command denied"
            );
            eprintln!("Access denied: {denial}");
            eprintln!("{}", policy.global_settings.admin_contact);
            std::process::exit(1);
        }
        Ok(result) => {
            let cmd = result.command;
            let rule_id = result.rule_id;

            let binary_hash = hash_binary_fd(cmd.binary().fd.as_raw_fd())
                .unwrap_or_else(|e| {
                    error!(txn_id = %txn_id, reason = %e, "binary hash computation failed — integrity check bypassed");
                    String::new()
                });

            let redacted = redact_args(&raw_args, &policy, &tool_name);
            let ev = SecurityEvent {
                event_id: telemetry::event_id::COMMAND_APPROVED.to_string(),
                txn_id: txn_id.clone(),
                timestamp: telemetry::rfc3339_now(),
                identity: identity.clone(),
                context: ContextInfo {
                    tool: tool_name.clone(),
                    binary_path: cmd.binary().path.clone(),
                    binary_hash: binary_hash.clone(),
                },
                policy: PolicyInfo {
                    status: "allowed".to_string(),
                    rule_id: Some(rule_id),
                    reason: None,
                },
                args: redacted.iter().map(|s| s.to_string()).collect(),
            };
            info!(
                security_event_json = %ev.to_json_or_fallback(),
                "Command approved"
            );

            match supervisor::run_supervisor(&cmd, &policy) {
                Ok(exit_code) => std::process::exit(exit_code),
                Err(e) => {
                    let ev_err = SecurityEvent {
                        event_id: telemetry::event_id::EXEC_FAILURE.to_string(),
                        txn_id: txn_id.clone(),
                        timestamp: telemetry::rfc3339_now(),
                        identity,
                        context: ContextInfo {
                            tool: tool_name,
                            binary_path: ev.context.binary_path,
                            binary_hash,
                        },
                        policy: PolicyInfo {
                            status: "error".to_string(),
                            rule_id: ev.policy.rule_id,
                            reason: Some("execution_failure".to_string()),
                        },
                        args: redacted.iter().map(|s| s.to_string()).collect(),
                    };
                    error!(
                        security_event_json = %ev_err.to_json_or_fallback(),
                        "Supervisor failed"
                    );
                    eprintln!("Execution failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn generate_txn_id() -> String {
    let mut buf = [0u8; 4];
    if unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, 4, 0) } == 4 {
        hex::encode(buf)
    } else {
        // Fallback to XOR pid with current nanoseconds for collision resistance
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:08x}", (std::process::id() as u128 ^ nanos) as u32)
    }
}

fn resolve_identity_triad() -> IdentityInfo {
    use nix::unistd::{Uid, User, geteuid, getuid};
    use std::env;

    let uid = getuid().as_raw();
    let euid = geteuid().as_raw();

    let sudo_uid: Option<u32> = env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    // Resolve the username. When running as root under sudo, prefer the
    // original invoking user (SUDO_UID -> passwd lookup -> SUDO_USER).
    let user: String = if euid == 0 {
        if let Some(orig_uid) = sudo_uid {
            User::from_uid(Uid::from_raw(orig_uid))
                .ok()
                .flatten()
                .map(|u| u.name)
                .or_else(|| env::var("SUDO_USER").ok())
                .unwrap_or_else(|| format!("uid:{}", uid))
        } else {
            env::var("SUDO_USER").unwrap_or_else(|_| {
                User::from_uid(Uid::from_raw(uid))
                    .ok()
                    .flatten()
                    .map(|u| u.name)
                    .unwrap_or_else(|| format!("uid:{}", uid))
            })
        }
    } else {
        User::from_uid(Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| uid.to_string())
    };

    IdentityInfo {
        user,
        uid,
        euid,
        sudo_uid,
    }
}

use std::path::Path;
use secure_sudoers_common::models::SecureSudoersPolicy;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

const PUBLIC_KEY_PATH: &str = "/etc/secure-sudoers/secure_sudoers_public_key.pem";

pub fn parse_invocation(raw_argv: &[String]) -> (String, Vec<String>) {
    if raw_argv.is_empty() { return (String::new(), vec![]); }
    let exe_path = Path::new(&raw_argv[0]);
    let exe_name = exe_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if exe_name == "secure-sudoers" || exe_name == "secure_sudoers" {
        if raw_argv.len() < 2 { (String::new(), vec![]) }
        else { (raw_argv[1].clone(), raw_argv[2..].to_vec()) }
    } else {
        (exe_name.to_string(), raw_argv[1..].to_vec())
    }
}

pub fn load_policy(path: &str) -> Result<SecureSudoersPolicy, String> {
    let policy_bytes = std::fs::read(path).map_err(|e| format!("Failed to read policy {path}: {e}"))?;
    
    let pubkey_bytes = secure_sudoers_common::util::read_pem_bytes(PUBLIC_KEY_PATH, "SECURE SUDOERS PUBLIC KEY")
        .map_err(|e| format!("Integrity failure: cannot load public key from {PUBLIC_KEY_PATH}: {e}"))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| "Integrity failure: public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| format!("Integrity failure: invalid public key: {e}"))?;

    let sig_path = format!("{path}.sig");
    let sig_bytes = std::fs::read(&sig_path)
        .map_err(|e| format!("Integrity failure: policy signature file {sig_path} missing or unreadable: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| format!("Integrity failure: signature must be 64 bytes (got {})", sig_bytes.len()))?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(&policy_bytes, &signature)
        .map_err(|e| format!("Integrity failure: policy signature verification failed for {path}: {e}"))?;

    serde_json::from_slice::<SecureSudoersPolicy>(&policy_bytes)
        .map_err(|e| format!("Failed to parse validated policy JSON: {e}"))
}

pub fn redact_args(args: &[String], policy: &SecureSudoersPolicy, tool_name: &str) -> Vec<String> {
    let sensitive_flags = match policy.tools.get(tool_name) {
        Some(tool) => &tool.sensitive_flags,
        None => return args.to_vec(),
    };
    let mut redacted = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for arg in args {
        if skip_next { redacted.push("[REDACTED]".to_string()); skip_next = false; continue; }
        redacted.push(arg.clone());
        if sensitive_flags.contains(arg) { skip_next = true; }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sudoers_common::testing::fixtures::args as argv;

    #[test]
    fn direct_invocation_extracts_tool_and_args() {
        let (tool, args) = parse_invocation(&argv(&["secure-sudoers", "apt", "-y", "install"]));
        assert_eq!(tool, "apt");
        assert_eq!(args, argv(&["-y", "install"]));
    }

    #[test]
    fn symlink_invocation_uses_basename_as_tool() {
        let (tool, args) = parse_invocation(&argv(&["/usr/local/bin/apt", "-y", "install", "curl"]));
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
        let (tool, args) = parse_invocation(&argv(&["secure_sudoers", "systemctl", "status"]));
        assert_eq!(tool, "systemctl");
        assert_eq!(args, argv(&["status"]));
    }
}

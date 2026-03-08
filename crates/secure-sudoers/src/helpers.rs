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
    // In debug builds, allow SECURE_SUDOERS_PUBKEY_PATH to redirect the key
    #[cfg(debug_assertions)]
    let pubkey_path = std::env::var("SECURE_SUDOERS_PUBKEY_PATH")
        .unwrap_or_else(|_| PUBLIC_KEY_PATH.to_string());
    #[cfg(not(debug_assertions))]
    let pubkey_path = PUBLIC_KEY_PATH.to_string();
    load_policy_with_pubkey(path, &pubkey_path)
}

pub(crate) fn load_policy_with_pubkey(path: &str, pubkey_path: &str) -> Result<SecureSudoersPolicy, String> {
    let policy_bytes = std::fs::read(path).map_err(|e| format!("Failed to read policy {path}: {e}"))?;
    
    let pubkey_bytes = secure_sudoers_common::util::read_pem_bytes(pubkey_path, "SECURE SUDOERS PUBLIC KEY")
        .map_err(|e| format!("Integrity failure: cannot load public key from {pubkey_path}: {e}"))?;
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

    let mut policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| format!("Failed to parse validated policy JSON: {e}"))?;
    
    policy.validate().map_err(|e| format!("Policy validation failed: {e}"))?;
    Ok(policy)
}
pub fn redact_args(args: &[String], policy: &SecureSudoersPolicy, tool_name: &str) -> Vec<String> {
    if let Some(tool) = policy.tools.get(tool_name) {
        let sensitive_flags = &tool.sensitive_flags;
        let mut redacted = Vec::with_capacity(args.len());
        let mut skip_next = false;
        for arg in args {
            if skip_next {
                redacted.push("[REDACTED]".to_string());
                skip_next = false;
                continue;
            }

            if let Some(idx) = arg.find('=') {
                let key = &arg[..idx];
                if sensitive_flags.iter().any(|f| f == key) {
                    redacted.push(format!("{}=[REDACTED]", key));
                    continue;
                }
            }

            let mut attached_found = false;
            for s_flag in sensitive_flags {
                if s_flag.starts_with('-') && !s_flag.starts_with("--") && s_flag.len() == 2 {
                    let flag_char = s_flag.chars().nth(1).unwrap();
                    if arg.starts_with('-') && !arg.starts_with("--") {
                        if let Some(pos) = arg.find(flag_char) {
                            if pos < arg.len() - 1 {
                                redacted.push(format!("{}[REDACTED]", &arg[..pos + 1]));
                            } else {
                                redacted.push(arg.clone());
                                skip_next = true;
                            }
                            attached_found = true;
                            break;
                        }
                    }
                }
            }
            if attached_found { continue; }

            redacted.push(arg.clone());
            if sensitive_flags.contains(arg) {
                skip_next = true;
            }
        }
        redacted
    } else {
        use secure_sudoers_common::models::UnauthorizedAuditMode;
        match policy.global_settings.unauthorized_audit_mode {
            UnauthorizedAuditMode::Minimal => {
                vec![format!("[{} arguments suppressed]", args.len())]
            }
            UnauthorizedAuditMode::KeysOnly => {
                args.iter().map(|arg| {
                    if let Some(idx) = arg.find('=') {
                        let key = &arg[..idx];
                        if key.starts_with('-') {
                            return format!("{}=[REDACTED]", key);
                        }
                    } else if arg.starts_with('-') {
                        if !arg.starts_with("--") && arg.len() > 2 {
                            return format!("{}[REDACTED]", &arg[..2]);
                        }
                        return arg.clone();
                    }
                    "[REDACTED]".to_string()
                }).collect()
            }
            UnauthorizedAuditMode::Full => args.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sudoers_common::testing::fixtures::{args as argv, make_policy};
    use secure_sudoers_common::models::UnauthorizedAuditMode;

    #[test]
    fn test_redact_args_clustered_with_separate_value() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.sensitive_flags.push("-p".to_string());
        }
        let args = argv(&["install", "-vp", "secret", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        // -vp is kept as is (it's the flag cluster), but secret must be redacted
        assert_eq!(redacted, argv(&["install", "-vp", "[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_clustered_short_flag() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.sensitive_flags.push("-p".to_string());
        }
        let args = argv(&["install", "-vpSECRET", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        assert_eq!(redacted, argv(&["install", "-vp[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_attached_short_flag() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.sensitive_flags.push("-p".to_string());
        }
        let args = argv(&["install", "-pSECRET", "curl"]);
        let redacted = redact_args(&args, &policy, "apt");
        assert_eq!(redacted, argv(&["install", "-p[REDACTED]", "curl"]));
    }

    #[test]
    fn test_redact_args_unauthorized_keys_only_attached() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::KeysOnly;
        let args = argv(&["-pSECRET", "-abc", "--longer"]);
        let redacted = redact_args(&args, &policy, "unknown");
        // -pSECRET -> -p[REDACTED], -abc -> -a[REDACTED], --longer -> --longer
        assert_eq!(redacted, vec!["-p[REDACTED]", "-a[REDACTED]", "--longer"]);
    }

    #[test]
    fn test_redact_args_unauthorized_minimal() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::Minimal;
        let args = argv(&["--pass", "secret", "pos"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, vec!["[3 arguments suppressed]"]);
    }

    #[test]
    fn test_redact_args_unauthorized_keys_only() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::KeysOnly;
        let args = argv(&["--pass=secret", "-f", "pos"]);
        let redacted = redact_args(&args, &policy, "unknown");
        // -f is kept as a key, --pass= is kept, pos is redacted
        assert_eq!(redacted, vec!["--pass=[REDACTED]", "-f", "[REDACTED]"]);
    }

    #[test]
    fn test_redact_args_unauthorized_full() {
        let mut policy = make_policy();
        policy.global_settings.unauthorized_audit_mode = UnauthorizedAuditMode::Full;
        let args = argv(&["--pass", "secret"]);
        let redacted = redact_args(&args, &policy, "unknown");
        assert_eq!(redacted, args);
    }

    #[test]
    fn test_redact_args_with_equals_syntax() {
        let mut policy = make_policy();
        if let Some(tool) = policy.tools.get_mut("apt") {
            tool.sensitive_flags.push("--password".to_string());
        }
        
        let raw_args = argv(&["install", "--password=SECRET", "--password", "SECRET2", "curl"]);
        let redacted = redact_args(&raw_args, &policy, "apt");
        
        assert_eq!(redacted, argv(&["install", "--password=[REDACTED]", "--password", "[REDACTED]", "curl"]));
    }

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

    // ── Task 3: load_policy crypto failure paths ─────────────────────────────

    use ed25519_dalek::{SigningKey, Signer};
    use rand_core::OsRng;
    use tempfile::TempDir;

    const VALID_POLICY_JSON: &str =
        r#"{"version":"1.0","global_settings":{},"tools":{}}"#;

    fn generate_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk_bytes = sk.verifying_key().to_bytes();
        (sk, vk_bytes)
    }

    fn write_pubkey_pem(dir: &TempDir, vk_bytes: &[u8; 32]) -> String {
        let b64 = secure_sudoers_common::util::bytes_to_base64(vk_bytes);
        let pem = format!(
            "-----BEGIN SECURE SUDOERS PUBLIC KEY-----\n{b64}\n-----END SECURE SUDOERS PUBLIC KEY-----\n"
        );
        let p = dir.path().join("pubkey.pem");
        std::fs::write(&p, pem).unwrap();
        p.to_str().unwrap().to_string()
    }

    fn write_policy_and_sig(dir: &TempDir, json: &str, sk: &SigningKey) -> String {
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, json).unwrap();
        let sig: ed25519_dalek::Signature = sk.sign(json.as_bytes());
        let sig_path = dir.path().join("policy.json.sig");
        std::fs::write(&sig_path, sig.to_bytes()).unwrap();
        policy_path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_load_policy_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nonexistent.json").to_str().unwrap().to_string();
        // pubkey path is irrelevant; policy read fails first
        let result = load_policy_with_pubkey(&missing, "/dev/null");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("Failed to read policy"),
            "expected 'Failed to read policy' in error"
        );
    }

    #[test]
    fn test_load_policy_missing_sig() {
        let dir = TempDir::new().unwrap();
        let (sk, vk_bytes) = generate_keypair();
        let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);

        // Write only the policy file, intentionally omit the .sig file
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, VALID_POLICY_JSON).unwrap();

        let result = load_policy_with_pubkey(policy_path.to_str().unwrap(), &pubkey_path);
        // Suppress unused variable warning
        let _ = sk;
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("missing or unreadable"),
            "expected 'missing or unreadable' in error, got: {msg}"
        );
    }

    #[test]
    fn test_load_policy_invalid_sig_size() {
        let dir = TempDir::new().unwrap();
        let (sk, vk_bytes) = generate_keypair();
        let pubkey_path = write_pubkey_pem(&dir, &vk_bytes);
        let _ = sk;

        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, VALID_POLICY_JSON).unwrap();
        // Write a 63-byte signature (one byte short of valid 64 bytes)
        let bad_sig = vec![0u8; 63];
        std::fs::write(dir.path().join("policy.json.sig"), &bad_sig).unwrap();

        let result = load_policy_with_pubkey(policy_path.to_str().unwrap(), &pubkey_path);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("signature must be 64 bytes"),
            "expected size error, got: {msg}"
        );
    }

    #[test]
    fn test_load_policy_wrong_key() {
        let dir = TempDir::new().unwrap();
        // Key A signs the policy
        let (sk_a, _vk_a) = generate_keypair();
        let policy_path = write_policy_and_sig(&dir, VALID_POLICY_JSON, &sk_a);

        // Key B is provided as the verifying key
        let (_sk_b, vk_b_bytes) = generate_keypair();
        let pubkey_b_path = write_pubkey_pem(&dir, &vk_b_bytes);

        let result = load_policy_with_pubkey(&policy_path, &pubkey_b_path);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("signature verification failed"),
            "expected 'signature verification failed', got: {msg}"
        );
    }

    macro_rules! require_root {
        () => {
            if unsafe { libc::getuid() } != 0 {
                eprintln!("  [SKIP] test requires root");
                return;
            }
        };
    }

    #[test]
    fn test_run_supervisor_true_exits_zero() {
        require_root!();

        use crate::supervisor::run_supervisor;
        use secure_sudoers_common::models::IsolationSettings;
        use secure_sudoers_common::testing::fixtures::make_policy;
        use secure_sudoers_common::validator::ValidatedCommand;

        // Locate /usr/bin/true or /bin/true
        let true_bin = if std::path::Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };

        let cmd = ValidatedCommand::new_for_testing(
            true_bin,
            vec![],
            IsolationSettings {
                unshare_network: false,
                unshare_pid: false,
                unshare_ipc: false,
                unshare_uts: false,
                private_mounts: vec![],
                readonly_mounts: vec![],
            },
            vec![],
        );
        // Use a policy with an empty blocked_paths list to avoid any
        // mount-namespace complications with pre-existing paths.
        let mut policy = make_policy();
        policy.global_settings.blocked_paths.clear();

        let result = run_supervisor(&cmd, &policy);
        assert_eq!(result.unwrap(), 0, "/usr/bin/true must exit 0");
    }
}

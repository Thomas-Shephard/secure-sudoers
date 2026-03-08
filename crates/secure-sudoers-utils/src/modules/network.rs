use super::keys::load_verifying_key;
use ed25519_dalek::{Signature, Verifier};
use secure_sudoers_common::models::SecureSudoersPolicy;
use std::io::Write;
use std::path::Path;

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const POLICY_PATH: &str = "/etc/secure-sudoers/policy.json";

pub fn run(url: &str, pubkey_path: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!("Security violation: URL must use HTTPS. Received: {url}"));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .https_only(true).build().map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let policy_bytes = fetch_limited(&client, url)?;
    let sig_bytes = fetch_limited(&client, &format!("{url}.sig"))?;

    let verifying_key = load_verifying_key(pubkey_path)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| format!("Signature must be 64 bytes; got {}", sig_bytes.len()))?;
    verifying_key.verify(&policy_bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|e| format!("Signature verification failed: {e}"))?;

    let mut new_policy: SecureSudoersPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| format!("Downloaded policy is not valid JSON: {e}"))?;
    new_policy.validate().map_err(|e| format!("Downloaded policy failed semantic validation: {e}"))?;

    if let Ok(current_src) = std::fs::read_to_string(POLICY_PATH) {
        if let Ok(current) = serde_json::from_str::<SecureSudoersPolicy>(&current_src) {
            if new_policy.serial <= current.serial {
                return Err(format!("Downgrade rejected: incoming serial {} <= current serial {}", new_policy.serial, current.serial));
            }
        }
    }

    let policy_dir = Path::new(POLICY_PATH).parent().unwrap_or_else(|| Path::new("/etc/secure-sudoers"));
    let mut tmp = tempfile::NamedTempFile::new_in(policy_dir)
        .map_err(|e| format!("Cannot create temp file in {}: {e}", policy_dir.display()))?;
    tmp.write_all(&policy_bytes).map_err(|e| format!("Failed to write temp file: {e}"))?;
    tmp.flush().map_err(|e| format!("Failed to flush temp file: {e}"))?;
    tmp.persist(POLICY_PATH).map_err(|e| format!("Atomic rename failed: {}", e.error))?;

    println!("Policy updated to serial {} and installed at {POLICY_PATH}", new_policy.serial);
    Ok(())
}

fn fetch_limited(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let response = client.get(url).send().map_err(|e| format!("GET {url} failed: {e}"))?;
    if !response.status().is_success() { return Err(format!("HTTP {} for {url}", response.status())); }
    if let Some(content_len) = response.content_length() {
        if content_len > MAX_POLICY_BYTES as u64 {
            return Err(format!("Server Content-Length {content_len} exceeds {MAX_POLICY_BYTES}-byte limit"));
        }
    }
    
    let mut buffer = Vec::new();
    response
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read body of {url}: {e}"))?;

    if buffer.len() > MAX_POLICY_BYTES {
        return Err(format!("Response body exceeds {MAX_POLICY_BYTES}-byte limit"));
    }
    Ok(buffer)
}

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

pub const PRIVATE_KEY_FILE: &str = "secure_sudoers_private_key.pem";
pub const PUBLIC_KEY_FILE: &str = "secure_sudoers_public_key.pem";

pub fn cmd_gen_keys() -> Result<(), String> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    write_key_file(
        PRIVATE_KEY_FILE,
        "SECURE SUDOERS PRIVATE KEY",
        &signing_key.to_bytes(),
        0o600,
    )?;
    write_key_file(
        PUBLIC_KEY_FILE,
        "SECURE SUDOERS PUBLIC KEY",
        &verifying_key.to_bytes(),
        0o644,
    )?;

    println!(
        "Generated:\n  {PRIVATE_KEY_FILE}  (private, mode 0600)\n  {PUBLIC_KEY_FILE}  (public, mode 0644)"
    );
    Ok(())
}

pub fn write_key_file(path: &str, label: &str, bytes: &[u8], unix_mode: u32) -> Result<(), String> {
    let content = format!(
        "-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n",
        b64 = secure_sudoers_common::util::bytes_to_base64(bytes)
    );

    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(unix_mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to create {path}: {e}"))?;
    let perms = std::fs::Permissions::from_mode(unix_mode);
    f.set_permissions(perms)
        .map_err(|e| format!("Failed to set permissions on {path}: {e}"))?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write {path}: {e}"))?;
    Ok(())
}

pub fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let bytes = secure_sudoers_common::util::read_pem_bytes(path, "SECURE SUDOERS PRIVATE KEY")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("Private key must be 32 bytes (got {})", bytes.len()))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn load_verifying_key(path: &str) -> Result<VerifyingKey, String> {
    let bytes = secure_sudoers_common::util::read_pem_bytes(path, "SECURE SUDOERS PUBLIC KEY")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("Public key must be 32 bytes (got {})", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid public key in {path}: {e}"))
}

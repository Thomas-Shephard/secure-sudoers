//! `secure-sudoers-utils` — Policy key management and distribution.
//!
//! # Subcommands
//! | command  | description                                                    |
//! |----------|----------------------------------------------------------------|
//! | gen-keys | Generate an Ed25519 keypair for policy signing                 |
//! | sign     | Sign a policy JSON file with the admin private key             |
//! | update   | Fetch, verify, and atomically install a new policy (Linux)     |
//! | install  | Install system-wide symlinks, sudoers drop-in, and lock files  |
//! | unlock   | Remove the immutable bit from all managed files for updates    |
//!
//! Key files use a minimal PEM-like text format (hex-encoded raw bytes) so
//! they are human-readable and inspectable with any text editor.  Signature
//! files contain the raw 64-byte Ed25519 signature.

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey};
// Verifier + VerifyingKey are needed in tests and in the network-update module.
#[cfg(any(feature = "network-update", test))]
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::rngs::OsRng;
#[cfg(feature = "network-update")]
use std::path::Path;

// ── Security constants ────────────────────────────────────────────────────────

const PRIVATE_KEY_FILE: &str = "ssdf_admin_key.pem";
const PUBLIC_KEY_FILE: &str = "ssdf_pubkey.pem";
/// Maximum policy size accepted over the network (1 MiB).
#[cfg(feature = "network-update")]
const MAX_POLICY_BYTES: usize = 1024 * 1024;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "secure-sudoers-utils",
    about = "Policy key management and distribution for secure-sudoers"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair and write it to the current directory.
    ///
    /// Writes `ssdf_admin_key.pem` (mode 0600) and `ssdf_pubkey.pem` (mode 0644).
    GenKeys,

    /// Sign a policy JSON file with the admin private key.
    ///
    /// Produces `<POLICY_PATH>.sig` containing the raw 64-byte Ed25519 signature.
    Sign {
        /// Path to the policy JSON file to sign.
        policy_path: String,
        /// Path to the private key file (ssdf_admin_key.pem).
        key_path: String,
    },

    /// Securely fetch and apply a signed policy update from a remote URL.
    ///
    /// The URL **must** use HTTPS.  The signature is fetched from `<URL>.sig`.
    /// Requires the `network-update` Cargo feature:
    ///   cargo install --features network-update
    Update {
        /// HTTPS URL of the new policy.json.
        url: String,
        /// Path to the public key file for signature verification.
        pubkey_path: String,
    },

    /// Install secure-sudoers system-wide from the active policy.
    ///
    /// For every tool in `/etc/ssdf/policy.json`, creates a symlink
    /// `/usr/local/bin/<tool>` → `/usr/local/bin/secure-sudoers`, writes a
    /// sudoers drop-in to `/etc/sudoers.d/secure-sudoers`, and locks all
    /// managed files with the immutable bit (`chattr +i` on Linux).
    ///
    /// **Requires root.**
    Install,

    /// Remove the immutable bit from all managed files to allow updates.
    ///
    /// Reads the active policy at `/etc/ssdf/policy.json` to enumerate the
    /// tool symlinks and runs `chattr -i` on each.  **Requires root.**
    Unlock,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::GenKeys => cmd_gen_keys(),
        Commands::Sign { policy_path, key_path } => cmd_sign(&policy_path, &key_path),
        Commands::Update { url, pubkey_path } => cmd_update(&url, &pubkey_path),
        Commands::Install => cmd_install(),
        Commands::Unlock => cmd_unlock(),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

// ── gen-keys ──────────────────────────────────────────────────────────────────

fn cmd_gen_keys() -> Result<(), String> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    write_key_file(PRIVATE_KEY_FILE, "SSDF PRIVATE KEY", &signing_key.to_bytes(), 0o600)?;
    write_key_file(PUBLIC_KEY_FILE, "SSDF PUBLIC KEY", &verifying_key.to_bytes(), 0o644)?;

    println!(
        "Generated:\n  {PRIVATE_KEY_FILE}  (private, mode 0600)\n  {PUBLIC_KEY_FILE}  (public, mode 0644)"
    );
    Ok(())
}

/// Write `bytes` as a PEM-like text file (hex-encoded data between headers).
fn write_key_file(path: &str, label: &str, bytes: &[u8], _unix_mode: u32) -> Result<(), String> {
    let content = format!(
        "-----BEGIN {label}-----\n{hex}\n-----END {label}-----\n",
        hex = bytes_to_hex(bytes)
    );

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(_unix_mode)
            .open(path)
            .map_err(|e| format!("Failed to create {path}: {e}"))?;
        let perms = std::fs::Permissions::from_mode(_unix_mode);
        f.set_permissions(perms)
            .map_err(|e| format!("Failed to set permissions on {path}: {e}"))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write {path}: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &content).map_err(|e| format!("Failed to write {path}: {e}"))?;
    }

    Ok(())
}

// ── sign ──────────────────────────────────────────────────────────────────────

fn cmd_sign(policy_path: &str, key_path: &str) -> Result<(), String> {
    let signing_key = load_signing_key(key_path)?;
    let policy_bytes =
        std::fs::read(policy_path).map_err(|e| format!("Cannot read {policy_path}: {e}"))?;

    let signature: Signature = signing_key.sign(&policy_bytes);

    let sig_path = format!("{policy_path}.sig");
    std::fs::write(&sig_path, signature.to_bytes())
        .map_err(|e| format!("Failed to write {sig_path}: {e}"))?;

    println!("Signed {policy_path} → {sig_path}");
    Ok(())
}

// ── update ────────────────────────────────────────────────────────────────────

fn cmd_update(url: &str, pubkey_path: &str) -> Result<(), String> {
    #[cfg(feature = "network-update")]
    {
        network_update::run(url, pubkey_path)
    }
    #[cfg(not(feature = "network-update"))]
    {
        let _ = (url, pubkey_path);
        Err(
            "The 'update' command requires the 'network-update' Cargo feature.\n\
             Rebuild with: cargo build --features network-update"
                .to_string(),
        )
    }
}

/// Full network-update implementation, compiled only when the feature is enabled.
#[cfg(feature = "network-update")]
mod network_update {
    use super::*;
    use secure_sudoers::models::SSDFPolicy;
    use std::io::Write;

    const POLICY_PATH: &str = "/etc/ssdf/policy.json";

    pub fn run(url: &str, pubkey_path: &str) -> Result<(), String> {
        // 1. Enforce HTTPS — never allow plaintext policy fetches.
        if !url.starts_with("https://") {
            return Err(format!(
                "Security violation: URL must use HTTPS. Received: {url}"
            ));
        }

        // 2. Build a client with a strict 30-second timeout, allowing only HTTPS redirects.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .https_only(true)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

        // 3. Fetch policy bytes and detached signature (at <url>.sig).
        let policy_bytes = fetch_limited(&client, url)?;
        let sig_bytes = fetch_limited(&client, &format!("{url}.sig"))?;

        // 4. Verify Ed25519 signature before touching the filesystem.
        let verifying_key = load_verifying_key(pubkey_path)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("Signature must be 64 bytes; got {}", sig_bytes.len()))?;
        verifying_key
            .verify(&policy_bytes, &Signature::from_bytes(&sig_arr))
            .map_err(|e| format!("Signature verification failed: {e}"))?;

        // 5. Structural validation + anti-downgrade (serial check).
        let new_policy: SSDFPolicy = serde_json::from_slice(&policy_bytes)
            .map_err(|e| format!("Downloaded policy is not valid JSON: {e}"))?;
        new_policy
            .validate()
            .map_err(|e| format!("Downloaded policy failed semantic validation: {e}"))?;

        if let Ok(current_src) = std::fs::read_to_string(POLICY_PATH) {
            if let Ok(current) = serde_json::from_str::<SSDFPolicy>(&current_src) {
                if new_policy.serial <= current.serial {
                    return Err(format!(
                        "Downgrade rejected: incoming serial {} ≤ current serial {}",
                        new_policy.serial, current.serial
                    ));
                }
            }
        }

        // 6. Atomic replacement: write to a temp file on the same filesystem,
        //    then rename — guarantees no partial writes are visible to readers.
        let policy_dir = Path::new(POLICY_PATH)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/ssdf"));
        let mut tmp = tempfile::NamedTempFile::new_in(policy_dir)
            .map_err(|e| format!("Cannot create temp file in {}: {e}", policy_dir.display()))?;
        tmp.write_all(&policy_bytes)
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        tmp.flush().map_err(|e| format!("Failed to flush temp file: {e}"))?;
        tmp.persist(POLICY_PATH)
            .map_err(|e| format!("Atomic rename failed: {}", e.error))?;

        println!(
            "Policy updated to serial {} and installed at {POLICY_PATH}",
            new_policy.serial
        );
        Ok(())
    }

    /// Fetch a URL with a 30-second timeout and a 1 MiB body size limit.
    fn fetch_limited(
        client: &reqwest::blocking::Client,
        url: &str,
    ) -> Result<Vec<u8>, String> {
        let response =
            client.get(url).send().map_err(|e| format!("GET {url} failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("HTTP {} for {url}", response.status()));
        }

        // Reject early if the server advertises an oversized Content-Length.
        if let Some(content_len) = response.content_length() {
            if content_len > MAX_POLICY_BYTES as u64 {
                return Err(format!(
                    "Server Content-Length {content_len} exceeds {MAX_POLICY_BYTES}-byte limit"
                ));
            }
        }

        let bytes =
            response.bytes().map_err(|e| format!("Failed to read body of {url}: {e}"))?;

        if bytes.len() > MAX_POLICY_BYTES {
            return Err(format!(
                "Response body {} bytes exceeds {MAX_POLICY_BYTES}-byte limit",
                bytes.len()
            ));
        }
        Ok(bytes.into())
    }
}

// ── Key file helpers ──────────────────────────────────────────────────────────

fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let bytes = read_pem_bytes(path, "SSDF PRIVATE KEY")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("Private key must be 32 bytes (got {})", bytes.len()))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(feature = "network-update")]
fn load_verifying_key(path: &str) -> Result<VerifyingKey, String> {
    let bytes = read_pem_bytes(path, "SSDF PUBLIC KEY")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("Public key must be 32 bytes (got {})", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid public key in {path}: {e}"))
}

/// Parse a PEM-like text file and return the hex-decoded payload bytes.
fn read_pem_bytes(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let hex_content: String = content
        .lines()
        .skip_while(|l| *l != begin.as_str())
        .skip(1) // consume the BEGIN header itself
        .take_while(|l| *l != end.as_str())
        .flat_map(|l| l.chars())
        .collect();

    if hex_content.is_empty() {
        return Err(format!("No '{label}' section found in {path}"));
    }
    hex_to_bytes(&hex_content)
}

// ── Hex encoding helpers ──────────────────────────────────────────────────────

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(format!("Odd-length hex string ({} chars)", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at offset {i} ('{}'): {e}", &hex[i..i + 2]))
        })
        .collect()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

// ── Installer ─────────────────────────────────────────────────────────────────

/// Standard path of the active policy file on a deployed system.
#[allow(dead_code)] // used inside #[cfg(unix)] blocks
const INSTALL_POLICY_PATH: &str = "/etc/ssdf/policy.json";
/// Canonical install path for the gatekeeper binary.
#[allow(dead_code)]
const INSTALL_BINARY: &str = "/usr/local/bin/secure-sudoers";
/// Canonical install path for the admin binary.
#[allow(dead_code)]
const INSTALL_UTILS_BINARY: &str = "/usr/local/bin/secure-sudoers-utils";
/// sudoers(5) drop-in written by the installer.
#[allow(dead_code)]
const INSTALL_SUDOERS_PATH: &str = "/etc/sudoers.d/secure-sudoers";
/// Directory in which per-tool symlinks are created.
#[allow(dead_code)]
const SYMLINK_DIR: &str = "/usr/local/bin";

// ── install entry point ───────────────────────────────────────────────────────

fn cmd_install() -> Result<(), String> {
    #[cfg(unix)]
    {
        installer::install()
    }
    #[cfg(not(unix))]
    {
        Err("The 'install' command requires a Unix system.".to_string())
    }
}

// ── unlock entry point ────────────────────────────────────────────────────────

fn cmd_unlock() -> Result<(), String> {
    #[cfg(unix)]
    {
        installer::unlock()
    }
    #[cfg(not(unix))]
    {
        Err("The 'unlock' command requires a Unix system.".to_string())
    }
}

// ── Pure string helper (platform-independent, unit-testable) ──────────────────

/// Build a sudoers(5) drop-in that restricts sudo to only the managed tools.
///
/// The output is sorted and deterministic so repeated runs are idempotent and
/// diffs in version control are minimal.
///
/// # Example output
/// ```text
/// # Managed by secure-sudoers-utils - do not edit manually.
/// Defaults secure_path="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
/// ALL ALL=(root) /usr/local/bin/apt, /usr/local/bin/tail
/// ```
#[allow(dead_code)] // used inside #[cfg(unix)] and in tests
fn generate_sudoers_content(tools: &[String]) -> String {
    // Sort for deterministic, idempotent output.
    let mut sorted: Vec<&str> = tools.iter().map(String::as_str).collect();
    sorted.sort_unstable();

    let paths: Vec<String> = sorted.iter().map(|t| format!("{SYMLINK_DIR}/{t}")).collect();

    format!(
        "# Managed by secure-sudoers-utils - do not edit manually.\n\
         Defaults secure_path=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
         ALL ALL=(root) {}\n",
        paths.join(", ")
    )
}

// ── Unix-only installer module ────────────────────────────────────────────────

#[cfg(unix)]
mod installer {
    use super::*;

    fn require_root() -> Result<(), String> {
        if unsafe { libc::getuid() } != 0 {
            return Err(
                "Root privileges required. Please run with sudo or as root.".to_string(),
            );
        }
        Ok(())
    }

    fn load_policy(path: &str) -> Result<secure_sudoers::models::SSDFPolicy, String> {
        let src =
            std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
        serde_json::from_str(&src).map_err(|e| format!("Invalid policy JSON at {path}: {e}"))
    }

    pub fn install() -> Result<(), String> {
        require_root()?;

        let policy = load_policy(INSTALL_POLICY_PATH)?;
        let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
        tool_names.sort_unstable();

        println!("Installing {} tool(s)...", tool_names.len());

        // 1. Create / refresh per-tool symlinks.
        let symlink_errors = install_symlinks(&tool_names, INSTALL_BINARY);

        // 2. Write the sudoers drop-in.
        write_sudoers_file(&tool_names)?;

        // 3. Lock all managed files with the immutable bit (Linux only).
        #[cfg(target_os = "linux")]
        {
            let mut targets: Vec<String> = vec![
                INSTALL_BINARY.to_string(),
                INSTALL_UTILS_BINARY.to_string(),
                INSTALL_POLICY_PATH.to_string(),
                INSTALL_SUDOERS_PATH.to_string(),
            ];
            targets.extend(tool_names.iter().map(|t| format!("{SYMLINK_DIR}/{t}")));
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
            for e in chattr_op("+i", &refs) {
                eprintln!("Warning: chattr +i failed: {e}");
            }
        }

        println!("Installation complete.");

        if !symlink_errors.is_empty() {
            return Err(format!(
                "Installation completed with symlink errors:\n{}",
                symlink_errors.join("\n")
            ));
        }
        Ok(())
    }

    pub fn unlock() -> Result<(), String> {
        require_root()?;

        #[cfg(target_os = "linux")]
        {
            // The immutable bit blocks modification but not reads — we can
            // always read the policy even when it is locked.
            let policy = load_policy(INSTALL_POLICY_PATH)?;
            let mut tool_names: Vec<String> = policy.tools.keys().cloned().collect();
            tool_names.sort_unstable();

            let mut targets: Vec<String> = vec![
                INSTALL_BINARY.to_string(),
                INSTALL_UTILS_BINARY.to_string(),
                INSTALL_POLICY_PATH.to_string(),
                INSTALL_SUDOERS_PATH.to_string(),
            ];
            targets.extend(tool_names.iter().map(|t| format!("{SYMLINK_DIR}/{t}")));
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();

            let errors = chattr_op("-i", &refs);
            for e in &errors {
                eprintln!("Warning: chattr -i failed: {e}");
            }
            println!("Unlocked {} managed file(s).", refs.len());

            if !errors.is_empty() {
                return Err(format!(
                    "Some files could not be unlocked:\n{}",
                    errors.join("\n")
                ));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            println!(
                "Note: file locking (chattr) is Linux-only; nothing to unlock on this platform."
            );
        }

        Ok(())
    }

    // ── Symlink management ────────────────────────────────────────────────────

    /// Create (or refresh) symlinks for each tool, backing up any regular file
    /// that already occupies the target path.
    ///
    /// Returns error messages for tools that could not be linked so the caller
    /// can continue with the rest of the install and report failures at the end.
    fn install_symlinks(tools: &[String], binary: &str) -> Vec<String> {
        let mut errors = Vec::new();

        for tool in tools {
            // Protect against path traversal: a valid tool name is exactly one path component.
            // On Unix, filenames can contain almost any character except '/' and the null byte.
            // We also explicitly reject newlines to prevent sudoers file injection.
            if !secure_sudoers::models::is_valid_tool_name(tool) {
                errors.push(format!("Invalid tool name '{tool}': must be a valid single filename component without path separators or newlines."));
                continue;
            }

            let link_path = std::path::Path::new(SYMLINK_DIR).join(tool);

            match std::fs::symlink_metadata(&link_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        // Overwrite existing symlink (`ln -sf` semantics).
                        if let Err(e) = std::fs::remove_file(&link_path) {
                            errors.push(format!(
                                "Cannot remove old symlink {}: {e}",
                                link_path.display()
                            ));
                            continue;
                        }
                    } else if meta.file_type().is_file() {
                        // Regular file: back it up rather than silently destroying it.
                        let backup = format!("{}.bak", link_path.display());
                        if let Err(e) = std::fs::rename(&link_path, &backup) {
                            errors.push(format!(
                                "Cannot back up {}: {e}",
                                link_path.display()
                            ));
                            continue;
                        }
                        println!("  Backed up {} -> {backup}", link_path.display());
                    } else {
                        // Directory or special device — refuse to touch it.
                        errors.push(format!(
                            "Skipping {}: exists and is not a regular file or symlink",
                            link_path.display()
                        ));
                        continue;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Nothing there yet — proceed.
                }
                Err(e) => {
                    errors.push(format!("Cannot stat {}: {e}", link_path.display()));
                    continue;
                }
            }

            match std::os::unix::fs::symlink(binary, &link_path) {
                Ok(()) => println!("  Symlinked {} -> {binary}", link_path.display()),
                Err(e) => errors.push(format!(
                    "Cannot create symlink {} -> {binary}: {e}",
                    link_path.display()
                )),
            }
        }

        errors
    }

    // ── Sudoers drop-in ───────────────────────────────────────────────────────

    fn write_sudoers_file(tools: &[String]) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let content = generate_sudoers_content(tools);

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o440)
            .open(INSTALL_SUDOERS_PATH)
            .map_err(|e| format!("Cannot create {INSTALL_SUDOERS_PATH}: {e}"))?;

        f.write_all(content.as_bytes())
            .map_err(|e| format!("Cannot write {INSTALL_SUDOERS_PATH}: {e}"))?;

        println!("  Wrote sudoers drop-in: {INSTALL_SUDOERS_PATH}");
        Ok(())
    }

    // ── chattr helper (Linux only) ────────────────────────────────────────────

    /// Run `chattr <flag>` on each path; returns per-path errors non-fatally.
    #[cfg(target_os = "linux")]
    fn chattr_op(flag: &str, paths: &[&str]) -> Vec<String> {
        let mut errors = Vec::new();
        for path in paths {
            match std::process::Command::new("chattr").arg(flag).arg(path).status() {
                Ok(s) if s.success() => {}
                Ok(s) => errors.push(format!("chattr {flag} {path}: exited with {s}")),
                Err(e) => errors.push(format!("chattr {flag} {path}: {e}")),
            }
        }
        errors
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_install_symlinks_rejects_path_traversal() {
            let invalid_tools = vec![
                "../evil".to_string(),
                "tool/name".to_string(),
                ".".to_string(),
                "..".to_string(),
                "".to_string(),
                "evil\0name".to_string(),
                "mytool\nALL".to_string(),
                "tool\rname".to_string(),
                "tool with space".to_string(),
            ];
            let errors = install_symlinks(&invalid_tools, "dummy");

            assert_eq!(
                errors.len(),
                9,
                "Should return an error for every invalid tool name"
            );
            for error in errors {
                assert!(error.contains("Invalid tool name"), "Expected error to mention 'Invalid tool name', got: {}", error);
            }
            
            // Valid names should NOT return errors based on character allow-lists
            let valid_tools = vec!["g++".to_string(), "python3.10".to_string(), "tool&name".to_string(), "weird-[]-name".to_string()];
            let no_errors = install_symlinks(&valid_tools, "dummy");
            // Note: Since the test runs `install_symlinks` which interacts with the real file system (e.g., SYMLINK_DIR)
            // we'll just check that it doesn't fail due to OUR new validation logic.
            // If it returns errors, they should be IO errors ("Cannot remove old symlink", "Cannot symlink", etc.),
            // not "Invalid tool name" errors.
            for error in no_errors {
                assert!(!error.contains("Invalid tool name"), "Legitimate tool names must not fail validation");
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end in-memory flow: generate keypair → sign payload → verify.
    #[test]
    fn test_keygen_sign_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let payload = b"dummy policy payload { \"version\": \"1.0\" }";
        let signature: Signature = signing_key.sign(payload);

        assert!(
            verifying_key.verify(payload, &signature).is_ok(),
            "Valid signature must verify"
        );

        // Tampered payload must fail verification.
        let tampered = b"tampered payload { \"version\": \"1.0\" }";
        assert!(
            verifying_key.verify(tampered, &signature).is_err(),
            "Modified payload must not verify with original signature"
        );
    }

    /// Key byte round-trip: serialize to [u8;32] and reconstruct identical keys.
    #[test]
    fn test_key_byte_serialization_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let sk2 = SigningKey::from_bytes(&sk.to_bytes());
        let vk2 = VerifyingKey::from_bytes(&vk.to_bytes()).expect("public key must deserialise");

        let msg = b"round-trip message";
        let sig = sk2.sign(msg);
        assert!(vk2.verify(msg, &sig).is_ok(), "Round-tripped keys must still sign/verify");
    }

    /// Hex helper round-trip.
    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original: &[u8] = &[0x00, 0x12, 0xab, 0xcd, 0xef, 0xff];
        let hex = bytes_to_hex(original);
        assert_eq!(hex, "0012abcdeff f".replace(' ', ""));
        let decoded = hex_to_bytes(&hex).expect("must decode valid hex");
        assert_eq!(decoded, original);
    }

    /// `hex_to_bytes` rejects odd-length strings.
    #[test]
    fn test_hex_rejects_odd_length() {
        assert!(hex_to_bytes("abc").is_err(), "Odd-length hex must be rejected");
    }

    /// `hex_to_bytes` rejects non-hex characters.
    #[test]
    fn test_hex_rejects_invalid_chars() {
        assert!(hex_to_bytes("zz").is_err(), "Non-hex chars must be rejected");
    }

    /// A wrong public key cannot verify a valid signature.
    #[test]
    fn test_wrong_key_cannot_verify() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);

        let payload = b"policy bytes";
        let sig = sk1.sign(payload);

        assert!(
            sk2.verifying_key().verify(payload, &sig).is_err(),
            "A different key must not verify a foreign signature"
        );
    }

    // ── Sudoers generation tests ──────────────────────────────────────────────

    /// The output must contain both required header lines and correctly
    /// comma-separate the tool paths on the `ALL ALL=(root)` line.
    #[test]
    fn test_sudoers_content_contains_required_sections() {
        let tools = vec!["apt".to_string(), "tail".to_string()];
        let content = generate_sudoers_content(&tools);

        assert!(
            content.contains(r#"Defaults secure_path="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin""#),
            "sudoers content must contain secure_path Defaults line"
        );
        assert!(
            content.contains("/usr/local/bin/apt"),
            "sudoers content must include /usr/local/bin/apt"
        );
        assert!(
            content.contains("/usr/local/bin/tail"),
            "sudoers content must include /usr/local/bin/tail"
        );

        // Verify comma-separation on the ALL line.
        let rule_line = content
            .lines()
            .find(|l| l.contains("ALL=(root)"))
            .expect("ALL ALL=(root) line must exist");
        assert!(
            rule_line.contains(", "),
            "tools must be comma-separated; got: {rule_line}"
        );
    }

    /// The tool list must be sorted alphabetically so the sudoers file is
    /// deterministic regardless of HashMap iteration order.
    #[test]
    fn test_sudoers_content_sorts_tools_deterministically() {
        let unsorted = vec![
            "zypper".to_string(),
            "apt".to_string(),
            "tail".to_string(),
        ];
        let content = generate_sudoers_content(&unsorted);

        let apt_pos = content.find("/usr/local/bin/apt").expect("apt must appear");
        let tail_pos = content.find("/usr/local/bin/tail").expect("tail must appear");
        let zypper_pos = content.find("/usr/local/bin/zypper").expect("zypper must appear");

        assert!(
            apt_pos < tail_pos && tail_pos < zypper_pos,
            "tools must appear in alphabetical order (apt < tail < zypper)"
        );
    }

    /// An empty tool list must still produce valid (non-panicking) output.
    #[test]
    fn test_sudoers_content_empty_tools() {
        let content = generate_sudoers_content(&[]);
        assert!(
            content.contains("Defaults secure_path="),
            "header must be present even with no tools"
        );
        let rule_line = content
            .lines()
            .find(|l| l.contains("ALL=(root)"))
            .expect("ALL=(root) line must still appear");
        // With no tools the path list should be empty (just whitespace after the tag).
        assert!(
            !rule_line.contains("/usr/local/bin/"),
            "rule line must be empty of paths when there are no tools; got: {rule_line}"
        );
    }
}


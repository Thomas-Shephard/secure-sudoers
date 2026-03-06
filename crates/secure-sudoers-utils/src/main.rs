#![cfg(target_os = "linux")]

use clap::{CommandFactory, Parser, Subcommand};
use secure_sudoers_utils::modules::{installer, keys, network};

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
    /// Generate a new Ed25519 keypair
    GenKeys,
    /// Sign a policy JSON file with the private key
    Sign {
        policy_path: String,
        key_path: String,
    },
    /// Securely fetch and apply a signed policy update
    Update { url: String, pubkey_path: String },
    /// Install secure-sudoers system-wide
    Install,
    /// Remove the immutable bit from all managed files
    Unlock,
    #[command(hide = true, name = "generate-man-page")]
    GenerateManPage,
}

fn main() {
    let cli = Cli::parse();

    if !matches!(cli.command, Commands::GenerateManPage)
        && let Err(e) = secure_sudoers_utils::require_root()
    {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::GenKeys => keys::cmd_gen_keys(),
        Commands::Sign {
            policy_path,
            key_path,
        } => cmd_sign(&policy_path, &key_path),
        Commands::Update { url, pubkey_path } => network::run(&url, &pubkey_path),
        Commands::Install => installer::cmd_install(),
        Commands::Unlock => installer::cmd_unlock(),
        Commands::GenerateManPage => cmd_generate_man_page(),
    };
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_sign(policy_path: &str, key_path: &str) -> Result<(), String> {
    let signing_key = keys::load_signing_key(key_path)?;
    let policy_bytes =
        std::fs::read(policy_path).map_err(|e| format!("Cannot read {policy_path}: {e}"))?;
    let signature = ed25519_dalek::Signer::sign(&signing_key, &policy_bytes);
    let sig_path = format!("{policy_path}.sig");
    std::fs::write(&sig_path, signature.to_bytes())
        .map_err(|e| format!("Failed to write {sig_path}: {e}"))?;
    println!("Signed {policy_path} → {sig_path}");
    Ok(())
}

fn cmd_generate_man_page() -> Result<(), String> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)
        .map_err(|e| format!("Failed to render man page: {e}"))?;
    std::io::Write::write_all(&mut std::io::stdout(), &buffer)
        .map_err(|e| format!("Failed to write to stdout: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use rand_core::OsRng;

    #[test]
    fn test_keygen_sign_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let payload = b"dummy policy payload";
        let signature: Signature = ed25519_dalek::Signer::sign(&signing_key, payload);
        assert!(verifying_key.verify(payload, &signature).is_ok());
    }
}

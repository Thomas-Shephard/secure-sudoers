# Secure Sudoers

Secure Sudoers is a policy-driven sudo delegation framework that provides granular, argument-level control over privileged command execution.

The tool is intended to replace traditional access to sudo by enforcing the **principle of least privilege** by validating every parameter before execution.

## Core Features
- **Argument-Level Control**: Validate flags, positional arguments, and file paths using regex or fixed choices.
- **Cryptographic Security**: Policies are signed with Ed25519; unauthorized or modified policies are rejected.
- **Process Isolation**: Secure sandboxing with network, PID, and mount namespaces (optional per tool).
- **Tamper Resistance**: Automatically applies the immutable bit (`chattr +i`) to configuration and binaries.
- **Auto Sudo Configuration**: Generates a single `sudoers.d` drop-in to manage all delegated tools.

## How It Works
1. **Invocation**: Run a symlink (e.g., `/usr/local/bin/apt`) that points to the `secure-sudoers` binary.
2. **Identification**: The binary identifies the tool name from the calling context.
3. **Verification**: The system loads the signed JSON policy and verifies it against the trusted public key.
4. **Validation**: Arguments are matched against the rules in the policy.
5. **Execution**: If valid, the process executes the command in a secure, isolated environment.

---

## Setup Guide

Follow these steps to set up Secure Sudoers on your system.

### 1. Install
Download the `secure-sudoers` and `secure-sudoers-utils` binaries from [GitHub Releases](https://github.com/thomas-shephard/secure-sudoers/releases).

### 2. Generate Keys
Use the built-in utility command to generate a new Ed25519 keypair:
```bash
sudo secure-sudoers-utils gen-keys
```
This generates:
- `secure_sudoers_private_key.pem` (keep this secret)
- `secure_sudoers_public_key.pem`

Move the public key to the trusted system directory:
```bash
sudo mkdir -p /etc/secure-sudoers
sudo mv secure_sudoers_public_key.pem /etc/secure-sudoers/
```

### 3. Create, Validate, and Sign Policy
Define tools and their restrictions in `/etc/secure-sudoers/policy.json`. See [POLICY.md](POLICY.md) for the full specification.

Before signing, it is recommended to validate the policy for errors:
```bash
secure-sudoers-utils check /etc/secure-sudoers/policy.json
```

Once the policy is ready, sign it using the private key:
```bash
sudo secure-sudoers-utils sign /etc/secure-sudoers/policy.json ./secure_sudoers_private_key.pem
```
This creates `/etc/secure-sudoers/policy.json.sig`.

### 4. Install the Environment
Deploy the configuration and set up symlinks:
```bash
sudo secure-sudoers-utils install
```
This command performs the following actions:
- Creates symlinks in `/usr/local/bin` for every tool defined in your policy.
- Writes a secure sudoers drop-in to `/etc/sudoers.d/secure-sudoers`.
- Protects the binaries, configuration, and symlinks with the immutable bit (`chattr +i`).

---

## Administration Utility

The `secure-sudoers-utils` tool provides several subcommands to manage the system:

| Command                         | Description                                                                            |
|---------------------------------|----------------------------------------------------------------------------------------|
| `gen-keys`                      | Generates a new Ed25519 keypair.                                                       |
| `sign <policy_path> <key_path>` | Signs a policy JSON file with a private key.                                           |
| `check <policy_path>`           | Validates a policy JSON file for correctness and best practices.                       |
| `install`                       | Sets up symlinks and sudoers configuration (requires `policy.json` and its signature). |
| `unlock`                        | Removes the immutable bit from all managed files to allow for updates.                 |
| `update <url> <pubkey_path>`    | Securely fetches and verifies policy updates over HTTPS.                               |

### Updating Policies
To update your configuration, you must first unlock the files:
```bash
sudo secure-sudoers-utils unlock
# ... modify policy and re-sign ...
sudo secure-sudoers-utils install
```

## Advanced Features

### Network Updates
Secure Sudoers can securely fetch and verify policy updates over HTTPS:
```bash
sudo secure-sudoers-utils update https://your-server.com/policy.json /etc/secure-sudoers/secure_sudoers_public_key.pem
```
The utility ensures the policy `serial` is higher than the current version to prevent downgrade attacks.

## Building from Source

```bash
# Standard build
cargo build --release

# Build utils with network update support
cargo build -p secure-sudoers-utils --release --features network-update
```

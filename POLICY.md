# Policy Specification - v1.0

Secure Sudoers relies on a signed JSON policy located at `/etc/secure-sudoers/policy.json`.

## Global Settings

| Field                  | Type          | Description                                                  |
|------------------------|---------------|--------------------------------------------------------------|
| `version`              | String        | Must be "1.0".                                               |
| `serial`               | Integer       | Monotonic version number to prevent policy downgrades.       |
| `admin_contact`        | String        | Support information displayed on access denial.              |
| `blocked_paths`        | Array<String> | Absolute paths that are always denied (e.g., `/etc/shadow`). |
| `safe_arg_regex`       | String        | Default regex for validating positional arguments.           |
| `common_env_whitelist` | Array<String> | Environment variables allowed for all tools (e.g., `TERM`).  |

## Tool Configuration

Each tool is an entry in the `tools` map.

### Top-Level Tool Fields

| Field                        | Type          | Description                                                                                                           |
|------------------------------|---------------|-----------------------------------------------------------------------------------------------------------------------|
| `real_binary`                | String        | Absolute path to the binary that will be executed. **Required**.                                                      |
| `id`                         | String        | Optional human-readable rule identifier. Used as `policy.rule_id` in security telemetry. Defaults to the map key.     |
| `verbs`                      | Array<String> | Ordered list of sub-commands the user must provide as the first argument (e.g., `["install", "update"]`).             |
| `help_description`           | String        | Human-readable description of the tool. **Required**.                                                                 |
| `isolation`                  | Object        | Namespace sandboxing settings (see [Isolation](#isolation-sandboxing)).                                               |
| `env_whitelist`              | Array<String> | Additional environment variables allowed for this tool (merged with `common_env_whitelist`).                          |
| `disallowed_positional_args` | Array<String> | List of specific strings that are never allowed as positional arguments (e.g., `["-exec", "--interactive"]`).         |

### Parameters
The `parameters` map defines allowed flags and their validation rules.

| Field       | Type          | Description                                          |
|-------------|---------------|:-----------------------------------------------------|
| `type`      | Enum          | `bool`, `string`, or `path`. **Required**.           |
| `sensitive` | Boolean       | Masks the argument value in logs with `[REDACTED]`.  |
| `regex`     | String        | Pattern the argument must match.                     |
| `choices`   | Array<String> | Set of allowed values (exact match).                 |

For the `path` type, Secure Sudoers resolves symlinks and canonicalizes the path *before* applying regex or checking blocked lists.

### Positional Arguments
The `positional` block defines rules for arguments not associated with a flag.

**This block is optional.** If omitted, Secure Sudoers performs a safety check against the global `safe_arg_regex` and ensures the argument does not start with a `-` to prevent flag injection.

This block should be defined if you need:
- **Path Security**: Set `type: "path"` to ensure positional arguments are canonicalized and checked against `blocked_paths`.
- **Strict Validation**: Use `choices` or `regex` to limit what values can be passed (e.g., specific sub-commands).
- **Redaction**: Use `sensitive: true` to mask the value in logs.

### Isolation (Sandboxing)
- `unshare_network`: Detach the network stack (Default: `false`).
- `unshare_pid`: Isolate the process tree (Default: `false`).
- `unshare_ipc`: Isolate System V IPC and POSIX message queues (Default: `true`).
- `unshare_uts`: Isolate hostname and NIS domain name (Default: `true`).
- `private_mounts`: Overlay directories with an empty `tmpfs`.
- `readonly_mounts`: Bind-mount host directories as read-only.

## Security Telemetry & Rule IDs

Every command validation attempt emits a JSON security event (see [Security Telemetry](README.md#security-telemetry)).
The `policy.rule_id` field in each event is populated from the tool's `id` field if set, otherwise it defaults to the tool's map key.

Use the `id` field to assign stable, versioned rule identifiers that remain meaningful even if the map key changes:

```
"apt": {
  "id": "apt-install-v2",
  "real_binary": "/usr/bin/apt",
  ...
}
```

This allows audit queries like `grep '"rule_id":"apt-install-v2"'` to work consistently across policy updates.

## Example Configuration

```json
{
  "version": "1.0",
  "serial": 42,
  "global_settings": {
    "admin_contact": "admin@example.com",
    "blocked_paths": ["/etc/shadow", "/etc/sudoers"]
  },
  "tools": {
    "apt": {
      "id": "apt-policy-v1",
      "real_binary": "/usr/bin/apt",
      "help_description": "System package manager",
      "verbs": ["install", "update"],
      "parameters": {
        "-y": { "type": "bool" },
        "--config": { "type": "path", "regex": "^/etc/apt/.*" }
      },
      "isolation": {
        "unshare_network": false,
        "private_mounts": ["/tmp"]
      }
    }
  }
}
```

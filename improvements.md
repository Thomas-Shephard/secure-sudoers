# secure-sudoers Deep Scan — Improvement Backlog

This file captures the full audit findings from a read-only functional and structural review.

Baseline status at audit time:
- `cargo test --workspace --all-features` passed.
- `cargo build --workspace --all-features` passed.

## 1) Functional Audit Findings

### 10. Coarse `..` path precheck may over/under-constrain semantics
1. **Location:** `crates/secure-sudoers-common/src/fs.rs::check_path`
2. **Issue:** Early `arg.contains("..")` check is string-based and coarse before component-level processing.
3. **Impact:** Can produce avoidable false denials and duplicate traversal logic complexity.
4. **Suggested Direction:** Rely on component-wise canonical traversal rules and explicit `ParentDir` handling only.

### 11. Disallowed positional argument matching is raw-string exact
1. **Location:** `crates/secure-sudoers-common/src/validator/helpers.rs::push_positional`
2. **Issue:** `disallowed_positional_args` is checked against raw argument strings without normalization/canonical equivalence.
3. **Impact:** Policy intent may be bypassed through semantically equivalent argument variants.
4. **Suggested Direction:** Normalize/canonicalize before disallowed comparisons when policy semantics require equivalence.

### 12. Installer and unlock robustness around signed policy lifecycle
1. **Location:** `crates/secure-sudoers-utils/src/modules/installer.rs` (`install_with_paths`, `unlock_with_paths`)
2. **Issue:** `install` validates JSON but does not verify signature; `unlock` depends on readable/parseable policy.
3. **Impact:** Operational DoS risks and weaker integrity guarantees during lifecycle operations.
4. **Suggested Direction:** Verify signature in installer path and make unlock resilient even when policy parsing fails.

## 2) Niggles & Structural Improvement Areas

### 13. God-module tendencies in core security paths
1. **Location:** `crates/secure-sudoers/src/helpers.rs`, `crates/secure-sudoers/src/isolation.rs`, `crates/secure-sudoers-utils/src/modules/installer.rs`
2. **Issue:** Multiple responsibilities packed into single large modules.
3. **Impact:** Harder auditing, review overhead, and increased regression probability.
4. **Suggested Direction:** Split by concern (invocation parsing, policy loading, redaction, mount ops, installer IO).

### 14. Error model is stringly typed across boundaries
1. **Location:** Cross-crate (`Result<_, String>` throughout runtime paths)
2. **Issue:** Unstructured errors limit context chaining and reliable classification.
3. **Impact:** Fragile error propagation and weaker observability/debuggability.
4. **Suggested Direction:** Introduce typed error enums (`thiserror`) with source preservation and stable categories.

### 15. Dependency surface can be tightened in `secure-sudoers`
1. **Location:** `crates/secure-sudoers/Cargo.toml`
2. **Issue:** Some dependencies appear heavier than runtime requirements (e.g., keygen/testing-oriented crates in runtime crate).
3. **Impact:** Larger attack surface and maintenance overhead.
4. **Suggested Direction:** Re-audit runtime vs dev usage and move non-runtime crates to `dev-dependencies` where possible.

### 16. Critical network update path lacks dedicated automated tests
1. **Location:** `crates/secure-sudoers-utils/src/modules/network.rs` and test suite coverage
2. **Issue:** No focused unit/integration tests for update success/failure matrix (downgrade, oversize body, bad sig, atomic replacement behavior).
3. **Impact:** Elevated regression risk in a security-sensitive update mechanism.
4. **Suggested Direction:** Add module-level tests with local HTTP fixtures and explicit rollback/assertion checks.

### 17. Security-critical tests can silently skip when non-root
1. **Location:** `crates/secure-sudoers/src/testing.rs::require_root!` and root-gated tests in isolation/supervisor paths
2. **Issue:** Tests are skipped rather than failed when privileges are missing.
3. **Impact:** CI may provide optimistic signal without exercising key isolation logic.
4. **Suggested Direction:** Enforce a privileged CI lane (containerized/root-capable) as a required gate.

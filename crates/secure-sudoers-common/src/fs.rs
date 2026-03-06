use crate::models::ValidationContext;
use std::path::Path;

pub fn check_path(
    arg: &str,
    context: &ValidationContext,
    blocked_paths: &[String],
) -> Result<String, String> {
    if arg.contains("..") {
        return Err(format!(
            "Path traversal detected in argument '{}' for '{}'",
            arg, context
        ));
    }
    let canonical_path = std::fs::canonicalize(arg).map_err(|e| {
        format!(
            "Security failure: cannot canonicalize path '{}': {}",
            arg, e
        )
    })?;
    let canonical = canonical_path.to_string_lossy().into_owned();

    for blocked in blocked_paths {
        let blocked_path = Path::new(blocked);
        if canonical_path == blocked_path || canonical_path.starts_with(blocked_path) {
            return Err(format!("Access to blocked path '{}' is denied", arg));
        }
    }
    Ok(canonical)
}

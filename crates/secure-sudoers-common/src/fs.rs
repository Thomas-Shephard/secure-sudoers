pub fn check_path(arg: &str, context: &str, blocked_paths: &[String]) -> Result<String, String> {
    if arg.contains("..") {
        return Err(format!("Path traversal detected in argument '{}' for '{}'", arg, context));
    }
    let canonical = std::fs::canonicalize(arg)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| format!("Security failure: cannot canonicalize path '{}': {}", arg, e))?;
    for blocked in blocked_paths {
        if canonical == *blocked || canonical.starts_with(&format!("{}/", blocked)) {
            return Err(format!("Access to blocked path '{}' is denied", arg));
        }
    }
    Ok(canonical)
}

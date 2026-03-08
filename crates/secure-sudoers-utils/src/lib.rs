pub mod modules;

pub fn require_root() -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 {
        return Err("Root privileges required.".to_string());
    }
    Ok(())
}

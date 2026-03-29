pub mod modules;
use secure_sudoers_common::error::Error;

pub fn require_root() -> Result<(), Error> {
    if unsafe { libc::getuid() } != 0 {
        return Err(Error::System("Root privileges required.".into()));
    }
    Ok(())
}

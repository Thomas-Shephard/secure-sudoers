use serde::{Deserialize, Serialize};

pub mod event_id {
    pub const COMMAND_APPROVED: &str = "SEC-101";
    pub const POLICY_VIOLATION: &str = "SEC-403";
    pub const IDENTITY_SPOOFING: &str = "SEC-500";
    pub const INTERNAL_ERROR: &str = "SEC-500";
    pub const EXEC_FAILURE: &str = "SEC-503";
}

pub mod denial_reason {
    pub const MISSING_TOOL: &str = "missing_tool";
    pub const BLOCKED_PATH: &str = "blocked_path";
    pub const BLOCKED_ARGUMENT: &str = "blocked_argument";
    pub const REGEX_MISMATCH: &str = "regex_mismatch";
    pub const MISSING_VERB: &str = "missing_verb";
    pub const UNKNOWN_VERB: &str = "unknown_verb";
    pub const UNKNOWN_FLAG: &str = "unknown_flag";
    pub const POLICY_ERROR: &str = "policy_error";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub user: String,
    pub uid: u32,
    pub euid: u32,
    pub sudo_uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInfo {
    pub tool: String,
    pub binary_path: String,
    pub binary_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub status: String,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub txn_id: String,
    pub timestamp: String,
    pub identity: IdentityInfo,
    pub context: ContextInfo,
    pub policy: PolicyInfo,
    pub args: Vec<String>,
}

impl SecurityEvent {
    pub fn to_json_or_fallback(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!(
                "CRITICAL: JSON serialization failed for event_id={} txn_id={}: {}",
                self.event_id, self.txn_id, e
            )
        })
    }
}

pub fn rfc3339_now() -> String {
    let mut buf = [0u8; 32];
    let written = unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&ts.tv_sec, &mut tm);
        libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            c"%Y-%m-%dT%H:%M:%SZ".as_ptr(),
            &tm,
        )
    };
    if written == 0 {
        return "1970-01-01T00:00:00Z".to_string();
    }
    std::str::from_utf8(&buf[..written])
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_now_format() {
        let ts = rfc3339_now();
        // Must be "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(ts.len(), 20, "unexpected length: {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn test_security_event_serializes_to_valid_json() {
        let ev = SecurityEvent {
            event_id: event_id::COMMAND_APPROVED.to_string(),
            txn_id: "abc12345".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            identity: IdentityInfo {
                user: "alice".to_string(),
                uid: 1000,
                euid: 0,
                sudo_uid: Some(1000),
            },
            context: ContextInfo {
                tool: "apt".to_string(),
                binary_path: "/usr/bin/apt".to_string(),
                binary_hash: "deadbeef".to_string(),
            },
            policy: PolicyInfo {
                status: "allowed".to_string(),
                rule_id: Some("apt".to_string()),
                reason: None,
            },
            args: vec!["install".to_string()],
        };
        let json = ev.to_json_or_fallback();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(parsed["event_id"], "SEC-101");
        assert_eq!(parsed["txn_id"], "abc12345");
        assert_eq!(parsed["identity"]["user"], "alice");
        assert_eq!(parsed["identity"]["uid"], 1000);
        assert_eq!(parsed["context"]["tool"], "apt");
        assert_eq!(parsed["policy"]["status"], "allowed");
    }

    #[test]
    fn test_to_json_or_fallback_never_panics() {
        let ev = SecurityEvent {
            event_id: "SEC-403".to_string(),
            txn_id: "00000000".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            identity: IdentityInfo {
                user: String::new(),
                uid: 0,
                euid: 0,
                sudo_uid: None,
            },
            context: ContextInfo {
                tool: String::new(),
                binary_path: String::new(),
                binary_hash: String::new(),
            },
            policy: PolicyInfo {
                status: "denied".to_string(),
                rule_id: None,
                reason: None,
            },
            args: vec![],
        };
        let out = ev.to_json_or_fallback();
        assert!(!out.is_empty());
    }
}

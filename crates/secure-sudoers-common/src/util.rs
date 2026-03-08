use base64::{Engine as _, prelude::BASE64_STANDARD};

pub fn read_pem_bytes(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let b64_content: String = content.lines()
        .skip_while(|l| *l != begin.as_str()).skip(1)
        .take_while(|l| *l != end.as_str())
        .map(|l| l.trim())
        .collect();
    if b64_content.is_empty() { return Err(format!("No '{label}' section found in {path}")); }
    base64_to_bytes(&b64_content)
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn base64_to_bytes(b64: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD.decode(b64.trim())
        .map_err(|e| format!("Invalid base64 encoding: {e}"))
}

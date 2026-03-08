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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_bytes_to_base64_and_back() {
        let cases: &[&[u8]] = &[
            b"hello world",
            b"\x00\x01\x02\x03\xff\xfe",
            b"",
            b"The quick brown fox jumps over the lazy dog",
        ];
        for &original in cases {
            let encoded = bytes_to_base64(original);
            let decoded = base64_to_bytes(&encoded).expect("round-trip decode should succeed");
            assert_eq!(decoded, original, "round-trip failed for {:?}", original);
        }
    }

    #[test]
    fn test_base64_to_bytes_invalid() {
        let invalid_cases = &["!@#$", "not-valid==!", "====", "\x01\x02"];
        for &bad in invalid_cases {
            assert!(base64_to_bytes(bad).is_err(), "expected Err for: {:?}", bad);
        }
    }

    fn write_temp_pem(label: &str, body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "-----BEGIN {label}-----").unwrap();
        writeln!(f, "{body}").unwrap();
        writeln!(f, "-----END {label}-----").unwrap();
        f
    }

    #[test]
    fn test_read_pem_bytes_valid() {
        let data: &[u8] = b"\x01\x02\x03\x04\x05";
        let b64 = bytes_to_base64(data);
        let f = write_temp_pem("TEST", &b64);
        let result = read_pem_bytes(f.path().to_str().unwrap(), "TEST").unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_read_pem_bytes_missing_label() {
        let b64 = bytes_to_base64(b"hello");
        let f = write_temp_pem("FOO", &b64);
        let result = read_pem_bytes(f.path().to_str().unwrap(), "BAR");
        assert!(result.is_err(), "expected Err for missing label");
        assert!(result.unwrap_err().contains("No 'BAR' section found"));
    }

    #[test]
    fn test_read_pem_bytes_corrupted_b64() {
        let f = write_temp_pem("TEST", "!!!not_valid_base64!!!");
        let result = read_pem_bytes(f.path().to_str().unwrap(), "TEST");
        assert!(result.is_err(), "expected Err for corrupted base64");
        assert!(result.unwrap_err().contains("Invalid base64"));
    }
}

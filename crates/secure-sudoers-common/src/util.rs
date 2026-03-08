pub fn read_pem_bytes(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let hex_content: String = content.lines().skip_while(|l| *l != begin.as_str()).skip(1)
        .take_while(|l| *l != end.as_str()).flat_map(|l| l.chars()).collect();
    if hex_content.is_empty() { return Err(format!("No '{label}' section found in {path}")); }
    hex_to_bytes(&hex_content)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 { return Err(format!("Odd-length hex string ({} chars)", hex.len())); }
    (0..hex.len()).step_by(2).map(|i| {
        u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex at offset {i}: {e}"))
    }).collect()
}

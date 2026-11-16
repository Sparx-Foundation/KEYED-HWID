//! canonical spellings for common values
//!
//! digests change with every byte, so values must be spelled the same way on every read

/// formats a MAC address as `aa:bb:cc:dd:ee:ff`
///
/// accepts `:`, `-` and `.` separators or none
/// 
/// Returns `None` for malformed input and for the all-zero and broadcast addresses.
pub fn mac(s: &str) -> Option<String> {
    let hex: String = s
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if hex == "000000000000" || hex == "ffffffffffff" {
        return None;
    }
    let octets: Vec<&str> = (0..12).step_by(2).map(|i| &hex[i..i + 2]).collect();
    Some(octets.join(":"))
}

/// formats a hardware id: trimmed, lowercase, without NUL padding or a `0x` prefix
///
/// returns `None` if nothing or only zeros remain
pub fn id(s: &str) -> Option<String> {
    let s = s
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_ascii_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    (!s.is_empty() && s.bytes().any(|b| b != b'0')).then(|| s.to_owned())
}

/// normalizes sorts and deduplicates access point addresses so scan order does not matter
pub fn bssids<'a>(scan: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = scan.into_iter().filter_map(mac).collect();
    out.sort_unstable();
    out.dedup();
    out
}

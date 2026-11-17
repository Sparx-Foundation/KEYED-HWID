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

/// values that firmware vendors leave in unset SMBIOS fields and that cheap spoofers copy
///
/// compared case-insensitively after trimming; hashing them would make unrelated machines look alike
const PLACEHOLDERS: &[&str] = &[
    "to be filled by o.e.m.",
    "to be filled by oem",
    "default string",
    "system serial number",
    "system product name",
    "system manufacturer",
    "system version",
    "base board serial number",
    "chassis serial number",
    "not specified",
    "not applicable",
    "not available",
    "none",
    "n/a",
    "na",
    "oem",
    "o.e.m.",
    "unknown",
    "invalid",
    "empty",
    "null",
    "serial",
    "serialnumber",
    "123456789",
    "0123456789",
    "1234567890",
    "03000200-0400-0500-0006-000700080009",
    "00020003-0004-0005-0006-000700080009",
];

/// formats a vendor serial number like [`id`] and drops placeholders
///
/// returns `None` for the known placeholder strings, and for values made of a single repeated character
/// (`xxxxxxxx`, `ffffffff`, `11111111`) which firmware uses for "not set"
pub fn serial(s: &str) -> Option<String> {
    let s = id(s)?;
    if PLACEHOLDERS.contains(&s.as_str()) {
        return None;
    }
    let mut chars = s.chars().filter(|c| !matches!(c, '-' | ' ' | '.' | ':'));
    let first = chars.next()?;
    chars.any(|c| c != first).then_some(s)
}

/// formats a UUID as lowercase `8-4-4-4-12` hex, for SMBIOS system UUIDs and GPT/volume ids
///
/// accepts braces, missing dashes and upper case. Returns `None` for malformed input, the nil and all-`f` UUIDs and
/// the well-known placeholder. Windows and Linux print the SMBIOS UUID the same way for SMBIOS 2.6 and later, so the
/// result is stable across both.
pub fn uuid(s: &str) -> Option<String> {
    let hex: String = s
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let out = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    serial(&out).filter(|_| hex.bytes().any(|b| b != b'0'))
}

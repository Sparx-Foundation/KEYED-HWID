use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// length of a part digest in bytes
pub const DIGEST_LEN: usize = 16;

/// maximum number of parts per list
pub const MAX_PARTS: usize = 16;

/// maximum label length in bytes
pub const MAX_LABEL_LEN: usize = 32;

const DOMAIN: &[u8] = b"keyed-hwid/v1";

/// errors returned when building or validating a [`Hwid`]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// a list holds more than [`MAX_PARTS`] parts
    #[error("more than {MAX_PARTS} {0} parts")]
    TooManyParts(Kind),
    /// a label is empty, too long or contains characters other than `a-z`, `0-9` and `_`
    #[error("invalid {0} label {1:?}")]
    InvalidLabel(Kind, String),
    /// a label occurs twice in one list
    #[error("duplicate {0} label {1:?}")]
    DuplicateLabel(Kind, String),
    /// a digest is not base64 of [`DIGEST_LEN`] bytes
    #[error("invalid digest")]
    InvalidDigest,
}

/// The list a part belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Kind {
    /// properties of the device itself, such as chip or storage ids
    Hardware,
    /// properties of its surroundings, such as the gateway or nearby access points
    Place,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hardware => "hardware",
            Self::Place => "place",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// the device secret used to key all digests. Zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HwidKey([u8; 32]);

impl HwidKey {
    /// Uses `bytes` as the key directly.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// derives a key from a device secret with HKDF-SHA256
    ///
    /// `info` separates this use from other keys derived from the same secret
    pub fn derive(secret: &[u8], info: &[u8]) -> Self {
        let mut key = [0; 32];
        #[expect(
            clippy::expect_used,
            reason = "32 bytes is within the HKDF-SHA256 output limit"
        )]
        hkdf::Hkdf::<Sha256>::new(Some(DOMAIN), secret)
            .expand(info, &mut key)
            .expect("valid output length");
        Self(key)
    }

    fn mac(&self) -> Hmac<Sha256> {
        #[expect(clippy::expect_used, reason = "HMAC accepts keys of any length")]
        <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0).expect("valid key length")
    }
}

impl fmt::Debug for HwidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HwidKey(..)")
    }
}

/// a truncated HMAC-SHA256. Displays and parses as standard base64
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; DIGEST_LEN]);

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.0))
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bytes = BASE64.decode(s).map_err(|_| Error::InvalidDigest)?;
        bytes.try_into().map(Self).map_err(|_| Error::InvalidDigest)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// a labelled digest of one measured value
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Part {
    /// What was measured, e.g. `soc` or `gateway`.
    pub label: String,
    /// The keyed digest of the value.
    pub digest: Digest,
}

impl Part {
    /// computes the part for `value`
    ///
    /// the digest is `HMAC-SHA256(key, "keyed-hwid/v1" 0x00 kind 0x00 label 0x00 value)`
    /// truncated to [`DIGEST_LEN`] bytes
    pub fn new(
        key: &HwidKey,
        kind: Kind,
        label: &str,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        validate_label(kind, label)?;
        let mut mac = key.mac();
        for field in [DOMAIN, kind.as_str().as_bytes(), label.as_bytes()] {
            mac.update(field);
            mac.update(&[0]);
        }
        mac.update(value.as_ref());
        let mut digest = [0; DIGEST_LEN];
        digest.copy_from_slice(&mac.finalize().into_bytes()[..DIGEST_LEN]);
        Ok(Self {
            label: label.to_owned(),
            digest: Digest(digest),
        })
    }
}

/// hardware and place parts of one device
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hwid {
    /// Parts describing the device.
    pub hardware: Vec<Part>,
    /// Parts describing its surroundings.
    pub place: Vec<Part>,
}

impl Hwid {
    /// builds a HWID from `(label, value)` pairs
    ///
    /// omit values that could not be measured rather than passing empty ones
    pub fn build<L, V>(
        key: &HwidKey,
        hardware: impl IntoIterator<Item = (L, V)>,
        place: impl IntoIterator<Item = (L, V)>,
    ) -> Result<Self, Error>
    where
        L: AsRef<str>,
        V: AsRef<[u8]>,
    {
        Ok(Self {
            hardware: parts(key, Kind::Hardware, hardware)?,
            place: parts(key, Kind::Place, place)?,
        })
    }

    /// checks labels and list sizes of a HWID received from a device
    pub fn validate(&self) -> Result<(), Error> {
        for (kind, parts) in [(Kind::Hardware, &self.hardware), (Kind::Place, &self.place)] {
            for part in parts {
                validate_label(kind, &part.label)?;
            }
            validate_list(kind, parts)?;
        }
        Ok(())
    }
}

fn parts<L, V>(
    key: &HwidKey,
    kind: Kind,
    values: impl IntoIterator<Item = (L, V)>,
) -> Result<Vec<Part>, Error>
where
    L: AsRef<str>,
    V: AsRef<[u8]>,
{
    let parts = values
        .into_iter()
        .map(|(label, value)| Part::new(key, kind, label.as_ref(), value))
        .collect::<Result<Vec<_>, _>>()?;
    validate_list(kind, &parts)?;
    Ok(parts)
}

fn validate_label(kind: Kind, label: &str) -> Result<(), Error> {
    let valid = !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidLabel(kind, label.to_owned()))
    }
}

fn validate_list(kind: Kind, parts: &[Part]) -> Result<(), Error> {
    if parts.len() > MAX_PARTS {
        return Err(Error::TooManyParts(kind));
    }
    for (i, part) in parts.iter().enumerate() {
        if parts[..i].iter().any(|p| p.label == part.label) {
            return Err(Error::DuplicateLabel(kind, part.label.clone()));
        }
    }
    Ok(())
}

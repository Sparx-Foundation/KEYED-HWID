use std::num::NonZeroUsize;

use semver::Version;

use crate::compare::same;
use crate::part::{Hwid, Part};

/// thresholds used by [`judge`]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rules {
    /// parts that must match for two lists to describe the same hardware or place
    pub min_matching: NonZeroUsize,
    /// look-back in seconds for hardware and place contradictions
    pub window_secs: i64,
    /// look-back in seconds for version contradictions
    pub version_window_secs: i64,
    /// hardware labels that must match whenever both lists hold them, regardless of `min_matching`
    ///
    /// meant for values that are attested or otherwise hard to forge, such as a digest of the TPM endorsement key;
    /// a spoofer that keeps the easy parts and changes an anchor is still caught
    pub anchors: Vec<String>,
    /// look-back in seconds for [`Signal::HardwareChurn`]
    pub churn_window_secs: i64,
    /// distinct hardware sets allowed within `churn_window_secs` before [`Signal::HardwareChurn`]
    pub max_hardware_sets: NonZeroUsize,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            min_matching: NonZeroUsize::MIN.saturating_add(1),
            window_secs: 24 * 60 * 60,
            version_window_secs: 60 * 60,
            anchors: Vec::new(),
            churn_window_secs: 30 * 24 * 60 * 60,
            max_hardware_sets: NonZeroUsize::MIN.saturating_add(2),
        }
    }
}

/// A report as stored by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Report {
    /// unix time in seconds.
    pub at: i64,
    /// name of the software the device runs
    pub unit: String,
    /// its version (non-semver versions are treated as unordered)
    pub version: String,
    /// `None` if the device sent no HWID
    pub hwid: Option<Hwid>,
    /// position of the rolling token the device presented, `None` if it presented none
    ///
    /// the server hands out a fresh random token with every accepted report and records the sequence number it
    /// belongs to; the device must return the latest one with its next report. A copied identity that runs in
    /// parallel with the original sooner or later presents a token that was already used, which no single device
    /// can do, even if it replays the original's digests exactly.
    #[cfg_attr(feature = "serde", serde(default))]
    pub seq: Option<u64>,
}

/// a contradiction between reports that a single device cannot produce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Signal {
    /// a rolling token was presented that is not newer than one already seen: two devices share the state
    Forked,
    /// different hardware within the window
    TwoDevices,
    /// fewer hardware parts than needed for a match, while recent reports had enough
    Withheld,
    /// the place changed and changed back within the window
    TwoPlaces,
    /// more distinct hardware sets than allowed within the churn window, or a return to an earlier set after a
    /// different one (A, B, A)
    HardwareChurn,
    /// a version that is neither the same as nor newer than one reported within the version window
    TwoVersions,
}

impl Signal {
    /// serde
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forked => "forked",
            Self::TwoDevices => "two_devices",
            Self::Withheld => "withheld",
            Self::TwoPlaces => "two_places",
            Self::HardwareChurn => "hardware_churn",
            Self::TwoVersions => "two_versions",
        }
    }
}

/// checks `report` against earlier reports of the same device, newest first
///
/// moves, updates and replacing a single component are expected and return `None`
pub fn judge(earlier: &[Report], report: &Report, rules: &Rules) -> Option<Signal> {
    let since = |secs: i64| earlier.iter().filter(move |r| r.at >= report.at - secs);
    let min = rules.min_matching.get();

    if let Some(seq) = report.seq
        && earlier.iter().filter_map(|r| r.seq).any(|seen| seen >= seq)
    {
        return Some(Signal::Forked);
    }

    if let Some(hwid) = &report.hwid {
        let recent: Vec<&Hwid> = since(rules.window_secs)
            .filter_map(|r| r.hwid.as_ref())
            .filter(|h| !h.hardware.is_empty())
            .collect();
        if recent.iter().any(|h| {
            !same(&hwid.hardware, &h.hardware, min)
                || anchor_differs(&hwid.hardware, &h.hardware, &rules.anchors)
        }) {
            return Some(Signal::TwoDevices);
        }
        if hwid.hardware.len() < min && recent.iter().any(|h| h.hardware.len() >= min) {
            return Some(Signal::Withheld);
        }
        if returned_to_earlier_place(hwid, &recent, min) {
            return Some(Signal::TwoPlaces);
        }
        let churn: Vec<&Hwid> = since(rules.churn_window_secs)
            .filter_map(|r| r.hwid.as_ref())
            .filter(|h| !h.hardware.is_empty())
            .collect();
        if hardware_sets(std::iter::once(hwid).chain(churn.iter().copied()), rules)
            > rules.max_hardware_sets.get()
            || returned_to_earlier_hardware(hwid, &churn, rules)
        {
            return Some(Signal::HardwareChurn);
        }
    }

    let version = Version::parse(&report.version).ok();
    let downgrade = since(rules.version_window_secs)
        .filter(|r| r.unit == report.unit && r.version != report.version)
        .any(|r| match (&version, Version::parse(&r.version)) {
            (Some(new), Ok(old)) => *new < old,
            _ => true,
        });
    downgrade.then_some(Signal::TwoVersions)
}

/// whether an anchor label is present in both lists with different digests
fn anchor_differs(a: &[Part], b: &[Part], anchors: &[String]) -> bool {
    anchors.iter().any(|label| {
        let find = |parts: &[Part]| parts.iter().find(|p| &p.label == label).map(|p| p.digest);
        matches!((find(a), find(b)), (Some(x), Some(y)) if x != y)
    })
}

/// A, B, A for hardware: matches an older set that the latest report did not match
///
/// catches one licence alternating between two machines at intervals longer than `window_secs`
fn returned_to_earlier_hardware(hwid: &Hwid, recent: &[&Hwid], rules: &Rules) -> bool {
    let min = rules.min_matching.get();
    let matches = |a: &[Part], b: &[Part]| same(a, b, min) && !anchor_differs(a, b, &rules.anchors);
    let Some(latest) = recent.first() else {
        return false;
    };
    !matches(&hwid.hardware, &latest.hardware)
        && recent[1..].iter().any(|h| {
            matches(&hwid.hardware, &h.hardware) && !matches(&h.hardware, &latest.hardware)
        })
}

/// counts groups of hardware lists that describe the same hardware, joining each list to the first group it matches
fn hardware_sets<'a>(hwids: impl Iterator<Item = &'a Hwid>, rules: &Rules) -> usize {
    let min = rules.min_matching.get();
    let mut groups: Vec<&[Part]> = Vec::new();
    for hwid in hwids.filter(|h| !h.hardware.is_empty()) {
        let known = groups.iter().any(|g| {
            same(&hwid.hardware, g, min) && !anchor_differs(&hwid.hardware, g, &rules.anchors)
        });
        if !known {
            groups.push(&hwid.hardware);
        }
    }
    groups.len()
}

/// A, B, A: the place differs from the latest report but matches an older one that the latest did not match
fn returned_to_earlier_place(hwid: &Hwid, recent: &[&Hwid], min: usize) -> bool {
    let mut placed = recent.iter().filter(|h| !h.place.is_empty());
    let Some(latest) = placed.next() else {
        return false;
    };
    !same(&hwid.place, &latest.place, min)
        && placed.any(|h| same(&hwid.place, &h.place, min) && !same(&h.place, &latest.place, min))
}

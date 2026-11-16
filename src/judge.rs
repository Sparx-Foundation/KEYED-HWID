use std::num::NonZeroUsize;

use semver::Version;

use crate::compare::same;
use crate::part::Hwid;

/// thresholds used by [`judge`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rules {
    /// parts that must match for two lists to describe the same hardware or place
    pub min_matching: NonZeroUsize,
    /// look-back in seconds for hardware and place contradictions
    pub window_secs: i64,
    /// look-back in seconds for version contradictions
    pub version_window_secs: i64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            min_matching: NonZeroUsize::MIN.saturating_add(1),
            window_secs: 24 * 60 * 60,
            version_window_secs: 60 * 60,
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
}

/// a contradiction between reports that a single device cannot produce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Signal {
    /// different hardware within the window
    TwoDevices,
    /// the place changed and changed back within the window
    TwoPlaces,
    /// a version that is neither the same as nor newer than one reported within the version window
    TwoVersions,
}

impl Signal {
    /// serde
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TwoDevices => "two_devices",
            Self::TwoPlaces => "two_places",
            Self::TwoVersions => "two_versions",
        }
    }
}

/// checks `report` against earlier reports of the same device, newest first
///
/// changed parts
/// moves and updates are expected and return `None`
pub fn judge(earlier: &[Report], report: &Report, rules: &Rules) -> Option<Signal> {
    let since = |secs: i64| earlier.iter().filter(move |r| r.at >= report.at - secs);
    let min = rules.min_matching.get();

    if let Some(hwid) = &report.hwid {
        let recent: Vec<&Hwid> = since(rules.window_secs)
            .filter_map(|r| r.hwid.as_ref())
            .filter(|h| !h.hardware.is_empty())
            .collect();
        if recent
            .iter()
            .any(|h| !same(&hwid.hardware, &h.hardware, min))
        {
            return Some(Signal::TwoDevices);
        }
        if returned_to_earlier_place(hwid, &recent, min) {
            return Some(Signal::TwoPlaces);
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

/// A, B, A: the place differs from the latest report but matches an older one that the latest did not match
fn returned_to_earlier_place(hwid: &Hwid, recent: &[&Hwid], min: usize) -> bool {
    let mut placed = recent.iter().filter(|h| !h.place.is_empty());
    let Some(latest) = placed.next() else {
        return false;
    };
    !same(&hwid.place, &latest.place, min)
        && placed.any(|h| same(&hwid.place, &h.place, min) && !same(&h.place, &latest.place, min))
}

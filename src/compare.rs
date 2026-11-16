use crate::part::Part;

/// labels of `a` split by whether `b` holds an equal part
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Comparison {
    /// labels with the same digest in both lists
    pub matching: Vec<String>,
    /// labels that differ or are missing in `b`
    pub changed: Vec<String>,
}

/// compares two part lists by label and digest
pub fn compare(a: &[Part], b: &[Part]) -> Comparison {
    let (matching, changed): (Vec<&Part>, Vec<&Part>) = a.iter().partition(|part| b.contains(part));
    let labels = |parts: Vec<&Part>| parts.into_iter().map(|p| p.label.clone()).collect();
    Comparison {
        matching: labels(matching),
        changed: labels(changed),
    }
}

/// returns whether `a` and `b` share at least `min_matching` parts
///
/// the threshold is capped at the length of the shorter list so an empty list matches anything
pub fn same(a: &[Part], b: &[Part], min_matching: usize) -> bool {
    let required = min_matching.min(a.len()).min(b.len());
    a.iter().filter(|part| b.contains(part)).count() >= required
}

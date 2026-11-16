#![allow(missing_docs, clippy::expect_used)]

use std::num::NonZeroUsize;

use keyed_hwid::normalize;
use keyed_hwid::{
    Digest, Error, Hwid, HwidKey, Kind, MAX_PARTS, Part, Report, Rules, Signal, compare, judge,
    same,
};

const T0: i64 = 1_798_761_600;

const HW_A: [(&str, &str); 3] = [("soc", "1"), ("emmc", "2"), ("se", "3")];
const HW_B: [(&str, &str); 3] = [("soc", "1"), ("emmc", "12"), ("se", "13")];
const HOME: [(&str, &str); 3] = [
    ("gateway", "g1"),
    ("bssid_1", "w1"),
    ("tz", "Europe/Berlin"),
];
const AWAY: [(&str, &str); 3] = [
    ("gateway", "g2"),
    ("bssid_1", "w2"),
    ("tz", "Europe/Berlin"),
];

fn key() -> HwidKey {
    HwidKey::from_bytes([7; 32])
}

fn hwid(hardware: &[(&str, &str)], place: &[(&str, &str)]) -> Hwid {
    Hwid::build(&key(), hardware.iter().copied(), place.iter().copied()).expect("valid input")
}

fn report(at: i64, version: &str, hwid: Hwid) -> Report {
    Report {
        at,
        unit: "os".into(),
        version: version.into(),
        hwid: Some(hwid),
    }
}

fn part(key: &HwidKey, kind: Kind, label: &str, value: &str) -> Part {
    Part::new(key, kind, label, value).expect("valid label")
}

#[test]
fn digest_matches_reference_vector() {
    // python3 -c "import hmac,hashlib,base64; m=b'keyed-hwid/v1\x00hardware\x00soc\x00'+b'1234abcd'; print(base64.b64encode(hmac.new(bytes([7]*32),m,hashlib.sha256).digest()[:16]).decode())"
    let p = part(&key(), Kind::Hardware, "soc", "1234abcd");
    assert_eq!(p.digest.to_string(), "ThTvc3recKv6o8C8ABBvFw==");
}

#[test]
fn digest_depends_on_kind_label_and_key() {
    let base = part(&key(), Kind::Hardware, "soc", "v").digest;
    assert_ne!(base, part(&key(), Kind::Place, "soc", "v").digest);
    assert_ne!(base, part(&key(), Kind::Hardware, "emmc", "v").digest);
    assert_ne!(
        base,
        part(&HwidKey::from_bytes([8; 32]), Kind::Hardware, "soc", "v").digest
    );
    assert_ne!(
        part(&key(), Kind::Hardware, "ab", "c").digest,
        part(&key(), Kind::Hardware, "a", "bc").digest
    );
}

#[test]
fn rejects_invalid_input() {
    let k = key();
    for label in ["", "SoC", "a-b", &"a".repeat(33)] {
        assert!(
            matches!(
                Part::new(&k, Kind::Hardware, label, "v"),
                Err(Error::InvalidLabel(..))
            ),
            "{label:?}"
        );
    }
    assert!(matches!(
        Hwid::build(&k, [("soc", "1"), ("soc", "2")], []),
        Err(Error::DuplicateLabel(..))
    ));

    let labels: Vec<String> = (0..=MAX_PARTS).map(|i| format!("p{i}")).collect();
    let many = labels.iter().map(|l| (l.as_str(), "v"));
    assert_eq!(
        Hwid::build(&k, many, []),
        Err(Error::TooManyParts(Kind::Hardware))
    );

    assert_eq!("AAAA".parse::<Digest>(), Err(Error::InvalidDigest));
    assert_eq!("not base64".parse::<Digest>(), Err(Error::InvalidDigest));
    let d = part(&k, Kind::Hardware, "soc", "v").digest;
    assert_eq!(d.to_string().parse(), Ok(d));
}

#[test]
fn same_requires_min_matching_parts() {
    let home = hwid(&HW_A, &HOME);
    let new_router = hwid(
        &HW_A,
        &[
            ("gateway", "g9"),
            ("bssid_1", "w1"),
            ("tz", "Europe/Berlin"),
        ],
    );
    assert!(same(&home.place, &new_router.place, 2));
    assert!(!same(&home.place, &hwid(&HW_A, &AWAY).place, 2));
    assert!(same(&home.place, &[], 2));

    let c = compare(&hwid(&HW_B, &HOME).hardware, &home.hardware);
    assert_eq!(c.matching, ["soc"]);
    assert_eq!(c.changed, ["emmc", "se"]);
}

#[test]
fn expected_changes_are_not_flagged() {
    let rules = Rules::default();
    let first = report(T0, "1.6.0", hwid(&HW_A, &HOME));
    let updated = report(T0 + 60, "1.7.0", hwid(&HW_A, &HOME));
    let moved = report(T0 + 120, "1.7.0", hwid(&HW_A, &AWAY));

    assert_eq!(judge(std::slice::from_ref(&first), &updated, &rules), None);
    assert_eq!(judge(&[updated.clone(), first], &moved, &rules), None);

    let much_later = report(T0 + 2 * 86_400, "1.6.0", hwid(&HW_B, &AWAY));
    assert_eq!(judge(&[updated], &much_later, &rules), None);
}

#[test]
fn contradictions_are_flagged() {
    let rules = Rules::default();
    let first = report(T0, "1.6.0", hwid(&HW_A, &HOME));
    let updated = report(T0 + 60, "1.7.0", hwid(&HW_A, &HOME));
    let moved = report(T0 + 120, "1.7.0", hwid(&HW_A, &AWAY));
    let history = [moved, updated.clone(), first];

    let back = report(T0 + 180, "1.7.0", hwid(&HW_A, &HOME));
    assert_eq!(judge(&history, &back, &rules), Some(Signal::TwoPlaces));

    let other_device = report(T0 + 240, "1.7.0", hwid(&HW_B, &HOME));
    assert_eq!(
        judge(std::slice::from_ref(&updated), &other_device, &rules),
        Some(Signal::TwoDevices)
    );

    let downgrade = report(T0 + 300, "1.6.0", hwid(&HW_A, &HOME));
    assert_eq!(
        judge(&[updated], &downgrade, &rules),
        Some(Signal::TwoVersions)
    );
}

#[test]
fn min_matching_is_configurable() {
    let strict = Rules {
        min_matching: NonZeroUsize::new(3).expect("non-zero"),
        ..Rules::default()
    };
    let before = report(T0, "1.7.0", hwid(&HW_A, &HOME));
    let one_part_changed = report(
        T0 + 60,
        "1.7.0",
        hwid(&[("soc", "1"), ("emmc", "2"), ("se", "9")], &HOME),
    );
    assert_eq!(
        judge(
            std::slice::from_ref(&before),
            &one_part_changed,
            &Rules::default()
        ),
        None
    );
    assert_eq!(
        judge(&[before], &one_part_changed, &strict),
        Some(Signal::TwoDevices)
    );
}

#[test]
fn derived_keys_are_deterministic_and_separated() {
    let a = HwidKey::derive(&[1; 32], b"hwid");
    let b = HwidKey::derive(&[1; 32], b"other");
    let digest = |k: &HwidKey| part(k, Kind::Hardware, "soc", "v").digest;
    assert_eq!(digest(&a), digest(&HwidKey::derive(&[1; 32], b"hwid")));
    assert_ne!(digest(&a), digest(&b));
}

#[test]
fn normalize_produces_canonical_values() {
    assert_eq!(
        normalize::mac("AA-BB-CC-DD-EE-0F").as_deref(),
        Some("aa:bb:cc:dd:ee:0f")
    );
    assert_eq!(
        normalize::mac(" aabb.ccdd.ee0f ").as_deref(),
        Some("aa:bb:cc:dd:ee:0f")
    );
    assert_eq!(normalize::mac("00:00:00:00:00:00"), None);
    assert_eq!(normalize::mac("ff:ff:ff:ff:ff:ff"), None);
    assert_eq!(normalize::mac("aa:bb"), None);

    assert_eq!(normalize::id(" 0x00ABcd\0").as_deref(), Some("00abcd"));
    assert_eq!(normalize::id("0000"), None);

    let scan = [
        "98-9B-CB-11-22-33",
        "3c:a6:2f:aa:bb:cd",
        "98:9b:cb:11:22:33",
    ];
    assert_eq!(
        normalize::bssids(scan),
        ["3c:a6:2f:aa:bb:cd", "98:9b:cb:11:22:33"]
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_uses_base64_digests() {
    let h = hwid(&[("soc", "1")], &[("tz", "Europe/Berlin")]);
    let json = serde_json::to_string(&h).expect("serialize");
    assert!(
        json.starts_with(r#"{"hardware":[{"label":"soc","digest":""#),
        "{json}"
    );
    assert_eq!(serde_json::from_str::<Hwid>(&json).expect("deserialize"), h);
    assert_eq!(
        serde_json::to_string(&Signal::TwoDevices).expect("serialize"),
        r#""two_devices""#
    );
    assert!(
        serde_json::from_str::<Hwid>(
            r#"{"hardware":[{"label":"soc","digest":"AAAA"}],"place":[]}"#
        )
        .is_err()
    );
}

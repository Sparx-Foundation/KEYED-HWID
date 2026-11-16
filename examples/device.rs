//! Builds a HWID the way a device would and prints what it sends.
//!
//! The readings are hard-coded here; a device would read them from sysfs, the ARP table and a Wi-Fi scan.

use keyed_hwid::normalize::{bssids, id, mac};
use keyed_hwid::{Hwid, HwidKey};

fn main() -> Result<(), keyed_hwid::Error> {
    let secret = [0x42; 32]; // from a secure element or a board secret
    let key = HwidKey::derive(&secret, b"hwid");

    let hardware: Vec<(&str, String)> = [
        ("soc", id("0x10000000A9ADF0FF\0")),
        ("emmc", id("9f544930303847080123456789abcdef")),
        ("eth_mac", mac("DC-A6-32-01-02-03")),
        ("se", id("0123A1B2C3D4E5F6EE")),
    ]
    .into_iter()
    .filter_map(|(label, value)| Some((label, value?)))
    .collect();

    let scan = [
        "98:9B:CB:11:22:33",
        "3c:a6:2f:aa:bb:cd",
        "98:9b:cb:11:22:33",
    ];
    let mut place: Vec<(&str, String)> = Vec::new();
    place.extend(mac("3c:a6:2f:aa:bb:cc").map(|gw| ("gateway", gw)));
    place.extend(["bssid_1", "bssid_2"].into_iter().zip(bssids(scan)));
    place.push(("tz", "Europe/Berlin".into()));

    let hwid = Hwid::build(&key, hardware, place)?;

    for (kind, parts) in [("hardware", &hwid.hardware), ("place", &hwid.place)] {
        for part in parts {
            println!("{kind:<8} {:<8} {}", part.label, part.digest);
        }
    }
    Ok(())
}

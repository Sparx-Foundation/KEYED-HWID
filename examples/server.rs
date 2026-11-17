//! Feeds a sequence of reports through `judge` the way a server would.
//!
//! The device side is simulated with the same key; the server itself only ever sees labels and digests.

use keyed_hwid::{Digest, Hwid, HwidKey, Kind, Part, Report, Rules, compare, judge};

const DAY: i64 = 24 * 60 * 60;

type Facts<'a> = &'a [(&'a str, &'a str)];

/// A part as received on the wire.
struct WirePart {
    label: String,
    digest: String,
}

fn decode(parts: &[WirePart]) -> Result<Vec<Part>, keyed_hwid::Error> {
    parts
        .iter()
        .map(|p| {
            Ok(Part {
                label: p.label.clone(),
                digest: p.digest.parse::<Digest>()?,
            })
        })
        .collect()
}

fn encode(parts: &[Part]) -> Vec<WirePart> {
    parts
        .iter()
        .map(|p| WirePart {
            label: p.label.clone(),
            digest: p.digest.to_string(),
        })
        .collect()
}

struct Server {
    rules: Rules,
    history: Vec<Report>,
}

impl Server {
    fn receive(
        &mut self,
        at: i64,
        version: &str,
        hardware: &[WirePart],
        place: &[WirePart],
    ) -> Result<(), keyed_hwid::Error> {
        let hwid = Hwid {
            hardware: decode(hardware)?,
            place: decode(place)?,
        };
        hwid.validate()?;

        if let Some(last) = self.history.first().and_then(|r| r.hwid.as_ref()) {
            for (kind, now, before) in [
                (Kind::Hardware, &hwid.hardware, &last.hardware),
                (Kind::Place, &hwid.place, &last.place),
            ] {
                let c = compare(now, before);
                let changed = if c.changed.is_empty() {
                    String::new()
                } else {
                    format!(", changed: {}", c.changed.join(", "))
                };
                println!(
                    "  {kind:<8} {}/{} unchanged{changed}",
                    c.matching.len(),
                    now.len()
                );
            }
        }

        let report = Report {
            at,
            unit: "os".into(),
            version: version.into(),
            hwid: Some(hwid),
            seq: None,
        };
        match judge(&self.history, &report, &self.rules) {
            Some(signal) => println!("  flagged: {}", signal.as_str()),
            None => println!("  ok"),
        }
        self.history.insert(0, report);
        self.history.truncate(5);
        Ok(())
    }
}

fn device(
    key: &HwidKey,
    hardware: &[(&str, &str)],
    place: &[(&str, &str)],
) -> (Vec<WirePart>, Vec<WirePart>) {
    let hwid =
        Hwid::build(key, hardware.iter().copied(), place.iter().copied()).unwrap_or_default();
    (encode(&hwid.hardware), encode(&hwid.place))
}

fn main() -> Result<(), keyed_hwid::Error> {
    let key = HwidKey::from_bytes([0x42; 32]);
    let hardware = [
        ("soc", "1000a9"),
        ("emmc", "9f54"),
        ("eth_mac", "dc:a6:32:01:02:03"),
    ];
    let home = [
        ("gateway", "3c:a6:2f:aa:bb:cc"),
        ("bssid_1", "98:9b:cb:11:22:33"),
        ("tz", "Europe/Berlin"),
    ];
    let new_router = [
        ("gateway", "44:4e:6d:00:00:01"),
        ("bssid_1", "98:9b:cb:11:22:33"),
        ("tz", "Europe/Berlin"),
    ];
    let travel = [
        ("gateway", "f0:9f:c2:10:20:30"),
        ("bssid_1", "00:11:22:33:44:55"),
        ("tz", "Europe/Rome"),
    ];

    let mut server = Server {
        rules: Rules::default(),
        history: Vec::new(),
    };
    let t0 = 1_798_761_600;
    let steps: [(&str, i64, &str, Facts); 4] = [
        ("first report", t0, "1.6.0", &home),
        ("update", t0 + 600, "1.7.0", &home),
        ("new router", t0 + DAY, "1.7.0", &new_router),
        ("moved", t0 + 3 * DAY, "1.7.0", &travel),
    ];
    for (name, at, version, place) in steps {
        println!("{name}");
        let (hw, pl) = device(&key, &hardware, place);
        server.receive(at, version, &hw, &pl)?;
    }

    println!("copied identity on other hardware");
    let (hw, pl) = device(&HwidKey::from_bytes([0x13; 32]), &hardware, &home);
    server.receive(t0 + 3 * DAY + 3600, "1.7.0", &hw, &pl)
}

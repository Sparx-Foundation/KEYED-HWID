# keyed-hwid

Privacy-preserving hardware ids for detecting cloned device identities.

A device hashes each property of its hardware (SoC id, storage id, MAC address) and of its surroundings (gateway,
nearby access points, time zone) with HMAC-SHA256 under a device-local key, and reports only the label and digest of
each. The server compares reports of the same device part by part. It can tell that a device kept its hardware and
moved, or that two different machines are reporting under one identity, but it never sees a measured value. Digests
from different devices cannot be correlated.

> [!NOTE]  
> The crate does no I/O.

## Example

```rust
use keyed_hwid::{normalize, Hwid, HwidKey, Rules, judge};

// Device
let key = HwidKey::derive(&device_secret, b"hwid");
let gateway = normalize::mac(&gateway_mac).unwrap_or_default();
let hwid = Hwid::build(&key, [("soc", soc_id), ("emmc", emmc_cid)], [("gateway", gateway), ("tz", tz)])?;

// Server
hwid.validate()?;
if let Some(signal) = judge(&previous_reports, &report, &Rules::default()) {
    // hold the identity for review
}
```

Runnable versions are in `examples/`:

```sh
cargo run --example device
cargo run --example server
```

## Format

```
digest = HMAC-SHA256(key, "keyed-hwid/v1" || 0x00 || kind || 0x00 || label || 0x00 || value)[..16]
kind   = "hardware" | "place"
label  = [a-z0-9_]{1,32}, unique per list, at most 16 parts per list
```

Values must be spelled the same way on every read; `normalize` covers MAC addresses, hardware ids and access point
lists. Leave out a property the device cannot read instead of hashing an empty value.

Reference vector: key `[0x07; 32]`, kind `hardware`, label `soc`, value `1234abcd` gives `ThTvc3recKv6o8C8ABBvFw==`.

## Matching

Two part lists describe the same hardware or place if at least `min_matching` parts (default 2) are equal, or all
parts of the shorter list if it has fewer. `judge` compares a new report with earlier ones of the same identity
and returns a `Signal` for:

- `forked`: a rolling token that is not newer than one already presented (see below)
- `two_devices`: hardware that does not match a report from the last 24 hours, or that differs in an anchor part
- `withheld`: fewer hardware parts than `min_matching` after recent reports had enough
- `two_places`: a return to an earlier place within 24 hours after a different one (A, B, A)
- `hardware_churn`: more than 3 distinct hardware sets within 30 days, or a return to an earlier hardware set after
  a different one (A, B, A); e.g. a licence alternated between machines more than 24 hours apart, or a device whose
  key keeps being wiped
- `two_versions`: a version older than one reported within the last hour

Replacing a single component, a new router, moving and updating do not produce a signal. The thresholds are
configurable through `Rules`.

`Rules::anchors` names hardware labels that must match whenever both reports hold them. Use it for values that are
attested or hard to forge, such as a digest of the TPM endorsement key, so that a spoofer cannot keep the easy parts
and swap the rest.

## Rolling tokens

Digests are static, so a copied identity can replay them exactly. To catch that, hand the device a fresh random
token with every accepted report, remember which sequence number it belongs to, and require it with the next report.
Store the sequence number in `Report::seq`. Two devices sharing one identity sooner or later present the same token
twice and `judge` returns `forked`. The token reveals nothing about the hardware.


## Scope

The scheme assumes the key stays on the device, ideally in a secure element. It makes a copied identity visible; it
does not prevent copying, and a device that leaks its key can be imitated. Pair it with attestation of the device
key.


## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your
option.

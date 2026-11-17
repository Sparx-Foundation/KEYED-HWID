//! anonymous hardware ids built from keyed parts
//!
//! a device measures facts about its hardware and its surroundings and sends one HMAC per fact, keyed with a secret
//! that stays on the device
//!
//! a server can then tell whether two reports come from the same hardware in the same
//! place without learning any of the measured values, and without being able to link two devices
//!
//! ```
//! use keyed_hwid::{Hwid, HwidKey, same};
//!
//! let key = HwidKey::from_bytes([7; 32]);
//! let before = Hwid::build(&key, [("soc", "1234abcd"), ("emmc", "9f00")], [("gateway", "aa:bb:cc:dd:ee:ff")])?;
//! let after = Hwid::build(&key, [("soc", "1234abcd"), ("emmc", "9f00")], [("gateway", "11:22:33:44:55:66")])?;
//!
//! assert!(same(&before.hardware, &after.hardware, 2));
//! assert!(!same(&before.place, &after.place, 1));
//! # Ok::<(), keyed_hwid::Error>(())
//! ```
//!
//! the crate performs no i/o
//! measuring values is up to the device storing reports is up to the server

mod compare;
mod judge;
pub mod normalize;
mod part;

pub use compare::{Comparison, compare, same};
pub use judge::{Report, Rules, Signal, judge};
pub use part::{DIGEST_LEN, Digest, Error, Hwid, HwidKey, Kind, MAX_LABEL_LEN, MAX_PARTS, Part};

# Changelog

## 0.1.0 - unreleased

Initial release.

- `Report::seq` and `Signal::Forked` for rolling-token clone detection
- `Rules::anchors` for parts that must always match
- `Signal::Withheld` for reports that drop hardware parts to dodge the match
- `Signal::HardwareChurn` (too many hardware sets, or A, B, A) with `Rules::churn_window_secs` and `Rules::max_hardware_sets`
- `normalize::serial` and `normalize::uuid`, which drop firmware placeholders
- `Rules` is no longer `Copy`

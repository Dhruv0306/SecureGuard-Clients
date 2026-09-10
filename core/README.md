# secureguard-core

Detection engine core: exact-hash matching, YARA-X pattern matching, Shannon-entropy
packer detection, and weighted scoring, tied together into a `CLEAN`/`SUSPICIOUS`/
`MALICIOUS` verdict. All scoring constants are ported directly from the Java backend's
`SecurityServiceImpl` (see comments at each constant's definition), not re-derived.

## Requirements

Rust 1.74+ (matches YARA-X's own MSRV). If you're on a Rust toolchain installed any
time in the last couple of years via `rustup`, you're fine, this only matters if
you're relying on a distro-packaged compiler that may be older.

## Build and test

```bash
cargo build
cargo test
```

## CLI usage

```bash
cargo run --bin scg-scan -- path/to/file
cargo run --bin scg-scan -- --json path/to/file   # machine-readable output
```

## What Phase 1 does and doesn't include

Included: hash matching, YARA-X integration (a minimal placeholder rule set, real
signature content is Phase 2), entropy detection, ZIP/archive scanning, local SQLite
storage, the CLI harness.

Not included: no live threat-intel sync (Phase 2), no UI (Phase 3), no UniFFI/Android
bindings (Phase 6), no privileged operations of any kind.

# SecureGuard Clients

Standalone desktop and Android clients for [SecureGuard Antivirus](https://github.com/Dhruv0306/Antivirus).
No backend dependency at runtime: detection logic runs natively in a shared Rust core.

## Structure

```
core/       Rust crate: YARA-X pattern matching + weighted scoring + entropy-based
            packer detection + local SQLite storage. See core/README.md.
desktop/    (Phase 3+) Tauri shell around core/
android/    (Phase 6+) Kotlin app using UniFFI-generated bindings to core/
docs/       Architecture and phase-by-phase plans
```

## Status

Phase 1 (detection core) in progress. See `docs/standalone-native-clients-plan.md`
for the full phase breakdown and `docs/phase1-detection-core-plan.md` for this
phase's detail.

## Distribution

GitHub Releases only, no app store submission. See the plan docs for the full
reasoning (fee avoidance, checksum/signing strategy, why iOS is out of scope).

## License

MIT, see `LICENSE`. Uses [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause)
for pattern matching.

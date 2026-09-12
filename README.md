# SecureGuard Clients

Standalone desktop and Android clients for [SecureGuard Antivirus](https://github.com/Dhruv0306/Antivirus).
No backend dependency at runtime: detection logic runs natively in a shared Rust core.

## Structure

```
core/       Rust crate: YARA-X pattern matching + weighted scoring + entropy-based
            packer detection + local SQLite storage. See core/README.md.
desktop/    Tauri shell around core/, in-process, no backend. See desktop/README.md.
android/    (Phase 6+) Kotlin app using UniFFI-generated bindings to core/
docs/       Architecture and phase-by-phase plans
```

## Status

Phase 1 (detection core) and Phase 2 (threat-intel sync) complete. Phase 3 (desktop
shell) in progress. See `docs/standalone-native-clients-plan.md` for the full phase
breakdown and `docs/phase3-desktop-shell-plan.md` for this phase's detail.

## Distribution

GitHub Releases only, no app store submission. See the plan docs for the full
reasoning (fee avoidance, checksum/signing strategy, why iOS is out of scope).

## License

MIT, see `LICENSE`. Uses [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause)
for pattern matching.

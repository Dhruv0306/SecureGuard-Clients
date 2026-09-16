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

Phases 1-4 complete (detection core, threat-intel sync, desktop shell, privileged
helper). Phase 5 (release workflow) in progress. Phases 6-8 (Android) not yet started.
See `docs/standalone-native-clients-plan.md` for the full phase breakdown and each
phase's own `docs/phaseN-*-plan.md` for detail.

## Distribution

GitHub Releases only, no app store submission. See the plan docs for the full
reasoning (fee avoidance, checksum/signing strategy, why iOS is out of scope).

Every release is checksummed and GPG-signed. Once the signing key exists (see
`docs/release-gpg-setup.md`, a one-time manual setup step), verifying a download looks
like:

```bash
gpg --import path/to/secureguard-release-signing-key.pub   # one-time
gpg --verify checksums.txt.asc checksums.txt
sha256sum -c checksums.txt
```

## License

MIT, see `LICENSE`. Uses [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause)
for pattern matching.

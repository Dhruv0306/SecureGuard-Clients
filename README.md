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

### Verifying a release

Every release is checksummed and GPG-signed. To verify a download:

```bash
# 1. Import the public signing key, one-time only.
#    Either from the copy committed in this repo (if present, check docs/
#    for a file named something like secureguard-release-signing-key.pub)...
gpg --import docs/secureguard-release-signing-key.pub

#    ...or from the public keyserver, using the key ID published alongside
#    each release:
gpg --keyserver keys.openpgp.org --recv-keys <KEY_ID>

# 2. Confirm checksums.txt is genuinely signed by that key, not tampered with.
gpg --verify checksums.txt.asc checksums.txt

# 3. Confirm your downloaded file matches the signed checksum.
sha256sum -c checksums.txt
```

Don't trust an installer from anywhere other than this repo's GitHub Releases page,
see `docs/release-gpg-setup.md` for how the signing key itself is managed.

## License

MIT, see `LICENSE`. Uses [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause)
for pattern matching.

# Release signing: GPG key setup (one-time, manual)

This has to happen on your machine, not in an automated session. A private signing key
shouldn't be generated anywhere other than the place that's going to hold onto it
long-term.

## 1. Generate a dedicated signing key

```bash
gpg --full-generate-key
```

Recommended choices when prompted:
- Kind: `RSA and RSA` (default)
- Key size: `4096`
- Expiration: your call, a 1-2 year expiry with a calendar reminder to rotate is
  reasonable for a project like this, "never expires" is simpler but riskier if the key
  is ever compromised.
- Name/email: doesn't need to be your personal identity, something like
  `SecureGuard Release Signing <releases@yourdomain-or-github-noreply>` is fine and
  keeps this key's purpose obvious to anyone who looks it up.
- Passphrase: yes, set one. It becomes the `RELEASE_GPG_PASSPHRASE` secret below.

## 2. Export the private key

```bash
gpg --list-secret-keys --keyid-format=long
# find the key ID from the output, looks like: sec   rsa4096/ABCD1234EFGH5678

gpg --armor --export-secret-keys ABCD1234EFGH5678 > secureguard-release-signing-key.asc
```

## 3. Store both as GitHub Actions secrets

Repo Settings → Secrets and variables → Actions → New repository secret:

- `RELEASE_GPG_PRIVATE_KEY`: the full contents of `secureguard-release-signing-key.asc`
  (paste the whole armored block, `-----BEGIN PGP PRIVATE KEY BLOCK-----` through
  `-----END PGP PRIVATE KEY BLOCK-----`).
- `RELEASE_GPG_PASSPHRASE`: the passphrase from step 1.

Then delete `secureguard-release-signing-key.asc` from your local disk, or at minimum
move it somewhere encrypted, it's a live copy of your private key sitting in plaintext.

## 4. Publish the public key somewhere verifiable

So anyone downloading a release can actually verify `checksums.txt.asc` against
something. Two reasonable options, not mutually exclusive:

```bash
gpg --armor --export ABCD1234EFGH5678 > secureguard-release-signing-key.pub
```

- Commit `secureguard-release-signing-key.pub` to the repo (e.g. under `docs/`), and
  link to it from the README's distribution section.
- Publish it to a public keyserver: `gpg --keyserver keys.openpgp.org --send-keys ABCD1234EFGH5678`.

Doing both is the most robust, a keyserver entry survives even if this repo's history
is ever rewritten, and a committed copy means no dependency on a third-party keyserver
being reachable.

## 5. Verifying a release (for anyone downloading, worth documenting in the README too)

```bash
gpg --import secureguard-release-signing-key.pub   # one-time, import the public key
gpg --verify checksums.txt.asc checksums.txt        # confirms checksums.txt is genuinely signed
sha256sum -c checksums.txt                          # confirms your downloaded file matches
```

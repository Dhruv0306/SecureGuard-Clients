# Release signing: GPG key setup (one-time, manual)

This has to happen on your machine, not in an automated session. A private signing key
shouldn't be generated anywhere other than the place that's going to hold onto it
long-term.

## 0. Install GPG

Skip this if `gpg --version` already prints something.

**Windows**

```powershell
winget install GnuPG.Gpg4win
```
Or download the installer directly from [gpg4win.org](https://www.gpg4win.org/) if you
don't have `winget`. Close and reopen your terminal afterward so `PATH` picks up the
new install, then confirm with `gpg --version`.

**macOS**

```bash
brew install gnupg
```
Or install [GPG Suite](https://gpgtools.org/) if you'd rather have a GUI key manager
alongside the command-line tools.

**Linux**

Usually already installed. If not:

```bash
# Debian/Ubuntu
sudo apt-get install gnupg

# Fedora
sudo dnf install gnupg2

# Arch
sudo pacman -S gnupg
```

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

gpg --armor --export-secret-keys --output secureguard-release-signing-key.asc ABCD1234EFGH5678
```

Use `--output` rather than `>`: in Windows PowerShell 5.1 a `>` redirect writes the file as
UTF-16, which is not a valid key file for anything that reads it back as bytes.

Check you exported the right thing. The first line of the file must say **PRIVATE** key block:

```bash
head -1 secureguard-release-signing-key.asc               # bash
Get-Content secureguard-release-signing-key.asc -TotalCount 1   # PowerShell
# expect: -----BEGIN PGP PRIVATE KEY BLOCK-----
```

Do not mix this file up with the `.pub` file from step 4. That one is the PUBLIC key; stored as
the secret it imports without any error and then cannot sign. Do not export with
`--export-secret-subkeys` unless the key you sign with is a subkey.

## 3. Store both as GitHub Actions secrets

Repo Settings → Secrets and variables → Actions → New repository secret:

- `RELEASE_GPG_PRIVATE_KEY`: the full contents of `secureguard-release-signing-key.asc`
  (paste the whole armored block, `-----BEGIN PGP PRIVATE KEY BLOCK-----` through
  `-----END PGP PRIVATE KEY BLOCK-----`).
- `RELEASE_GPG_PASSPHRASE`: the passphrase from step 1.

Then delete `secureguard-release-signing-key.asc` from your local disk, or at minimum
move it somewhere encrypted, it's a live copy of your private key sitting in plaintext.

### Test the secrets without making a release

The release only runs when a version tag is pushed, so use the manual workflow instead: on
GitHub open **Actions**, pick **Check the release signing key** on the left, and press
**Run workflow**. (It appears there once it is on the default branch.) It imports the key,
proves it can sign, signs a sample file and checks the signature, and uploads nothing. The
release itself runs the same check first, before any build.

Success ends with `Signing key OK` and the key id. Each failure says what to fix:

| The error contains | Meaning and fix |
|---|---|
| `RELEASE_GPG_PRIVATE_KEY is empty or not visible` | The secret is missing, empty, or stored as an environment or Dependabot secret. It must be a **repository** secret with exactly that name. |
| `...is not an ASCII-armored key block` | Often a key pasted onto one line with literal `\n` between lines. Paste the whole block with real line breaks. |
| `no secret key was imported` | The secret holds a PUBLIC key, or only secret subkeys without the primary key that signs. Store the output of `--export-secret-keys` from step 2. |
| `RELEASE_GPG_PASSPHRASE does not unlock` | The passphrase secret is not the one for this key. |
| `the imported key cannot sign` | gpg's own reason follows; the key may be expired or have no signing capability. |

The step log also prints only public information: the key id of the key that was loaded.
Compare it with the id you see in `gpg --list-secret-keys --keyid-format=long`.

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
sha256sum -c --ignore-missing checksums.txt         # confirms the files you downloaded match
```

`checksums.txt` lists every file attached to the release (the installers and the `scg-scan`
binaries) by plain file name. Run the last command in the folder you downloaded to;
`--ignore-missing` skips the files you did not download.

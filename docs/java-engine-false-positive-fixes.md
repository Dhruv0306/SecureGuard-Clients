# False-positive fixes: Rust now, Java to follow

Date: 15/10/2026.

A release-build system scan of a developer's Windows machine (11,508 files in 5 minutes)
flagged 528 of them: 497 suspicious and 31 malicious. Nearly all were legitimate: IDE extension
`.jar` and `.js` files, vendor driver archives and install scripts, bundled native libraries. The
scan engine itself worked; the scoring rules did not hold up at that scale.

The Rust engine (`secureguard-core`) has been fixed. The Java engine
(`SecurityServiceImpl`, repository `Dhruv0306/Antivirus`) is **not changed yet** and still has
the problems below. Line numbers refer to commit `0348cca` of that repository.

A second measurement on 26/10/2026 (release build, after the first round) found 5 Malicious files
in 57,000 scanned, all false positives, which led to fixes 4 and 5. Fixes 4 and 5 describe the
Rust code; the Java method was not re-read for them, so check it before use.

## Fixed in Rust and still to do in Java

### 1. Entropy scoring flags every `.jar` and `.msi`

`.jar` and `.msi` are in `SUSPICIOUS_EXTENSIONS` (line 198), which switches entropy scoring on
(`isExecutableLikeForEntropy`, line 839). Both formats are compressed by design, so their entropy
is always high and each one gets `SCORE_HIGH_ENTROPY` (30), which is a SUSPICIOUS verdict by
itself (`THRESHOLD_SUSPICIOUS` is 25).

Rust change: a compressed container is only entropy-checked if its header is really a Windows or
Linux executable.

```java
private static final Set<String> COMPRESSED_CONTAINER_EXTENSIONS = Set.of(".jar", ".msi");

private boolean isExecutableLikeForEntropy(String extensionLowerCase, byte[] header) {
    if (containsSuspiciousBytes(header)) {
        return true;
    }
    return SUSPICIOUS_EXTENSIONS.contains(extensionLowerCase)
            && !COMPRESSED_CONTAINER_EXTENSIONS.contains(extensionLowerCase);
}
```

Tests to add: a high-entropy `library.jar` and `Setup.msi` score CLEAN; a high-entropy `packed.bin`
is still SUSPICIOUS; a file named `fake.jar` that starts with `MZ` is still entropy-checked.

### 2. Weak text patterns can convict a file on their own

`MAX_WEAK_PATTERN_SCORE` is 32 (line 251), above the suspicious threshold of 25. Weak patterns
(`eval(`, `fromCharCode`, `document.write` and similar) appear in ordinary bundled JavaScript, so
any such file was SUSPICIOUS, and with one strong pattern on top (32 + 30 = 62) it was
MALICIOUS.

Rust change: cap weak patterns just below the threshold so they add to a verdict but never produce
one alone.

```java
private static final int MAX_WEAK_PATTERN_SCORE = THRESHOLD_SUSPICIOUS - 1; // 24
```

`THRESHOLD_SUSPICIOUS` must be declared before this constant or be a literal. Tests to add: a text
with many weak patterns scores CLEAN but above 0; the same text plus
`powershell -w hidden -Command x` is SUSPICIOUS (24 + 30 = 54), not MALICIOUS.

### 3. An ELF `.so` is called a disguised executable

`checkExtensionMasquerade` (line 824) returns `SCORE_EXTENSION_MASQUERADE` (70) for any
executable header behind an extension that is not in `SUSPICIOUS_EXTENSIONS`. `.so` is not in
the list, so every Linux shared library bundled inside a Windows program (the Python debugger
ships several) was MALICIOUS.

Rust change: an executable whose header matches the kind its name promises is expected.

```java
private boolean isExpectedNativeLibrary(String nameLowerCase, byte[] header) {
    boolean elf = header.length >= 4 && header[0] == 0x7f && header[1] == 'E'
            && header[2] == 'L' && header[3] == 'F';
    boolean pe = header.length >= 2 && header[0] == 'M' && header[1] == 'Z';
    String ext = getFileExtension(new File(nameLowerCase)).toLowerCase();
    boolean elfName = ext.equals(".so") || ext.equals(".ko") || ext.equals(".o")
            || ext.equals(".node") || nameLowerCase.contains(".so.");
    boolean peName = ext.equals(".pyd") || ext.equals(".node");
    return (elf && elfName) || (pe && peName);
}
```

Call it before `checkExtensionMasquerade` at lines 514 and 1618 and skip the score when true. A
Windows executable named `.so`, or an ELF named `report.pdf`, must still be flagged. Tests to add:
`libfoo.so`, `libfoo.so.1.2.3`, `mod.ko` and `addon.node` with an ELF header are CLEAN;
`report.pdf` with an ELF header is MALICIOUS.

### 4. The ransomware folder score is given to every file in the folder

The heuristic (`scoreRansomwareDirectoryBehavior` in Java, `dir_behavior.rs` in Rust) adds 55 when
a folder has a ransom-note-like name (`readme` with `txt`, `recovery`, `how_to_decrypt`, ...) and
five entries that share an unfamiliar extension. It added the 55 to **every file** in the folder,
and the Rust walker counted subfolder names as entries. Measured on a developer machine:

| Folder | Why it qualified | Effect |
|---|---|---|
| Python `site-packages` | `README.txt` plus many `*.dist-info` folders | `six.py`: folder 55 + one weak pattern 8 = 63, MALICIOUS |
| `reportlab/fonts` | `00readme.txt` plus 18 `.afm`, 18 `.pfb`, 5 `.ttf` files | every file in the folder scored 55 |

Rust change: count regular files only, and give the score only to the files it is about: the
note-like files and the files whose extension forms the cluster (`FolderBehavior::score_for`). A
`.py` file next to them scores 0. Tests to add: a folder with `README.txt`, five `*.dist-info`
subfolders and `six.py` scores 0; in a folder with a note and five `.xyz123` files, the note and
the `.xyz123` files score 55 and `main.py` scores 0.

### 5. Text patterns and the folder score can convict a file on their own

Both are circumstantial. They describe a file's wording or surroundings, not the file, and a
document that talks about malware matches them as well as malware does. Measured: a handoff
document that mentions a hidden PowerShell window and a "ransom note" scored 30 + 8 + 45 = 83; a
bundled `app.js` with two strong patterns scored 60 + 24 = 84; a font license with the joke
"Vera cannot become a ransom note font" scored 45 + 55 = 100. All were MALICIOUS.

Rust change: when no signal about the file itself contributed, the total is held at 59 (Suspicious).
Signals about the file itself: extension masquerade, high entropy, ransomware extension, trojan
file name, rootkit binary, YARA match, zip entry score, and a known hash (which returns early).

```java
private static final int MAX_CIRCUMSTANTIAL_ONLY_SCORE = THRESHOLD_MALICIOUS - 1; // 59
// Track `directSignal`, set by every signal above; after all signals are added:
if (!directSignal) {
    score = Math.min(score, MAX_CIRCUMSTANTIAL_ONLY_SCORE);
}
```

Tests to add: two strong patterns plus four weak ones in `bundle.js` is SUSPICIOUS at 59; the
folder score plus one weak pattern is SUSPICIOUS; a strong pattern in `report.locked` and in
`backdoor_tool.js` is still MALICIOUS.

## Rust only: a port bug, Java is already correct

The Rust zip check added `SCORE_ZIP_SUSPICIOUS_ENTRY` (15) **per matching entry** and ran on any
file whose bytes looked like a zip. Java adds it **once** (line 559) and only for names ending in
`.zip`, `.jar` or `.war` (`isZipFile`, line 738). A driver archive with 29 `.dll` entries scored
435 in Rust and was convicted; in Java it scores 15. Rust now matches Java. No Java change.

## Until Java catches up

The two engines will disagree on the five cases above. Any cross-engine comparison that includes
a `.jar`/`.msi` with high entropy, a script with only weak patterns, a native library with a
matching header, a file next to a note and a cluster of unfamiliar extensions, or a file whose only
evidence is text patterns will show Rust as less suspicious than Java. That is intended.

## Not fixed yet (both engines)

Observed in the same scan and not addressed by these changes:

- install scripts (`.cmd`) that use `powershell -w hidden`, which is a strong pattern
- `.exe` installers and some `.dll` files whose entropy is high because they are packed or
  contain compressed payloads
- JSON, log and source-map files that contain weak patterns
- bundled JavaScript that contains one strong pattern (now SUSPICIOUS instead of MALICIOUS)
- files whose text really matches a pattern, such as a document about malware or a license that
  jokes about a "ransom note": now SUSPICIOUS (59), no longer MALICIOUS
- font and other asset folders with a readme still score 55 for the readme and the files with the
  clustered extension (`.afm`, `.pfb`); adding those extensions to `COMMON_EXTENSIONS` would stop it

Larger fixes to consider later: trust for signed binaries (Authenticode), known-good hash lists,
and a per-folder trust list. Re-running the scan after these changes will show how much is left.

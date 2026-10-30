// Checks for the pure logic behind the scan screen (desktop/src/scan-view.js).
// No dependencies: run with `node --test desktop/tests/scan-view.test.js`
// (Node 18+). The file is loaded the way the page loads it, as a classic
// script that defines `ScanView` on `window`, so what is tested is what ships.
// The DOM and the Tauri event wiring in main.js are checked by hand, see the
// smoke checklist in the pull request.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const context = {};
context.window = context;
vm.runInNewContext(
    fs.readFileSync(new URL("../src/scan-view.js", import.meta.url), "utf8"),
    context
);
const V = context.ScanView;
// Arrays made inside the vm have another realm's prototype, which strict
// deepEqual rejects; comparing plain copies compares the contents.
const plain = value => JSON.parse(JSON.stringify(value));

const finding = (path, verdict, score) => ({ path, result: { verdict, score } });

test("every engine reason has a plain-language line", () => {
    const table = [
        ["EICAR standard antivirus test file detected", "The standard antivirus test file"],
        ["Known malware signature detected", "Matches a known malware signature"],
        ["ZIP_BOMB_LIMIT_EXCEEDED", "Archive expands to an extreme size (possible zip bomb)"],
        ["EXTENSION_MASQUERADE: .jpg file is really an executable", "The file type does not match its name"],
        ["HIGH_ENTROPY_EXECUTABLE (7.91)", "Executable looks packed or encrypted"],
        ["RANSOMWARE_EXTENSION", "Has a file extension used by ransomware"],
        ["RANSOMWARE_NOTE_TEXT", "Contains text like a ransom note"],
        ["RANSOMWARE_DIRECTORY_BEHAVIOR", "Sits among files that look like ransomware damage"],
        ["TROJAN_NAME_SIGNATURE", "The file name matches a known trojan name"],
        ["STRONG_CODE_PATTERN(x2)", "Contains code patterns often used by malware"],
        ["WEAK_CODE_PATTERN(x3)", "Contains code patterns that are sometimes suspicious"],
        ["ROOTKIT_BINARY_IN_DRIVER_LOCATION", "Driver-like file in a system driver location"],
        ["ROOTKIT_TEXT_PATTERN", "Contains text about hiding from the operating system"],
        ["ZIP_CONTAINS_EXECUTABLE_ENTRY", "Archive contains executable files"],
    ];
    for (const [engine, plain] of table) {
        assert.equal(V.reasonText(engine), plain, engine);
    }
});

test("a YARA reason keeps the rule name, an unknown reason is shown as it is", () => {
    assert.equal(V.reasonText("YARA-X pattern match: my_rule"), "Matches a detection rule (my_rule)");
    assert.equal(V.reasonText("SOMETHING_NEW(x1)"), "SOMETHING_NEW(x1)");
});

test("a long path is shortened in the middle and a short one is left alone", () => {
    assert.equal(V.shortenMiddle("C:\\a\\b.txt", 40), "C:\\a\\b.txt");
    const long = "C:\\Users\\Someone\\Downloads\\a\\very\\deep\\folder\\file.exe";
    const short = V.shortenMiddle(long, 30);
    assert.equal(Array.from(short).length, 30);
    assert.ok(short.startsWith("C:\\Users"), short);
    assert.ok(short.endsWith("file.exe"), short);
    assert.ok(short.includes("\u2026"), short);
});

test("shortening never splits a character made of two code units", () => {
    const text = "\u{1F600}".repeat(50);
    const short = V.shortenMiddle(text, 11);
    assert.equal(Array.from(short).length, 11);
    assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(short), "lone surrogate");
});

test("findings split into malicious and suspicious, each highest score first then by path", () => {
    const groups = V.splitFindings([
        finding("b.js", "Suspicious", 40),
        finding("z.exe", "Malicious", 70),
        finding("a.js", "Suspicious", 40),
        finding("m.exe", "Malicious", 100),
        finding("c.js", "Suspicious", 59),
        finding("clean.txt", "Clean", 0),
    ]);
    assert.deepEqual(plain(groups.malicious.map(f => f.path)), ["m.exe", "z.exe"]);
    assert.deepEqual(plain(groups.suspicious.map(f => f.path)), ["c.js", "a.js", "b.js"]);
});

test("a finding that was already shown is not added again", () => {
    const seen = new Set();
    const first = V.takeUnseen(seen, [finding("a", "Malicious", 90), finding("b", "Malicious", 90)]);
    assert.deepEqual(plain(first.map(f => f.path)), ["a", "b"]);
    const second = V.takeUnseen(seen, [finding("b", "Malicious", 90), finding("c", "Suspicious", 30)]);
    assert.deepEqual(plain(second.map(f => f.path)), ["c"]);
    assert.deepEqual(plain(V.takeUnseen(seen, [finding("a", "Malicious", 90)])), []);
});

test("counts and durations read naturally", () => {
    assert.equal(V.formatCount(0), "0");
    assert.equal(V.formatCount(999), "999");
    assert.equal(V.formatCount(1000), "1,000");
    assert.equal(V.formatCount(1234567), "1,234,567");
    assert.equal(V.formatDuration(950), "0.9 s");
    assert.equal(V.formatDuration(21800), "21.8 s");
    assert.equal(V.formatDuration(125000), "2 min 5 s");
    assert.equal(V.formatDuration(3720000), "1 h 2 min");
});

test("the banner says why a scan stopped early and nothing when it completed", () => {
    assert.equal(V.bannerText("cancelled"), "Scan cancelled. Showing what was found so far.");
    assert.equal(V.bannerText("findings_cap"), "Stopped after 2,000 findings. Review these, then scan again.");
    assert.equal(V.bannerText("time_budget"), "Stopped at the time limit.");
    assert.equal(V.bannerText("completed"), "");
});

test("the progress line and the summary use the report's counts", () => {
    assert.equal(V.progressText({ scanned: 12345, findings: 3 }), "Scanned 12,345 files, 3 flagged");
    const report = {
        scanned: 1450, clean: 1440, suspicious: 10, malicious: 0, elapsed_ms: 21800,
        skipped_excluded: 0, skipped_too_large: 0, skipped_links_or_special: 0,
        unreadable_files: 0, unreadable_dirs: 0,
    };
    assert.equal(
        V.summaryText(report),
        "Scanned 1,450 files in 21.8 s. Clean 1,440, worth a look 10, likely malicious 0."
    );
    assert.equal(V.skippedText(report), "");
    assert.equal(
        V.skippedText({ ...report, skipped_excluded: 3, skipped_too_large: 1, unreadable_dirs: 2 }),
        "Skipped: 3 excluded, 1 over 100 MB, 2 unreadable folders."
    );
});

test("the sync line shows why a feed failed, not only that one did", () => {
    assert.equal(V.syncText({ new_signatures: 5, total_signatures: 6661, feed_errors: [] }), "Synced 5 new (6,661 total)");
    assert.equal(
        V.syncText({ new_signatures: 0, total_signatures: 6661, feed_errors: ["request to x failed: http status: 410"] }),
        "Synced 0 new (6,661 total); 1 feed(s) failed: request to x failed: http status: 410"
    );
    const long = V.syncText({ new_signatures: 0, total_signatures: 1, feed_errors: ["e".repeat(500)] });
    assert.ok(long.length < 300, long.length);
});

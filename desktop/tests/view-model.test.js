// Checks the pure logic behind the redesigned scan screen
// (desktop/src/view-model.js): the plain sentence, place chips and filters,
// routing, and the choice of scan command. No dependencies: run with
// `node --test "desktop/tests/**/*.test.js"`. Both scripts are loaded the way
// the page loads them (scan-view.js first), so what is tested is what ships.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const context = {};
context.window = context;
for (const file of ["scan-view.js", "view-model.js"]) {
    vm.runInNewContext(fs.readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8"), context);
}
const M = context.ViewModel;
// Objects made inside the vm have another realm's prototype, which strict
// deepEqual rejects; comparing plain copies compares the contents.
const plain = value => JSON.parse(JSON.stringify(value));

const report = (over = {}) => ({
    findings: [], scanned: 14209, clean: 14204, suspicious: 3, malicious: 2,
    skipped_excluded: 200, skipped_too_large: 5, skipped_links_or_special: 3, unreadable_files: 2, unreadable_dirs: 1,
    stop_reason: "completed", elapsed_ms: 38250, ...over,
});
const done = (r, extra = {}) => M.summarySentence({ phase: "done", kindLabel: "Quick scan", report: r, ...extra });
const finding = (path, verdict = "Suspicious", score = 30) => ({ path, result: { verdict, score } });

test("number words cover one to nine, then digits with commas", () => {
    assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8, 9].map(M.numberWord),
        ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]);
    assert.equal(M.numberWord(10), "10");
    assert.equal(M.numberWord(1204), "1,204");
    assert.equal(M.numberWord(0), "0");
});

test("idle: ready to scan, with the folder count and when signatures were last checked", () => {
    const when = new Date(2026, 10, 11, 18, 2).getTime() / 1000;
    const now = new Date(2026, 10, 28, 9, 0);
    const out = M.summarySentence({ phase: "idle", mode: "quick", foldersCount: 5, checkedText: M.checkedText(when, now) });
    assert.equal(out.headline, "Ready to scan.");
    assert.deepEqual(plain(out.lines), ["Quick scan checks 5 folders. Signatures last checked 11 Nov, 18:02."]);
    const never = M.summarySentence({ phase: "idle", mode: "quick", foldersCount: 5, checkedText: M.checkedText(null, now) });
    assert.deepEqual(plain(never.lines), ["Quick scan checks 5 folders. Signatures have not been checked yet."]);
});

test("idle: one folder is singular, Custom with nothing asks for a folder, Full names the drives", () => {
    const sig = "Signatures last checked 11 Nov, 18:02.";
    assert.deepEqual(plain(M.summarySentence({ phase: "idle", mode: "custom", foldersCount: 1, checkedText: sig }).lines),
        ["Custom scan checks 1 folder. " + sig]);
    const empty = M.summarySentence({ phase: "idle", mode: "custom", foldersCount: 0, checkedText: sig });
    assert.equal(empty.headline, "Choose what to scan.");
    assert.deepEqual(plain(empty.lines), ["Add a folder, or check one file."]);
    const full = M.summarySentence({ phase: "idle", mode: "full", foldersCount: 5, drivesCount: 2, checkedText: sig });
    assert.equal(full.headline, "Ready to scan.");
    assert.deepEqual(plain(full.lines), ["Full scan checks 5 folders and 2 drives, so it can take a long time.", sig]);
});

test("checked text adds the year when it is not this year, and reads bad input as never", () => {
    const now = new Date(2026, 10, 28);
    assert.equal(M.checkedText(new Date(2025, 11, 31, 23, 5).getTime() / 1000, now), "Signatures last checked 31 Dec 2025, 23:05.");
    for (const bad of [undefined, null, 0, -5, NaN, "x"]) {
        assert.equal(M.checkedText(bad, now), "Signatures have not been checked yet.");
    }
});

test("scanning: the progress line plus the folder being read, shortened", () => {
    const base = { phase: "scanning", progress: { scanned: 4210, findings: 2, current_dir: "C:\\Users\\Meera\\Downloads" } };
    const out = M.summarySentence(base);
    assert.equal(out.headline, "Checking your files.");
    assert.deepEqual(plain(out.lines), ["Scanned 4,210 files, 2 flagged in \u2026\\Downloads"]);
    const unix = M.summarySentence({ phase: "scanning", progress: { scanned: 12, findings: 0, current_dir: "/home/meera/Documents/" } });
    assert.deepEqual(plain(unix.lines), ["Scanned 12 files, 0 flagged in \u2026/Documents"]);
    const noDir = M.summarySentence({ phase: "scanning", progress: { scanned: 7, findings: 0, current_dir: "" } });
    assert.deepEqual(plain(noDir.lines), ["Scanned 7 files, 0 flagged"]);
});

test("done with malicious files: singular and plural, number words, digits from ten", () => {
    assert.equal(done(report({ malicious: 1, suspicious: 0 })).headline, "One file needs your attention.");
    assert.equal(done(report({ malicious: 2 })).headline, "Two files need your attention.");
    assert.equal(done(report({ malicious: 9 })).headline, "Nine files need your attention.");
    assert.equal(done(report({ malicious: 10 })).headline, "10 files need your attention.");
    assert.equal(done(report({ malicious: 1204 })).headline, "1,204 files need your attention.");
});

test("done with malicious files: the counts line shows only when both counts are above zero", () => {
    const both = done(report({ malicious: 2, suspicious: 3 }));
    assert.deepEqual(plain(both.lines), [
        "2 likely malicious, 3 worth a look.",
        "Quick scan finished in 38.2 s. 14,209 files checked, 211 skipped. Nothing was changed or deleted.",
    ]);
    const only = done(report({ malicious: 2, suspicious: 0 }));
    assert.deepEqual(plain(only.lines), [
        "Quick scan finished in 38.2 s. 14,209 files checked, 211 skipped. Nothing was changed or deleted.",
    ]);
});

test("done with only suspicious files", () => {
    assert.equal(done(report({ malicious: 0, suspicious: 1 })).headline, "One file is worth a look.");
    assert.equal(done(report({ malicious: 0, suspicious: 3 })).headline, "Three files are worth a look.");
    assert.equal(done(report({ malicious: 0, suspicious: 12 })).headline, "12 files are worth a look.");
    assert.deepEqual(plain(done(report({ malicious: 0, suspicious: 3 })).lines), [
        "Quick scan finished in 38.2 s. 14,209 files checked, 211 skipped. Nothing was changed or deleted.",
    ]);
});

test("done and clean: nothing looks wrong, and only the finished line", () => {
    const out = done(report({ malicious: 0, suspicious: 0, elapsed_ms: 41000 }));
    assert.equal(out.headline, "Nothing looks wrong.");
    assert.deepEqual(plain(out.lines), ["Quick scan finished in 41.0 s. 14,209 files checked, 211 skipped."]);
});

test("the finished line drops the skipped part when nothing was skipped and counts one file in the singular", () => {
    const none = done(report({
        malicious: 0, suspicious: 0, scanned: 1, skipped_excluded: 0, skipped_too_large: 0,
        skipped_links_or_special: 0, unreadable_files: 0, unreadable_dirs: 0,
    }));
    assert.deepEqual(plain(none.lines), ["Quick scan finished in 38.2 s. 1 file checked."]);
});

test("a stopped scan starts with 'So far,' and gives the reason with the number of files checked", () => {
    const cancelled = done(report({ malicious: 2, suspicious: 1, scanned: 8317, stop_reason: "cancelled" }));
    assert.equal(cancelled.headline, "So far, two files need your attention.");
    assert.deepEqual(plain(cancelled.lines), ["2 likely malicious, 1 worth a look."]);
    assert.equal(cancelled.banner, "Scan cancelled. Showing what was found so far. 8,317 files checked.");
    const cap = done(report({ malicious: 0, suspicious: 2, stop_reason: "findings_cap" }));
    assert.equal(cap.headline, "So far, two files are worth a look.");
    assert.equal(cap.banner, "Stopped after 2,000 findings. Review these, then scan again. 14,209 files checked.");
    const time = done(report({ malicious: 0, suspicious: 0, stop_reason: "time_budget" }));
    assert.equal(time.headline, "So far, nothing looks wrong.");
    assert.equal(time.banner, "Stopped at the time limit. 14,209 files checked.");
    assert.equal(done(report()).banner, undefined, "a completed scan has no banner");
});

test("one file: a headline for each verdict and the name with its score", () => {
    const one = verdict => M.summarySentence({ phase: "file", fileResult: { file_name: "invoice.pdf.exe", verdict, score: 92 } });
    assert.equal(one("Malicious").headline, "This file is likely malicious.");
    assert.equal(one("Suspicious").headline, "This file is worth a look.");
    assert.equal(one("Clean").headline, "This file looks clean.");
    assert.deepEqual(plain(one("Malicious").lines), ["invoice.pdf.exe. Score 92."]);
    assert.equal(one("Surprising").headline, "This file was checked.");
});

test("an error: the scan could not start, with the text as it was given", () => {
    const out = M.summarySentence({ phase: "error", error: "A scan is already running." });
    assert.equal(out.headline, "The scan could not start.");
    assert.deepEqual(plain(out.lines), ["A scan is already running."]);
    assert.deepEqual(plain(M.summarySentence({ phase: "error", error: { code: 7 } }).lines), ["[object Object]"]);
    assert.deepEqual(plain(M.summarySentence({ phase: "error" }).lines), ["Something went wrong."]);
});

test("an unknown phase reads as ready, and a missing report never throws", () => {
    assert.equal(M.summarySentence({ phase: "nonsense", mode: "quick", foldersCount: 1 }).headline, "Ready to scan.");
    assert.equal(M.summarySentence({ phase: "done", kindLabel: "Quick scan" }).headline, "The scan finished.");
    assert.equal(M.summarySentence(undefined).headline, "Ready to scan.");
});

const places = [
    { path: "C:\\Users\\Meera\\Downloads", label: "Downloads" },
    { path: "C:\\Users\\Meera\\Documents", label: "Documents" },
    { path: "C:\\Users\\Meera\\AppData\\Local\\Temp", label: "Temp files" },
    { path: "C:\\", label: "C:" },
];

test("chips: All first, then places with findings, biggest first, empty places left out", () => {
    const findings = [
        finding("C:\\Users\\Meera\\Downloads\\a.exe"), finding("C:\\Users\\Meera\\Downloads\\b.zip"),
        finding("C:\\Users\\Meera\\AppData\\Local\\Temp\\7z\\c.dll"), finding("c:\\users\\meera\\documents\\d.xlsm"),
        finding("C:\\Users\\Meera\\Documents\\e.xlsm"), finding("C:\\Users\\Meera\\Documents\\f.xlsm"),
    ];
    assert.deepEqual(plain(M.placeChips(findings, places)), [
        { key: "all", label: "All", count: 6 },
        { key: "C:\\Users\\Meera\\Documents", label: "Documents", count: 3 },
        { key: "C:\\Users\\Meera\\Downloads", label: "Downloads", count: 2 },
        { key: "C:\\Users\\Meera\\AppData\\Local\\Temp", label: "Temp files", count: 1 },
    ]);
});

test("a finding belongs to one place only, the one with the longest matching path", () => {
    const f = [finding("C:\\Users\\Meera\\AppData\\Local\\Temp\\x.dll")];
    const chips = M.placeChips(f, places);
    assert.deepEqual(plain(chips.map(c => [c.label, c.count])), [["All", 1], ["Temp files", 1]]);
    const total = chips.slice(1).reduce((sum, c) => sum + c.count, 0);
    assert.equal(total, 1, "counted once, not under C: as well");
});

test("a folder name that only starts the same does not match it, and unmatched findings go under Other", () => {
    const f = [finding("C:\\Users\\Meera\\DownloadsOld\\x.exe"), finding("D:\\Work\\y.exe")];
    // DownloadsOld is not under Downloads; it is only under the C: drive place.
    assert.deepEqual(plain(M.placeChips(f, places).map(c => [c.label, c.count])), [["All", 2], ["C:", 1], ["Other", 1]]);
    assert.deepEqual(plain(M.filterFindings(f, places, "other").map(x => x.path)), ["D:\\Work\\y.exe"]);
    assert.deepEqual(plain(M.filterFindings(f, places, "C:\\").map(x => x.path)), ["C:\\Users\\Meera\\DownloadsOld\\x.exe"]);
});

test("paths match across slash style, case, and the Windows extended prefix", () => {
    const f = [finding("//?/C:/Users/Meera/Downloads/a.exe"), finding("C:/users/meera/downloads/b.exe")];
    assert.deepEqual(plain(M.placeChips(f, places).map(c => [c.label, c.count])), [["All", 2], ["Downloads", 2]]);
    const unix = [{ path: "/home/meera/Downloads", label: "Downloads" }];
    assert.deepEqual(plain(M.placeChips([finding("/home/meera/Downloads/a.sh")], unix).map(c => c.count)), [1, 1]);
});

test("filter: All returns everything, a place returns its own findings in order", () => {
    const f = [finding("C:\\Users\\Meera\\Downloads\\a.exe"), finding("C:\\Users\\Meera\\Documents\\b.xlsm"),
        finding("C:\\Users\\Meera\\Downloads\\c.zip")];
    assert.equal(M.filterFindings(f, places, "all").length, 3);
    assert.deepEqual(plain(M.filterFindings(f, places, "C:\\Users\\Meera\\Downloads").map(x => x.path)),
        ["C:\\Users\\Meera\\Downloads\\a.exe", "C:\\Users\\Meera\\Downloads\\c.zip"]);
    assert.equal(M.filterFindings(f, places, "no-such-place").length, 0);
    assert.equal(M.filterFindings(f, places, undefined).length, 3);
});

test("no findings and no places give only the All chip", () => {
    assert.deepEqual(plain(M.placeChips([], places)), [{ key: "all", label: "All", count: 0 }]);
    assert.deepEqual(plain(M.placeChips([finding("C:\\a.exe")], [])), [
        { key: "all", label: "All", count: 1 }, { key: "other", label: "Other", count: 1 }]);
});

test("routing: the hash picks the view, anything else is Scan, and it round-trips", () => {
    assert.equal(M.viewFromHash("#history"), "history");
    assert.equal(M.viewFromHash("#blocking"), "blocking");
    assert.equal(M.viewFromHash("#signatures"), "signatures");
    assert.equal(M.viewFromHash("#scan"), "scan");
    assert.equal(M.viewFromHash("#HISTORY"), "history");
    assert.equal(M.viewFromHash("signatures"), "signatures");
    for (const bad of ["", "#", "#nope", "#history/extra", "#history?x=1", undefined, null, 5]) {
        assert.equal(M.viewFromHash(bad), "scan", String(bad));
    }
    for (const v of ["scan", "history", "blocking", "signatures"]) {
        assert.equal(M.viewFromHash(M.hashForView(v)), v);
    }
    assert.equal(M.hashForView("history"), "#history");
    assert.equal(M.hashForView("bogus"), "#scan");
});

const quick = [{ path: "/d" }, { path: "/e" }, { path: "/f" }];

test("Quick with everything checked runs the existing quick scan", () => {
    assert.deepEqual(plain(M.scanRequest("quick", quick, ["/d", "/e", "/f"], [], true)), { command: "scan_quick_cmd", args: {} });
});

test("Quick with some places unchecked scans only those places with the quick preset", () => {
    assert.deepEqual(plain(M.scanRequest("quick", quick, ["/f", "/d"], [], false)),
        { command: "scan_selected_cmd", args: { paths: ["/d", "/f"], preset: "quick", recursive: true } });
});

test("Quick with nothing checked is an error and no command", () => {
    const out = M.scanRequest("quick", quick, [], [], true);
    assert.deepEqual(plain(out), { error: "Choose at least one folder to scan." });
    assert.equal(out.command, undefined);
});

test("Custom scans the chosen folders with the custom preset and the subfolder choice", () => {
    assert.deepEqual(plain(M.scanRequest("custom", quick, [], ["D:\\Work", "D:\\Work", "E:\\Pics"], true)),
        { command: "scan_selected_cmd", args: { paths: ["D:\\Work", "E:\\Pics"], preset: "custom", recursive: true } });
    assert.equal(M.scanRequest("custom", quick, [], ["D:\\Work"], false).args.recursive, false);
    assert.deepEqual(plain(M.scanRequest("custom", quick, [], [], true)), { error: "Choose at least one folder to scan." });
});

test("Full runs the full scan and an unknown mode is an error", () => {
    assert.deepEqual(plain(M.scanRequest("full", quick, [], [], true)), { command: "scan_full_cmd", args: {} });
    assert.deepEqual(plain(M.scanRequest("weird", quick, [], [], true)), { error: "Choose how to scan." });
});

test("copy review: no em dash or en dash in the source or in any string it produces", () => {
    const source = fs.readFileSync(new URL("../src/view-model.js", import.meta.url), "utf8");
    assert.ok(!/[\u2013\u2014]/.test(source), "view-model.js contains a dash");
    const when = new Date(2026, 10, 11, 18, 2).getTime() / 1000;
    const outputs = [
        M.summarySentence({ phase: "idle", mode: "full", foldersCount: 5, drivesCount: 2, checkedText: M.checkedText(when) }),
        M.summarySentence({ phase: "idle", mode: "custom", foldersCount: 0, checkedText: "x" }),
        M.summarySentence({ phase: "scanning", progress: { scanned: 1, findings: 0, current_dir: "C:\\a\\b" } }),
        done(report({ stop_reason: "cancelled" })), done(report({ stop_reason: "findings_cap" })),
        done(report({ stop_reason: "time_budget" })), done(report()), done(report({ malicious: 0, suspicious: 0 })),
        M.summarySentence({ phase: "file", fileResult: { file_name: "a", verdict: "Clean", score: 1 } }),
        M.summarySentence({ phase: "error", error: "e" }), M.summarySentence({ phase: "done" }),
        M.scanRequest("quick", [], [], [], true),
    ];
    assert.ok(!/[\u2013\u2014]/.test(JSON.stringify(outputs)));
});

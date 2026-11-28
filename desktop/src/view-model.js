// Pure logic behind the redesigned scan screen: the plain sentence, place
// chips and filters, routing, and which scan command a choice maps to.
// Nothing here touches the page or Tauri, so it can be checked with Node
// (desktop/tests/view-model.test.js). A classic script: it defines
// `ViewModel` on `window` and needs `ScanView` (scan-view.js) loaded first.

(function (root) {
    const ELLIPSIS = "\u2026";
    const WORDS = ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
    const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const VIEWS = ["scan", "history", "blocking", "signatures"];
    const KIND = { quick: "Quick scan", full: "Full scan", custom: "Custom scan" };
    const NOTHING_CHANGED = "Nothing was changed or deleted.";
    const NO_FOLDER = "Choose at least one folder to scan.";
    const ALL = "all";
    const OTHER = "other";

    const S = () => root.ScanView;

    function numberWord(n) {
        return Number.isInteger(n) && n >= 1 && n <= 9 ? WORDS[n - 1] : S().formatCount(n);
    }

    function capitalize(text) {
        return text.charAt(0).toUpperCase() + text.slice(1);
    }

    function lowerFirst(text) {
        return text.charAt(0).toLowerCase() + text.slice(1);
    }

    function pad(n) {
        return String(n).padStart(2, "0");
    }

    // "Signatures last checked 11 Nov, 18:02." in local time, with the year
    // when it is not the current one. Anything that is not a positive number
    // of seconds reads as never checked.
    function checkedText(epochSecs, now) {
        if (typeof epochSecs !== "number" || !Number.isFinite(epochSecs) || epochSecs <= 0) {
            return "Signatures have not been checked yet.";
        }
        const date = new Date(epochSecs * 1000);
        const current = now instanceof Date ? now : new Date();
        const year = date.getFullYear() === current.getFullYear() ? "" : ` ${date.getFullYear()}`;
        return `Signatures last checked ${date.getDate()} ${MONTHS[date.getMonth()]}${year}, ` +
            `${pad(date.getHours())}:${pad(date.getMinutes())}.`;
    }

    function plural(n, one, many) {
        return `${S().formatCount(n)} ${n === 1 ? one : many}`;
    }

    // The last folder of a path, led by an ellipsis: "C:\a\b\Downloads" gives
    // "...\Downloads". The separator of the path itself is kept.
    function lastFolder(dir) {
        if (typeof dir !== "string") {
            return "";
        }
        const trimmed = dir.replace(/[\\/]+$/, "");
        const cut = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
        if (cut === -1) {
            return trimmed;
        }
        return ELLIPSIS + trimmed.charAt(cut) + trimmed.slice(cut + 1);
    }

    function idle(input) {
        const kind = KIND[input.mode] || KIND.quick;
        const checked = input.checkedText || "";
        const folders = Number.isInteger(input.foldersCount) ? input.foldersCount : 0;
        if (input.mode === "custom" && folders === 0) {
            return { headline: "Choose what to scan.", lines: ["Add a folder, or check one file."] };
        }
        if (input.mode === "full") {
            const drives = Number.isInteger(input.drivesCount) ? input.drivesCount : 0;
            const what = drives > 0
                ? `${plural(folders, "folder", "folders")} and ${plural(drives, "drive", "drives")}`
                : plural(folders, "folder", "folders");
            return {
                headline: "Ready to scan.",
                lines: [`${kind} checks ${what}, so it can take a long time.`, checked].filter(Boolean),
            };
        }
        const line = `${kind} checks ${plural(folders, "folder", "folders")}.`;
        return { headline: "Ready to scan.", lines: [checked ? `${line} ${checked}` : line] };
    }

    function scanning(input) {
        const progress = input.progress || { scanned: 0, findings: 0 };
        const where = lastFolder(progress.current_dir);
        const text = S().progressText(progress);
        return { headline: "Checking your files.", lines: [where ? `${text} in ${where}` : text] };
    }

    function skippedTotal(report) {
        return (report.skipped_excluded || 0) + (report.skipped_too_large || 0) +
            (report.skipped_links_or_special || 0) + (report.unreadable_files || 0) + (report.unreadable_dirs || 0);
    }

    function finished(input) {
        const report = input.report;
        if (!report) {
            return { headline: "The scan finished.", lines: [] };
        }
        const m = report.malicious || 0;
        const s = report.suspicious || 0;
        const banner = S().bannerText(report.stop_reason);
        const stopped = banner !== "";
        let headline;
        if (m > 0) {
            headline = m === 1 ? "One file needs your attention."
                : `${capitalize(numberWord(m))} files need your attention.`;
        } else if (s > 0) {
            headline = s === 1 ? "One file is worth a look."
                : `${capitalize(numberWord(s))} files are worth a look.`;
        } else {
            headline = "Nothing looks wrong.";
        }
        const lines = [];
        if (m > 0 && s > 0) {
            lines.push(`${S().formatCount(m)} likely malicious, ${S().formatCount(s)} worth a look.`);
        }
        const checked = `${plural(report.scanned || 0, "file", "files")} checked`;
        if (stopped) {
            return { headline: `So far, ${lowerFirst(headline)}`, lines, banner: `${banner} ${checked}.` };
        }
        const skipped = skippedTotal(report);
        let line = `${input.kindLabel || "Scan"} finished in ${S().formatDuration(report.elapsed_ms || 0)}. ` +
            (skipped > 0 ? `${checked}, ${S().formatCount(skipped)} skipped.` : `${checked}.`);
        if (m > 0 || s > 0) {
            line += ` ${NOTHING_CHANGED}`;
        }
        lines.push(line);
        return { headline, lines };
    }

    function oneFile(input) {
        const result = input.fileResult || {};
        const headline = { Malicious: "This file is likely malicious.", Suspicious: "This file is worth a look.",
            Clean: "This file looks clean." }[result.verdict] || "This file was checked.";
        return { headline, lines: [`${result.file_name}. Score ${result.score}.`] };
    }

    function failed(input) {
        const text = input.error === undefined || input.error === null || input.error === ""
            ? "Something went wrong."
            : typeof input.error === "string" ? input.error : String(input.error);
        return { headline: "The scan could not start.", lines: [text] };
    }

    // The headline and the lines under it for the scan screen. `lines` is an
    // array so the page can set each on its own row; a stopped scan also has
    // `banner`, the existing stop-reason text plus the files checked.
    function summarySentence(input) {
        const data = input || {};
        switch (data.phase) {
            case "scanning": return scanning(data);
            case "done": return finished(data);
            case "file": return oneFile(data);
            case "error": return failed(data);
            default: return idle(data);
        }
    }

    // Lower case, forward slashes, no trailing slash, no Windows "\\?\" prefix.
    function normalize(path) {
        return String(path).replace(/\\/g, "/").replace(/^\/\/\?\//, "").replace(/\/+$/, "").toLowerCase();
    }

    function belongsTo(findingPath, placePath) {
        const f = normalize(findingPath);
        const p = normalize(placePath);
        return f === p || f.startsWith(`${p}/`);
    }

    // The place with the longest matching path, or null.
    function placeOf(finding, places) {
        let best = null;
        let bestLength = -1;
        for (const place of places) {
            const length = normalize(place.path).length;
            if (belongsTo(finding.path, place.path) && length > bestLength) {
                best = place;
                bestLength = length;
            }
        }
        return best;
    }

    function placeChips(findings, places) {
        const list = Array.isArray(places) ? places : [];
        const counts = new Map();
        let other = 0;
        for (const finding of findings) {
            const place = placeOf(finding, list);
            if (place) {
                counts.set(place.path, (counts.get(place.path) || 0) + 1);
            } else {
                other += 1;
            }
        }
        const chips = list
            .filter((place, i) => counts.has(place.path) && list.findIndex(p => p.path === place.path) === i)
            .map(place => ({ key: place.path, label: place.label, count: counts.get(place.path) }))
            .sort((a, b) => b.count - a.count);
        const all = [{ key: ALL, label: "All", count: findings.length }, ...chips];
        if (other > 0) {
            all.push({ key: OTHER, label: "Other", count: other });
        }
        return all;
    }

    function filterFindings(findings, places, key) {
        if (key === undefined || key === null || key === ALL) {
            return findings.slice();
        }
        const list = Array.isArray(places) ? places : [];
        return findings.filter(finding => {
            const place = placeOf(finding, list);
            return key === OTHER ? place === null : place !== null && place.path === key;
        });
    }

    function viewFromHash(hash) {
        if (typeof hash !== "string") {
            return "scan";
        }
        const name = hash.replace(/^#/, "").toLowerCase();
        return VIEWS.includes(name) ? name : "scan";
    }

    function hashForView(view) {
        return `#${VIEWS.includes(view) ? view : "scan"}`;
    }

    // Which backend command a choice runs. Quick with every place checked is
    // the existing quick scan; a subset, and Custom, go to scan_selected_cmd.
    function scanRequest(mode, places, checked, customFolders, recursive) {
        if (mode === "full") {
            return { command: "scan_full_cmd", args: {} };
        }
        if (mode === "quick") {
            const wanted = new Set(checked || []);
            const paths = (places || []).map(place => place.path).filter(path => wanted.has(path));
            if (paths.length === 0) {
                return { error: NO_FOLDER };
            }
            if (paths.length === (places || []).length) {
                return { command: "scan_quick_cmd", args: {} };
            }
            return { command: "scan_selected_cmd", args: { paths, preset: "quick", recursive: true } };
        }
        if (mode === "custom") {
            const paths = [...new Set(customFolders || [])];
            if (paths.length === 0) {
                return { error: NO_FOLDER };
            }
            return { command: "scan_selected_cmd", args: { paths, preset: "custom", recursive: !!recursive } };
        }
        return { error: "Choose how to scan." };
    }

    root.ViewModel = {
        numberWord, checkedText, summarySentence, placeChips, filterFindings,
        viewFromHash, hashForView, scanRequest,
    };
})(window);

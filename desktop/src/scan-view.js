// Pure logic behind the scan screen: wording, sorting, shortening, counts.
// Nothing here touches the page or Tauri, so it can be checked with Node
// (desktop/tests/scan-view.test.js). main.js does the DOM work. A classic
// script: it defines `ScanView` on `window`.

(function (root) {
    // The engine's reason strings come from core/src/scoring.rs. Matched by
    // prefix, because some carry a suffix: "STRONG_CODE_PATTERN(x2)".
    const REASONS = [
        ["EICAR standard antivirus test file detected", "The standard antivirus test file"],
        ["Known malware signature detected", "Matches a known malware signature"],
        ["ZIP_BOMB_LIMIT_EXCEEDED", "Archive expands to an extreme size (possible zip bomb)"],
        ["EXTENSION_MASQUERADE", "The file type does not match its name"],
        ["HIGH_ENTROPY_EXECUTABLE", "Executable looks packed or encrypted"],
        ["RANSOMWARE_EXTENSION", "Has a file extension used by ransomware"],
        ["RANSOMWARE_NOTE_TEXT", "Contains text like a ransom note"],
        ["RANSOMWARE_DIRECTORY_BEHAVIOR", "Sits among files that look like ransomware damage"],
        ["TROJAN_NAME_SIGNATURE", "The file name matches a known trojan name"],
        ["STRONG_CODE_PATTERN", "Contains code patterns often used by malware"],
        ["WEAK_CODE_PATTERN", "Contains code patterns that are sometimes suspicious"],
        ["ROOTKIT_BINARY_IN_DRIVER_LOCATION", "Driver-like file in a system driver location"],
        ["ROOTKIT_TEXT_PATTERN", "Contains text about hiding from the operating system"],
        ["ZIP_CONTAINS_EXECUTABLE_ENTRY", "Archive contains executable files"],
    ];
    const YARA_PREFIX = "YARA-X pattern match:";
    const ELLIPSIS = "\u2026";

    function reasonText(reason) {
        if (reason.startsWith(YARA_PREFIX)) {
            return `Matches a detection rule (${reason.slice(YARA_PREFIX.length).trim()})`;
        }
        for (const [prefix, plain] of REASONS) {
            if (reason.startsWith(prefix)) {
                return plain;
            }
        }
        return reason; // unknown: show what the engine said
    }

    // Keeps the start and, more of, the end (the file name). Counts code
    // points, so a character made of two code units is never cut in half.
    function shortenMiddle(text, max) {
        const chars = Array.from(text);
        if (chars.length <= max) {
            return text;
        }
        if (max <= 1) {
            return ELLIPSIS;
        }
        const keep = max - 1;
        const head = Math.floor(keep * 0.4);
        const tail = keep - head;
        return chars.slice(0, head).join("") + ELLIPSIS + chars.slice(chars.length - tail).join("");
    }

    function byScoreThenPath(a, b) {
        if (b.result.score !== a.result.score) {
            return b.result.score - a.result.score;
        }
        return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
    }

    function splitFindings(findings) {
        return {
            malicious: findings.filter(f => f.result.verdict === "Malicious").sort(byScoreThenPath),
            suspicious: findings.filter(f => f.result.verdict === "Suspicious").sort(byScoreThenPath),
        };
    }

    // Returns the findings whose path is not in `seen` yet, and adds them.
    function takeUnseen(seen, findings) {
        const fresh = [];
        for (const finding of findings) {
            if (!seen.has(finding.path)) {
                seen.add(finding.path);
                fresh.push(finding);
            }
        }
        return fresh;
    }

    function formatCount(n) {
        return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }

    function formatDuration(ms) {
        if (ms < 60000) {
            return `${(Math.floor(ms / 100) / 10).toFixed(1)} s`;
        }
        const seconds = Math.floor(ms / 1000);
        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
        }
        return `${Math.floor(seconds / 3600)} h ${Math.floor((seconds % 3600) / 60)} min`;
    }

    function bannerText(stopReason) {
        switch (stopReason) {
            case "cancelled":
                return "Scan cancelled. Showing what was found so far.";
            case "findings_cap":
                return "Stopped after 2,000 findings. Review these, then scan again.";
            case "time_budget":
                return "Stopped at the time limit.";
            default:
                return "";
        }
    }

    function progressText(progress) {
        return `Scanned ${formatCount(progress.scanned)} files, ${formatCount(progress.findings)} flagged`;
    }

    function summaryText(report) {
        return (
            `Scanned ${formatCount(report.scanned)} files in ${formatDuration(report.elapsed_ms)}. ` +
            `Clean ${formatCount(report.clean)}, worth a look ${formatCount(report.suspicious)}, ` +
            `likely malicious ${formatCount(report.malicious)}.`
        );
    }

    function skippedText(report) {
        const parts = [
            [report.skipped_excluded, "excluded"],
            [report.skipped_too_large, "over 100 MB"],
            [report.skipped_links_or_special, "links or special files"],
            [report.unreadable_files, "unreadable files"],
            [report.unreadable_dirs, "unreadable folders"],
        ]
            .filter(([count]) => count > 0)
            .map(([count, label]) => `${formatCount(count)} ${label}`);
        return parts.length ? `Skipped: ${parts.join(", ")}.` : "";
    }

    function syncText(result) {
        let text = `Synced ${formatCount(result.new_signatures)} new (${formatCount(result.total_signatures)} total)`;
        if (result.feed_errors.length > 0) {
            const reasons = result.feed_errors.map(e => shortenMiddle(e, 120)).join("; ");
            text += `; ${result.feed_errors.length} feed(s) failed: ${reasons}`;
        }
        return text;
    }

    const api = {
        reasonText, shortenMiddle, splitFindings, takeUnseen, formatCount, formatDuration,
        bannerText, progressText, summaryText, skippedText, syncText,
    };
    root.ScanView = api;
})(window);

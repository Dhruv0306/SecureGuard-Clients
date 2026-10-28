// No bundler, no npm frontend dependencies: window.__TAURI__ is injected
// globally by Tauri (withGlobalTauri: true in tauri.conf.json), exposing
// both `core.invoke` (calls into commands.rs), `event.listen` (scan progress)
// and `dialog.open` / `dialog.confirm` (the native pickers and prompts)
// without needing to import anything. The wording, sorting and formatting
// live in scan-view.js (window.ScanView) so they can be checked under Node.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { open, confirm } = window.__TAURI__.dialog;
const V = window.ScanView;

const pickFileBtn = document.getElementById("pick-file-btn");
const pickedFileLabel = document.getElementById("picked-file");
const verdictPanel = document.getElementById("verdict-panel");
const verdictBadge = document.getElementById("verdict-badge");
const verdictDetails = document.getElementById("verdict-details");
const historyList = document.getElementById("history-list");
const syncBtn = document.getElementById("sync-btn");
const syncStatus = document.getElementById("sync-status");
const domainInput = document.getElementById("domain-input");
const blockDomainBtn = document.getElementById("block-domain-btn");
const domainStatus = document.getElementById("domain-status");
const blockedDomainsList = document.getElementById("blocked-domains-list");

const scanFolderBtn = document.getElementById("scan-folder-btn");
const recursiveBox = document.getElementById("recursive-checkbox");
const quickScanBtn = document.getElementById("quick-scan-btn");
const fullScanBtn = document.getElementById("full-scan-btn");
const cancelScanBtn = document.getElementById("cancel-scan-btn");
const scanProgress = document.getElementById("scan-progress");
const progressText = document.getElementById("progress-text");
const progressDir = document.getElementById("progress-dir");
const scanBanner = document.getElementById("scan-banner");
const scanSummary = document.getElementById("scan-summary");
const summaryText = document.getElementById("summary-text");
const skippedText = document.getElementById("skipped-text");
const scanResults = document.getElementById("scan-results");
const noFindings = document.getElementById("no-findings");
const maliciousHeading = document.getElementById("malicious-heading");
const maliciousList = document.getElementById("malicious-list");
const suspiciousGroup = document.getElementById("suspicious-group");
const suspiciousSummary = document.getElementById("suspicious-summary");
const suspiciousList = document.getElementById("suspicious-list");

async function refreshHistory() {
    try {
        const scans = await invoke("recent_scans_cmd", { limit: 20 });
        historyList.innerHTML = "";
        for (const scan of scans) {
            const li = document.createElement("li");
            li.className = `history-item verdict-${scan.verdict.toLowerCase()}`;
            li.textContent = `${scan.file_name} — ${scan.verdict} (score ${scan.score})`;
            historyList.appendChild(li);
        }
    } catch (err) {
        console.error("failed to load history:", err);
    }
}

function renderVerdict(result) {
    verdictPanel.classList.remove("hidden");
    verdictBadge.textContent = result.verdict;
    verdictBadge.className = `verdict-badge verdict-${result.verdict.toLowerCase()}`;

    const lines = [
        `File: ${result.file_name}`,
        `SHA-256: ${result.sha256}`,
        `Score: ${result.score}`,
    ];
    if (result.threat_type) {
        lines.push(`Threat type: ${result.threat_type}`);
    }
    if (result.contributions.length > 0) {
        lines.push("Contributing signals:");
        for (const c of result.contributions) {
            lines.push(`  \u2022 ${c.reason} (+${c.points})`);
        }
    }
    verdictDetails.textContent = lines.join("\n");
}

pickFileBtn.addEventListener("click", async () => {
    const path = await open({ multiple: false, directory: false });
    if (!path) {
        return; // user cancelled the dialog
    }

    pickedFileLabel.textContent = path;
    pickFileBtn.disabled = true;
    pickFileBtn.textContent = "Scanning\u2026";

    try {
        const result = await invoke("scan_file_cmd", { path });
        renderVerdict(result);
        await refreshHistory();
    } catch (err) {
        verdictPanel.classList.remove("hidden");
        verdictBadge.textContent = "ERROR";
        verdictBadge.className = "verdict-badge verdict-error";
        verdictDetails.textContent = String(err);
    } finally {
        pickFileBtn.disabled = false;
        pickFileBtn.textContent = "Choose file to scan\u2026";
    }
});

syncBtn.addEventListener("click", async () => {
    // do_sync holds the database lock while it fetches, which would stall a
    // scan's history write, so a scan and a sync never run together.
    syncing = true;
    refreshControls();
    syncStatus.textContent = "Syncing\u2026";

    try {
        const result = await invoke("sync_signatures_cmd");
        syncStatus.textContent = V.syncText(result);
    } catch (err) {
        syncStatus.textContent = `Sync failed: ${err}`;
    } finally {
        syncing = false;
        refreshControls();
    }
});

refreshHistory();
refreshBlockedDomains();

async function refreshBlockedDomains() {
    try {
        const domains = await invoke("list_blocked_domains_cmd");
        renderBlockedDomains(domains);
    } catch (err) {
        console.error("failed to load blocked domains:", err);
    }
}

function renderBlockedDomains(domains) {
    blockedDomainsList.innerHTML = "";
    for (const domain of domains) {
        const li = document.createElement("li");
        li.className = "domain-item";

        const label = document.createElement("span");
        label.textContent = domain;
        li.appendChild(label);

        const unblockBtn = document.createElement("button");
        unblockBtn.textContent = "Unblock";
        unblockBtn.className = "unblock-btn";
        unblockBtn.addEventListener("click", () => unblockDomain(domain));
        li.appendChild(unblockBtn);

        blockedDomainsList.appendChild(li);
    }
}

async function unblockDomain(domain) {
    domainStatus.textContent = `Unblocking ${domain}\u2026`;
    try {
        await invoke("unblock_domain_cmd", { domain });
        domainStatus.textContent = `Unblocked ${domain}`;
        await refreshBlockedDomains();
    } catch (err) {
        // block_domain_cmd/unblock_domain_cmd roll back their DB change on
        // helper failure (see desktop/src-tauri/src/commands.rs), so a
        // failure here means the domain's active state is unchanged, not
        // left inconsistent, refreshing still shows the accurate list.
        domainStatus.textContent = `Failed to unblock ${domain}: ${err}`;
        await refreshBlockedDomains();
    }
}

blockDomainBtn.addEventListener("click", async () => {
    const domain = domainInput.value.trim();
    if (!domain) {
        return;
    }

    blockDomainBtn.disabled = true;
    domainStatus.textContent = `Blocking ${domain}\u2026`;

    try {
        await invoke("block_domain_cmd", { domain, reason: null });
        domainStatus.textContent = `Blocked ${domain}`;
        domainInput.value = "";
        await refreshBlockedDomains();
    } catch (err) {
        domainStatus.textContent = `Failed to block ${domain}: ${err}`;
    } finally {
        blockDomainBtn.disabled = false;
    }
});

domainInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        blockDomainBtn.click();
    }
});

// --- Folder, quick and full scan ---------------------------------------

// One scan at a time, and never together with a sync (see the sync handler).
let scanning = false;
let cancelling = false;
let syncing = false;
// Set when the scan command returns, so a progress event that arrives late
// cannot add rows to, or change, the final report.
let finished = false;
// Paths already shown, so a finding sent live is not shown again.
const shownPaths = new Set();
let maliciousShown = 0;
let suspiciousShown = 0;

function refreshControls() {
    const busy = scanning || syncing;
    for (const control of [scanFolderBtn, recursiveBox, quickScanBtn, fullScanBtn]) {
        control.disabled = busy;
    }
    syncBtn.disabled = busy;
    cancelScanBtn.classList.toggle("hidden", !scanning);
    cancelScanBtn.disabled = cancelling;
    cancelScanBtn.textContent = cancelling ? "Cancelling\u2026" : "Cancel";
}

function showBanner(text, isError) {
    scanBanner.textContent = text;
    scanBanner.classList.toggle("banner-error", Boolean(isError));
    scanBanner.classList.toggle("hidden", text === "");
}

function updateGroupHeadings() {
    maliciousHeading.textContent = `Likely malicious (${V.formatCount(maliciousShown)})`;
    maliciousHeading.classList.toggle("hidden", maliciousShown === 0);
    suspiciousSummary.textContent = `Worth a look (${V.formatCount(suspiciousShown)})`;
    suspiciousGroup.classList.toggle("hidden", suspiciousShown === 0);
}

function resetResults() {
    maliciousList.replaceChildren();
    suspiciousList.replaceChildren();
    shownPaths.clear();
    maliciousShown = 0;
    suspiciousShown = 0;
    suspiciousGroup.open = false;
    scanResults.classList.add("hidden");
    noFindings.classList.add("hidden");
    scanSummary.classList.add("hidden");
    showBanner("", false);
    updateGroupHeadings();
}

// Everything shown comes from the engine or the file system, so it is set as
// text, never as markup: a path containing "<" or "&" is shown as it is.
function findingRow(finding) {
    const malicious = finding.result.verdict === "Malicious";
    const row = document.createElement("li");
    row.className = `finding-row verdict-${malicious ? "malicious" : "suspicious"}`;

    const head = document.createElement("div");
    head.className = "finding-head";
    const badge = document.createElement("span");
    badge.className = `verdict-badge verdict-${malicious ? "malicious" : "suspicious"}`;
    badge.textContent = malicious ? "Likely malicious" : "Worth a look";
    const score = document.createElement("span");
    score.className = "finding-score";
    score.textContent = `score ${finding.result.score}`;
    head.append(badge, score);

    const path = document.createElement("div");
    path.className = "finding-path";
    path.title = finding.path;
    path.textContent = V.shortenMiddle(finding.path, 90);

    const reasons = document.createElement("ul");
    reasons.className = "finding-reasons";
    for (const contribution of finding.result.contributions) {
        const item = document.createElement("li");
        item.textContent = V.reasonText(contribution.reason);
        // The engine's own wording and points, for anyone looking closer.
        item.title = `${contribution.reason} (+${contribution.points})`;
        reasons.appendChild(item);
    }

    row.append(head, path, reasons);
    return row;
}

function appendFindings(findings) {
    if (findings.length === 0) {
        return;
    }
    const groups = V.splitFindings(findings);
    const maliciousRows = document.createDocumentFragment();
    for (const finding of groups.malicious) {
        maliciousRows.appendChild(findingRow(finding));
    }
    const suspiciousRows = document.createDocumentFragment();
    for (const finding of groups.suspicious) {
        suspiciousRows.appendChild(findingRow(finding));
    }
    maliciousList.appendChild(maliciousRows);
    suspiciousList.appendChild(suspiciousRows);
    maliciousShown += groups.malicious.length;
    suspiciousShown += groups.suspicious.length;
    scanResults.classList.remove("hidden");
    updateGroupHeadings();
}

// The final report replaces the live list: it is sorted and capped, and it
// is the authoritative one.
function showReport(report) {
    resetResults();
    for (const finding of report.findings) {
        shownPaths.add(finding.path);
    }
    appendFindings(report.findings);
    scanResults.classList.remove("hidden");
    noFindings.classList.toggle("hidden", report.findings.length > 0);

    summaryText.textContent = V.summaryText(report);
    skippedText.textContent = V.skippedText(report);
    scanSummary.classList.remove("hidden");
    showBanner(V.bannerText(report.stop_reason), false);
}

async function runScan(start) {
    if (scanning) {
        return;
    }
    resetResults();
    finished = false;
    scanning = true;
    cancelling = false;
    refreshControls();
    progressText.textContent = "Starting\u2026";
    progressDir.textContent = "";
    scanProgress.classList.remove("hidden");

    try {
        const report = await start();
        finished = true;
        showReport(report);
        await refreshHistory();
    } catch (err) {
        finished = true;
        showBanner(String(err), true);
    } finally {
        scanning = false;
        cancelling = false;
        scanProgress.classList.add("hidden");
        refreshControls();
    }
}

scanFolderBtn.addEventListener("click", async () => {
    const path = await open({ directory: true, multiple: false });
    if (!path) {
        return; // user cancelled the dialog
    }
    runScan(() => invoke("scan_folder_cmd", { path, recursive: recursiveBox.checked }));
});

quickScanBtn.addEventListener("click", () => {
    runScan(() => invoke("scan_quick_cmd"));
});

fullScanBtn.addEventListener("click", async () => {
    const go = await confirm(
        "A full scan checks every drive and can take a long time. You can cancel at any time. Start?",
        { title: "Full scan", kind: "warning" }
    );
    if (go) {
        runScan(() => invoke("scan_full_cmd"));
    }
});

cancelScanBtn.addEventListener("click", async () => {
    // A cancel can take as long as the file being read (up to 100 MB).
    cancelling = true;
    refreshControls();
    try {
        await invoke("cancel_scan_cmd");
    } catch (err) {
        console.error("cancel failed:", err);
    }
});

// Events from the Rust side. Registered once, at startup.
(async () => {
    await listen("scan-progress", (event) => {
        if (finished || !scanning) {
            return;
        }
        const progress = event.payload;
        progressText.textContent = V.progressText(progress);
        progressDir.textContent = V.shortenMiddle(progress.current_dir, 80);
        appendFindings(V.takeUnseen(shownPaths, progress.new_findings || []));
    });

    // Closing the window during a scan is stopped on the Rust side; ask here.
    await listen("close-blocked-by-scan", async () => {
        const exit = await confirm("A scan is running. Cancel it and exit?", {
            title: "SecureGuard",
            kind: "warning",
        });
        if (exit) {
            await invoke("cancel_scan_cmd");
            await invoke("exit_app_cmd");
        }
    });
})().catch((err) => console.error("failed to register scan events:", err));

// No bundler, no npm frontend dependencies: window.__TAURI__ is injected
// globally by Tauri (withGlobalTauri: true in tauri.conf.json), exposing
// both `core.invoke` (calls into commands.rs) and `dialog.open` (the
// native file picker) without needing to import anything.

const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;

const pickFileBtn = document.getElementById("pick-file-btn");
const pickedFileLabel = document.getElementById("picked-file");
const verdictPanel = document.getElementById("verdict-panel");
const verdictBadge = document.getElementById("verdict-badge");
const verdictDetails = document.getElementById("verdict-details");
const historyList = document.getElementById("history-list");
const syncBtn = document.getElementById("sync-btn");
const syncStatus = document.getElementById("sync-status");

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
    syncBtn.disabled = true;
    syncStatus.textContent = "Syncing\u2026";

    try {
        const result = await invoke("sync_signatures_cmd");
        syncStatus.textContent = `Synced ${result.new_signatures} new (${result.total_signatures} total)`;
        if (result.feed_errors.length > 0) {
            syncStatus.textContent += ` \u2014 ${result.feed_errors.length} feed(s) failed`;
        }
    } catch (err) {
        syncStatus.textContent = `Sync failed: ${err}`;
    } finally {
        syncBtn.disabled = false;
    }
});

refreshHistory();

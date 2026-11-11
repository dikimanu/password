// AI Security Advisor: loads personalized security insights on the dashboard.
document.addEventListener("DOMContentLoaded", function () {
    const loadingEl = document.getElementById("ai-advisor-loading");
    const contentEl = document.getElementById("ai-advisor-content");
    const statusEl = document.getElementById("ai-advisor-status");
    if (!loadingEl || !contentEl) return;

    // ---- Rotating status text while we wait ----
    const messages = [
        "Reading your recent login activity...",
        "Checking your security events...",
        "Comparing against your account risk level...",
        "Looking at your two-factor authentication status...",
        "Writing your personalized advice..."
    ];
    let msgIndex = 0;
    let statusTimer = null;

    function setStatus(text) {
        if (!statusEl) return;
        statusEl.classList.add("ai-fade");
        setTimeout(() => {
            statusEl.textContent = text;
            statusEl.classList.remove("ai-fade");
        }, 250);
    }

    if (statusEl) {
        statusTimer = setInterval(() => {
            msgIndex++;
            if (msgIndex >= messages.length) {
                setStatus("Still working... the AI is a bit slow right now.");
                clearInterval(statusTimer);
                return;
            }
            setStatus(messages[msgIndex]);
        }, 3500);
    }

    // ---- Safe rendering of the AI's text ----
    function escapeHtml(text) {
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    // Converts the AI's simple Markdown (headings, **bold**, bullets) into safe HTML.
    // Everything is escaped first, so no HTML or script from the AI can ever run.
    function renderInsights(text) {
        const lines = escapeHtml(String(text || "")).split(/\r?\n/);
        let html = "";
        let inList = false;

        for (const rawLine of lines) {
            const line = rawLine.trim();
            const heading = line.match(/^#{1,6}\s+(.*)$/);
            const bullet = line.match(/^[-*•]\s+(.*)$/);
            const bold = s => s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");

            if (bullet) {
                if (!inList) { html += "<ul>"; inList = true; }
                html += `<li>${bold(bullet[1])}</li>`;
                continue;
            }
            if (inList) { html += "</ul>"; inList = false; }

            if (heading) {
                html += `<h6 class="mt-3 mb-1">${bold(heading[1])}</h6>`;
            } else if (line) {
                html += `<p class="mb-1">${bold(line)}</p>`;
            }
        }
        if (inList) html += "</ul>";
        return html;
    }

    // ---- Fetch the insights ----
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 70000);

    fetch("/user/api/security-insights", {
        credentials: "same-origin",
        signal: controller.signal
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch security insights (HTTP " + response.status + ").");
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.insights) {
                throw new Error("Empty insights response.");
            }
            contentEl.innerHTML = renderInsights(data.insights);
            loadingEl.style.display = "none";
            contentEl.style.display = "block";
            contentEl.classList.add("ai-reveal");
        })
        .catch(error => {
            loadingEl.innerHTML = '<span class="text-danger">Could not load AI Security Advisor insights at this time.</span>';
            console.error("Error fetching insights:", error);
        })
        .finally(() => {
            clearTimeout(timer);
            if (statusTimer) clearInterval(statusTimer);
        });
});
async function fetchJSON(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (data && data.error) msg = data.error;
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

function escapeHtml(s) {
  return (s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadLabels() {
  const tbody = document.getElementById("labels-table-body");
  const status = document.getElementById("labels-status");
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="4" class="text-muted">Loading…</td></tr>`;
  if (status) status.textContent = "";

  const labels = await fetchJSON("/api/labels");

  if (!labels.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-muted">No labels returned.</td></tr>`;
    return;
  }

  tbody.innerHTML = labels
    .map((l) => {
      return `
        <tr>
          <td>${escapeHtml(l.name)}</td>
          <td class="text-end">${l.messagesUnread ?? 0}</td>
          <td class="text-end">${l.messagesTotal ?? 0}</td>
          <td class="text-end">
            <button class="btn btn-sm btn-outline-secondary" data-markread="${escapeHtml(
              l.id
            )}">Mark Read</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("[data-markread]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-markread");
      if (!confirm("Mark all unread messages in this label as read?")) return;

      if (status) status.textContent = "Marking read…";
      try {
        const data = await fetchJSON(`/api/labels/${id}/mark-read`, { method: "POST" });
        if (status) status.textContent = data.message || "Done.";
        await loadLabels();
      } catch (e) {
        if (status) status.textContent = `Error: ${e.message}`;
      }
    });
  });
}

async function initDefaultLabels() {
  const status = document.getElementById("init-labels-status");
  if (status) status.textContent = "Initializing default labels…";

  try {
    const data = await fetchJSON("/init-default-labels", { method: "POST" });
    if (status) status.textContent = `Ensured ${data.count} labels.`;
    await loadLabels();
  } catch (e) {
    if (status) status.textContent = `Error: ${e.message}`;
  }
}

async function runLabeler() {
  const status = document.getElementById("run-labeler-status");
  const logLink = document.getElementById("download-run-log-link");

  if (status) status.textContent = "Running labeler…";

  try {
    const res = await fetch("/run-labeler", { method: "POST" });
    if (!res.ok) {
      if (status) status.textContent = `Error: ${res.status} ${res.statusText}`;
      return;
    }
    const data = await res.json();
    if (status) {
      status.textContent = `Done. Processed=${data.processed}, Rule=${data.rule_labeled}, AI=${data.ai_labeled}`;
    }
    if (logLink && data.log_download_url) {
      logLink.href = data.log_download_url;
      logLink.style.display = "inline";
    }

    // Refresh labels after run so counts reflect changes
    await loadLabels();
  } catch (e) {
    if (status) status.textContent = `Error: ${e.message || e}`;
  }
}

function wireCollapseToggleLabel() {
  const collapseEl = document.getElementById("labelsCollapse");
  const btn = document.getElementById("toggle-labels-btn");
  if (!collapseEl || !btn) return;

  const updateText = () => {
    const isShown = collapseEl.classList.contains("show");
    btn.textContent = isShown ? "Collapse" : "Expand";
  };

  collapseEl.addEventListener("shown.bs.collapse", updateText);
  collapseEl.addEventListener("hidden.bs.collapse", updateText);
  updateText();
}

document.addEventListener("DOMContentLoaded", async () => {
  wireCollapseToggleLabel();

  try {
    await loadLabels();
  } catch (e) {
    console.error(e);
  }

  const refreshLabelsBtn = document.getElementById("refresh-labels-btn");
  if (refreshLabelsBtn) refreshLabelsBtn.addEventListener("click", loadLabels);

  const initBtn = document.getElementById("init-default-labels-btn");
  if (initBtn) initBtn.addEventListener("click", initDefaultLabels);

  const runBtn = document.getElementById("run-labeler-btn");
  if (runBtn) runBtn.addEventListener("click", runLabeler);
});

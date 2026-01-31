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

function setForm(rule) {
  document.getElementById("label-name").value = rule.label_name || "";
  document.getElementById("from-contains").value = rule.from_contains || "";
  document.getElementById("subject-contains").value = rule.subject_contains || "";
  document.getElementById("body-contains").value = rule.body_contains || "";
  document.getElementById("is-active").checked = !!rule.is_active;
  document.getElementById("mark-as-read").checked = !!rule.mark_as_read;
  document.getElementById("rule-form").dataset.editingId = rule.id;
}

function clearForm() {
  document.getElementById("label-name").value = "";
  document.getElementById("from-contains").value = "";
  document.getElementById("subject-contains").value = "";
  document.getElementById("body-contains").value = "";
  document.getElementById("is-active").checked = true;
  document.getElementById("mark-as-read").checked = false;
  delete document.getElementById("rule-form").dataset.editingId;
  const status = document.getElementById("rule-status");
  if (status) status.textContent = "";
}

async function loadRules() {
  const tbody = document.getElementById("rules-table-body");
  tbody.innerHTML = `<tr><td colspan="8" class="text-muted">Loading…</td></tr>`;
  const rules = await fetchJSON("/api/rules");

  if (!rules.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted">No rules yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = rules
    .map((r) => {
      return `
        <tr>
          <td>${r.id}</td>
          <td>${escapeHtml(r.label_name)}</td>
          <td>${escapeHtml(r.from_contains)}</td>
          <td>${escapeHtml(r.subject_contains)}</td>
          <td>${escapeHtml(r.body_contains)}</td>
          <td>${r.is_active ? "✅" : "—"}</td>
          <td>${r.mark_as_read ? "✅" : "—"}</td>
          <td class="text-end">
            <button class="btn btn-sm btn-outline-primary me-1" data-edit="${r.id}">Edit</button>
            <button class="btn btn-sm btn-outline-danger" data-del="${r.id}">Delete</button>
          </td>
        </tr>
      `;
    })
    .join("");

  // Wire edit/delete
  tbody.querySelectorAll("[data-edit]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-edit");
      const rule = rules.find((x) => String(x.id) === String(id));
      if (rule) setForm(rule);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  tbody.querySelectorAll("[data-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-del");
      if (!confirm(`Delete rule ${id}?`)) return;

      try {
        await fetchJSON(`/api/rules/${id}`, { method: "DELETE" });
        await loadRules();
      } catch (e) {
        alert(`Delete failed: ${e.message}`);
      }
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  // Initial load (rules only)
  try {
    await loadRules();
  } catch (e) {
    console.error(e);
  }

  // Refresh rules
  const refreshRulesBtn = document.getElementById("refresh-rules-btn");
  if (refreshRulesBtn) refreshRulesBtn.addEventListener("click", loadRules);

  // Learn rules
  const learnBtn = document.getElementById("learn-rules-btn");
  if (learnBtn) {
    learnBtn.addEventListener("click", async () => {
      const status = document.getElementById("learn-status");
      status.textContent = "Learning rules from labeled emails…";
      try {
        const data = await fetchJSON("/learn-rules", { method: "POST" });
        const created = data.created ?? 0;
        status.textContent = `Learned and created ${created} rule(s). Refreshing rules…`;
        await loadRules();
      } catch (e) {
        status.textContent = `Error: ${e.message}`;
      }
    });
  }

  // Create/update rule
  document.getElementById("rule-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const status = document.getElementById("rule-status");

    const label_name = document.getElementById("label-name").value.trim();
    const from_contains = document.getElementById("from-contains").value.trim();
    const subject_contains = document.getElementById("subject-contains").value.trim();
    const body_contains = document.getElementById("body-contains").value.trim();
    const is_active = document.getElementById("is-active").checked;
    const mark_as_read = document.getElementById("mark-as-read").checked;

    const payload = { label_name, from_contains, subject_contains, body_contains, is_active, mark_as_read };

    const editingId = document.getElementById("rule-form").dataset.editingId;
    const url = editingId ? `/api/rules/${editingId}` : "/api/rules";
    const method = editingId ? "PUT" : "POST";

    const res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      try {
        const data = await res.json();
        if (data && data.error) msg = data.error;
      } catch (_) {}
      status.textContent = `Save failed: ${msg}`;
      return;
    }

    status.textContent = "Saved.";
    clearForm();
    await loadRules();
  });

  // Clear form
  const clearBtn = document.getElementById("clear-btn");
  if (clearBtn) clearBtn.addEventListener("click", clearForm);
});

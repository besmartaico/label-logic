function renderRuleRow(rule) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${rule.id}</td>
    <td>${rule.label_name}</td>
    <td>${rule.from_contains || ""}</td>
    <td>${rule.subject_contains || ""}</td>
    <td>${rule.body_contains || ""}</td>
    <td>${rule.is_active ? "Yes" : "No"}</td>
    <td>${rule.mark_as_read ? "Yes" : "No"}</td>
    <td>
      <button class="btn btn-sm btn-outline-primary me-1 edit-btn">Edit</button>
      <button class="btn btn-sm btn-outline-danger delete-btn">Delete</button>
    </td>
  `;

  tr.querySelector(".edit-btn").addEventListener("click", () => {
    document.getElementById("label-name").value = rule.label_name || "";
    document.getElementById("from-contains").value = rule.from_contains || "";
    document.getElementById("subject-contains").value = rule.subject_contains || "";
    document.getElementById("body-contains").value = rule.body_contains || "";
    document.getElementById("is-active").checked = !!rule.is_active;
    document.getElementById("mark-as-read").checked = !!rule.mark_as_read;

    document.getElementById("rule-form").dataset.editingId = rule.id;
    document.getElementById("rule-status").textContent = `Editing rule ${rule.id}`;
  });

  tr.querySelector(".delete-btn").addEventListener("click", async () => {
    if (!confirm(`Delete rule ${rule.id}?`)) return;

    const res = await fetch(`/api/rules/${rule.id}`, { method: "DELETE" });
    if (!res.ok) {
      alert(`Delete failed: ${res.status}`);
      return;
    }
    await loadRules();
  });

  return tr;
}

async function loadRules() {
  const tbody = document.querySelector("#rules-table tbody");
  tbody.innerHTML = `
    <tr><td colspan="8" class="text-center text-muted py-4">Loading…</td></tr>
  `;

  const res = await fetch("/api/rules");
  if (!res.ok) {
    tbody.innerHTML = `
      <tr><td colspan="8" class="text-center text-danger py-4">Error loading rules</td></tr>
    `;
    return;
  }

  const rules = await res.json();
  tbody.innerHTML = "";

  if (!rules.length) {
    tbody.innerHTML = `
      <tr><td colspan="8" class="text-center text-muted py-4">No rules yet. Create one above.</td></tr>
    `;
    return;
  }

  for (const r of rules) {
    tbody.appendChild(renderRuleRow(r));
  }
}

async function loadLabels() {
  const tbody = document.querySelector("#labels-table tbody");
  tbody.innerHTML = `
    <tr><td colspan="4" class="text-center text-muted py-4">Loading…</td></tr>
  `;

  const res = await fetch("/api/labels");
  if (!res.ok) {
    tbody.innerHTML = `
      <tr><td colspan="4" class="text-center text-danger py-4">Error loading labels</td></tr>
    `;
    return;
  }

  const labels = await res.json();
  tbody.innerHTML = "";

  if (!labels.length) {
    tbody.innerHTML = `
      <tr><td colspan="4" class="text-center text-muted py-4">No labels found.</td></tr>
    `;
    return;
  }

  for (const lbl of labels) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${lbl.name}</td>
      <td class="text-end">${lbl.messagesUnread ?? 0}</td>
      <td class="text-end">${lbl.messagesTotal ?? 0}</td>
      <td class="text-end">
        <button class="btn btn-sm btn-outline-secondary mark-read-btn">Mark Read</button>
      </td>
    `;

    tr.querySelector(".mark-read-btn").addEventListener("click", async () => {
      const ok = confirm(`Mark all unread in "${lbl.name}" as read?`);
      if (!ok) return;

      tr.querySelector(".mark-read-btn").disabled = true;
      tr.querySelector(".mark-read-btn").textContent = "Working…";

      const resp = await fetch(`/api/labels/${lbl.id}/mark-read`, { method: "POST" });
      const data = await resp.json();

      if (!resp.ok) {
        alert(data?.error || `Error: ${resp.status}`);
      } else {
        alert(data?.message || "Done");
        await loadLabels();
      }

      tr.querySelector(".mark-read-btn").disabled = false;
      tr.querySelector(".mark-read-btn").textContent = "Mark Read";
    });

    tbody.appendChild(tr);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadRules();

  // Refresh labels
  document.getElementById("refresh-labels-btn").addEventListener("click", async () => {
    await loadLabels();
  });

  // Initialize default LL labels
  document.getElementById("init-labels-btn").addEventListener("click", async () => {
    const status = document.getElementById("init-labels-status");
    status.textContent = "Initializing default LL labels…";

    try {
      const res = await fetch("/init-default-labels", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        status.textContent = data?.error || `Error: ${res.status}`;
        return;
      }
      status.textContent = `Ensured ${data.count} labels.`;
      await loadLabels();
    } catch (e) {
      status.textContent = `Error: ${e}`;
    }
  });

  // Learn rules from labeled emails
  const learnBtn = document.getElementById("learn-rules-btn");
  if (learnBtn) {
    learnBtn.addEventListener("click", async () => {
      const status = document.getElementById("learn-rules-status");
      status.textContent = "Learning rules from existing labeled emails… (this can take a bit)";

      try {
        const res = await fetch("/learn-rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({})
        });

        if (!res.ok) {
          status.textContent = `Error: ${res.status}`;
          return;
        }

        const data = await res.json();
        const created = data.created ?? 0;
        status.textContent = `Learned and created ${created} rule(s). Refreshing rules…`;
        await loadRules();
      } catch (e) {
        status.textContent = `Error: ${e}`;
      }
    });
  }

  // Run labeler
  document.getElementById("run-labeler-btn").addEventListener("click", async () => {
    const status = document.getElementById("run-labeler-status");
    status.textContent = "Running labeler…";

    try {
      const res = await fetch("/run-labeler", { method: "POST" });
      if (!res.ok) {
        status.textContent = `Error: ${res.status}`;
        return;
      }
      const data = await res.json();
      status.textContent = `Done. Processed=${data.processed}, Rule=${data.rule_labeled}, AI=${data.ai_labeled}`;
    } catch (e) {
      status.textContent = `Error: ${e}`;
    }
  });

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

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      status.textContent = data?.error || `Error: ${res.status}`;
      return;
    }

    status.textContent = editingId ? `Rule ${editingId} updated.` : "Rule created.";
    delete document.getElementById("rule-form").dataset.editingId;

    document.getElementById("label-name").value = "";
    document.getElementById("from-contains").value = "";
    document.getElementById("subject-contains").value = "";
    document.getElementById("body-contains").value = "";
    document.getElementById("is-active").checked = true;
    document.getElementById("mark-as-read").checked = false;

    await loadRules();
  });

  // Clear form
  const clearBtn = document.getElementById("clear-form-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      delete document.getElementById("rule-form").dataset.editingId;
      document.getElementById("label-name").value = "";
      document.getElementById("from-contains").value = "";
      document.getElementById("subject-contains").value = "";
      document.getElementById("body-contains").value = "";
      document.getElementById("is-active").checked = true;
      document.getElementById("mark-as-read").checked = false;
      document.getElementById("rule-status").textContent = "Form cleared.";
    });
  }
});

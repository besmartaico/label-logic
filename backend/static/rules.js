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
      <button class="btn btn-sm btn-outline-secondary me-1 edit-btn">Edit</button>
      <button class="btn btn-sm btn-outline-danger delete-btn">Delete</button>
    </td>
  `;

  tr.querySelector(".edit-btn").addEventListener("click", () => {
    document.getElementById("rule-id").value = rule.id;
    document.getElementById("label-name").value = rule.label_name;
    document.getElementById("from-contains").value = rule.from_contains || "";
    document.getElementById("subject-contains").value = rule.subject_contains || "";
    document.getElementById("body-contains").value = rule.body_contains || "";
    document.getElementById("is-active").checked = !!rule.is_active;
    document.getElementById("mark-as-read").checked = !!rule.mark_as_read;
    document.getElementById("rule-status").textContent = `Editing rule #${rule.id}`;
  });

  tr.querySelector(".delete-btn").addEventListener("click", async () => {
    if (!confirm(`Delete rule #${rule.id}?`)) return;
    try {
      const res = await fetch(`/api/rules/${rule.id}`, { method: "DELETE" });
      if (!res.ok) {
        alert("Error deleting rule.");
        return;
      }
      document.getElementById("rule-status").textContent = `Deleted rule #${rule.id}`;
      fetchRules();
    } catch (err) {
      console.error(err);
      alert("Error deleting rule.");
    }
  });

  return tr;
}

async function fetchRules() {
  const tbody = document.querySelector("#rules-table tbody");
  tbody.innerHTML = `
    <tr>
      <td colspan="8" class="text-center text-muted small">Loading rules…</td>
    </tr>
  `;

  try {
    const res = await fetch("/api/rules");
    if (!res.ok) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center text-danger small">
            Error loading rules: ${res.status}
          </td>
        </tr>
      `;
      return;
    }

    const rules = await res.json();
    if (!rules.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center text-muted small">
            No rules yet. Create one above.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    rules.forEach(rule => {
      tbody.appendChild(renderRuleRow(rule));
    });

  } catch (err) {
    document.getElementById("rule-status").textContent = "Error loading rules.";
    console.error(err);
  }
}

async function loadGmailLabelOptions() {
  const sel = document.getElementById("label-select");
  if (!sel) return;

  try {
    const res = await fetch("/api/gmail-labels");
    if (!res.ok) {
      console.error("Error fetching Gmail labels for dropdown:", res.status);
      return;
    }

    const labels = await res.json();
    while (sel.options.length > 2) {
      sel.remove(2);
    }

    labels.forEach(label => {
      if (!label.name) return;
      const opt = document.createElement("option");
      opt.value = label.name;
      opt.textContent = label.name;
      sel.appendChild(opt);
    });
  } catch (err) {
    console.error("Error loading Gmail label options:", err);
  }
}

async function fetchLabels() {
  const tbody = document.querySelector("#labels-table tbody");
  const status = document.getElementById("labels-status");
  tbody.innerHTML = `
    <tr>
      <td colspan="4" class="text-center text-muted small">Loading labels…</td>
    </tr>
  `;
  status.textContent = "";

  try {
    const res = await fetch("/api/labels");
    if (!res.ok) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="text-center text-danger small">
            Error loading labels: ${res.status}
          </td>
        </tr>
      `;
      return;
    }

    const labels = await res.json();
    if (!labels.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="text-center text-muted small">
            No labels found.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    labels.forEach(label => {
      const tr = document.createElement("tr");
      const displayName = label.name === "UNREAD" ? "Unread" : label.name;

      tr.innerHTML = `
        <td>${displayName}</td>
        <td class="text-end">${label.messagesUnread}</td>
        <td class="text-end">${label.messagesTotal}</td>
        <td class="text-end">
          <button class="btn btn-sm btn-outline-primary mark-read-btn">
            Mark all as read
          </button>
        </td>
      `;

      tr.querySelector(".mark-read-btn").addEventListener("click", async () => {
        if (!confirm(`Mark all unread emails in "${displayName}" as read?`)) return;

        status.textContent = `Marking unread emails in "${displayName}" as read…`;

        try {
          const res2 = await fetch(`/api/labels/${label.id}/mark-read`, {
            method: "POST",
          });
          if (!res2.ok) {
            status.textContent = `Error marking label as read: ${res2.status}`;
            return;
          }
          const data2 = await res2.json();
          status.textContent = data2.message || "Done.";
          fetchLabels();
        } catch (err) {
          status.textContent = "Error marking label as read.";
          console.error(err);
        }
      });

      tbody.appendChild(tr);
    });

  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="text-center text-danger small">
          Error loading labels.
        </td>
      </tr>
    `;
    console.error(err);
  }
}

async function initDefaultLabels() {
  const status = document.getElementById("init-labels-status");
  status.textContent = "Creating default LL labels in Gmail…";

  try {
    const res = await fetch("/init-default-labels", { method: "POST" });
    if (!res.ok) {
      status.textContent = `Error initializing labels: ${res.status}`;
      return;
    }
    const data = await res.json();
    status.textContent =
      `Ensured ${data.count || 0} labels exist: ` +
      (data.ensured_labels || []).map(l => l.name).join(", ");
    loadGmailLabelOptions();
    fetchLabels();
  } catch (err) {
    console.error(err);
    status.textContent = "Error initializing labels.";
  }
}

async function learnFromUserLabels() {
  try {
    const res = await fetch("/learn-from-user-labels", { method: "POST" });
    if (!res.ok) {
      console.error("Error learning from user labels:", res.status);
      return;
    }
    const data = await res.json();
    console.log(
      `Learned from ${data.user_labeled_added} emails. Created ${data.rules_created} new rules.`
    );
    fetchRules();
  } catch (err) {
    console.error("Error learning from user labels.", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Rule form handlers
  document.getElementById("rule-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const payload = {
      label_name: document.getElementById("label-name").value,
      from_contains: document.getElementById("from-contains").value,
      subject_contains: document.getElementById("subject-contains").value,
      body_contains: document.getElementById("body-contains").value,
      is_active: document.getElementById("is-active").checked,
      mark_as_read: document.getElementById("mark-as-read").checked,
    };

    const ruleId = document.getElementById("rule-id").value;
    const url = ruleId ? `/api/rules/${ruleId}` : "/api/rules";
    const method = ruleId ? "PUT" : "POST";

    try {
      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        document.getElementById("rule-status").textContent =
          `Error saving rule (status ${res.status}).`;
        return;
      }

      const saved = await res.json();
      document.getElementById("rule-status").textContent =
        `Rule #${saved.id} saved.`;
      document.getElementById("rule-form").reset();
      document.getElementById("rule-id").value = "";
      document.getElementById("is-active").checked = true;
      document.getElementById("mark-as-read").checked = false;

      fetchRules();
    } catch (err) {
      console.error(err);
      document.getElementById("rule-status").textContent =
        "Unexpected error saving rule.";
    }
  });

  document.getElementById("clear-btn").addEventListener("click", () => {
    document.getElementById("rule-form").reset();
    document.getElementById("rule-id").value = "";
    document.getElementById("is-active").checked = true;
    document.getElementById("mark-as-read").checked = false;
    document.getElementById("rule-status").textContent = "Form cleared.";
  });

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
      status.textContent =
        `Processed ${data.processed} emails. ` +
        `Rules applied: ${data.rule_labeled}. ` +
        `AI-labeled: ${data.ai_labeled}.`;

    } catch (err) {
      status.textContent = "Error running labeler.";
      console.error(err);
    }
  });

  // Init default labels
  document.getElementById("init-labels-btn").addEventListener("click", initDefaultLabels);

  // Label dropdown change
  document.getElementById("label-select").addEventListener("change", (e) => {
    const selVal = e.target.value;
    const input = document.getElementById("label-name");
    if (!input) return;

    if (!selVal || selVal === "__custom__") {
      return;
    }
    input.value = selVal;
  });

  // Refresh labels table
  const refreshBtn = document.getElementById("refresh-labels-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", fetchLabels);
  }

  // Initial load
  learnFromUserLabels();
  fetchRules();
  loadGmailLabelOptions();
  fetchLabels();
});

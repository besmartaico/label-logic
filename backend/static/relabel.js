let targetLabelOptions = [];

async function loadTargetLabelOptions() {
  try {
    const res = await fetch("/api/gmail-labels");
    if (!res.ok) {
      console.error("Error fetching gmail labels:", res.status);
      return;
    }
    const labels = await res.json();
    targetLabelOptions = labels.map(l => l.name).filter(Boolean);
  } catch (err) {
    console.error("Error loading gmail label options:", err);
  }
}

function buildTargetSelect(defaultValue = "") {
  const sel = document.createElement("select");
  sel.className = "form-select form-select-sm";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "-- choose target --";
  sel.appendChild(placeholder);

  targetLabelOptions.forEach(name => {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    if (name === defaultValue) {
      opt.selected = true;
    }
    sel.appendChild(opt);
  });

  return sel;
}

async function fetchLabelsForRelabel() {
  const tbody = document.querySelector("#labels-table tbody");
  const status = document.getElementById("relabel-status");

  tbody.innerHTML = `
    <tr>
      <td colspan="5" class="text-center text-muted small">Loading labels…</td>
    </tr>
  `;
  status.textContent = "";

  try {
    const res = await fetch("/api/labels");
    if (!res.ok) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-danger small">
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
          <td colspan="5" class="text-center text-muted small">
            No labels found.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    labels.forEach(label => {
      const tr = document.createElement("tr");
      const name = label.name;

      const nameTd = document.createElement("td");
      nameTd.textContent = name;

      const unreadTd = document.createElement("td");
      unreadTd.className = "text-end";
      unreadTd.textContent = label.messagesUnread;

      const totalTd = document.createElement("td");
      totalTd.className = "text-end";
      totalTd.textContent = label.messagesTotal;

      const targetTd = document.createElement("td");
      const sel = buildTargetSelect();
      targetTd.appendChild(sel);

      const actionTd = document.createElement("td");
      actionTd.className = "text-end";
      const btn = document.createElement("button");
      btn.className = "btn btn-sm btn-outline-primary";
      btn.textContent = "Relabel";
      btn.addEventListener("click", async () => {
        const targetLabel = sel.value;
        if (!targetLabel) {
          alert("Please choose a target label first.");
          return;
        }
        if (!confirm(`Move all messages from "${name}" to "${targetLabel}"?`)) {
          return;
        }

        status.textContent = `Relabeling messages from "${name}" to "${targetLabel}"…`;

        try {
          const res2 = await fetch("/api/relabel", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              source_label: name,
              target_label: targetLabel,
            }),
          });

          if (!res2.ok) {
            status.textContent = `Error relabeling: ${res2.status}`;
            return;
          }

          const data2 = await res2.json();
          status.textContent =
            `Relabeled ${data2.updated} messages from "${data2.source_label}" to "${data2.target_label}".`;
          fetchLabelsForRelabel();
        } catch (err) {
          console.error(err);
          status.textContent = "Error relabeling messages.";
        }
      });
      actionTd.appendChild(btn);

      tr.appendChild(nameTd);
      tr.appendChild(unreadTd);
      tr.appendChild(totalTd);
      tr.appendChild(targetTd);
      tr.appendChild(actionTd);

      tbody.appendChild(tr);
    });

  } catch (err) {
    console.error(err);
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center text-danger small">
          Error loading labels.
        </td>
      </tr>
    `;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadTargetLabelOptions();
  fetchLabelsForRelabel();

  const refreshBtn = document.getElementById("refresh-labels-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      await loadTargetLabelOptions();
      fetchLabelsForRelabel();
    });
  }
});

function showStatus(id, msg, type){
  const el = document.getElementById(id);
  if(!el) return;
  el.className = 'status-msg ' + type;
  el.innerHTML = msg;
  el.style.display = msg ? 'block' : 'none';
}

document.addEventListener('DOMContentLoaded', async () => {

  // ── AI Instructions ────────────────────────────────────────
  // Load saved instructions
  try {
    const res = await fetch('/api/ai-instructions', {credentials:'same-origin'});
    const data = await res.json();
    const ta = document.getElementById('ai-instructions');
    if(ta && data.ai_instructions) ta.value = data.ai_instructions;
  } catch(e) { console.error('Failed to load AI instructions', e); }

  // Save button
  document.getElementById('save-ai-instructions-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('save-ai-instructions-btn');
    const text = document.getElementById('ai-instructions')?.value || '';
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-1"></span>Saving...';
    try {
      const res = await fetch('/api/ai-instructions', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ai_instructions: text})
      });
      const d = await res.json();
      if(d.error) throw new Error(d.error);
      showStatus('ai-instructions-status', '✓ Saved', 'success');
      setTimeout(() => showStatus('ai-instructions-status', '', ''), 3000);
    } catch(e) {
      showStatus('ai-instructions-status', 'Error: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-floppy me-1"></i>Save';
    }
  });

  // ── Init Default Labels ────────────────────────────────────
  document.getElementById('init-default-labels-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('init-default-labels-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-1"></span>Initializing...';
    showStatus('init-labels-status', 'Creating default @LL- labels in your Gmail...', 'info');
    try {
      const res = await fetch('/init-default-labels', {method:'POST', credentials:'same-origin'});
      const text = await res.text();
      if(text.trim().startsWith('<')) throw new Error('Session expired — please refresh.');
      const d = JSON.parse(text);
      if(d.error) throw new Error(d.error);
      showStatus('init-labels-status', `✓ ${d.count} labels ready in Gmail.`, 'success');
    } catch(e) {
      showStatus('init-labels-status', 'Error: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-tags me-1"></i>Init Default Labels';
    }
  });

  // ── Run Labeler ────────────────────────────────────────────
  document.getElementById('run-labeler-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('run-labeler-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-2"></span>Running...';
    showStatus('run-labeler-status', 'Scanning your inbox...', 'info');
    document.getElementById('run-stats').style.display = 'none';

    try {
      const res = await fetch('/run-labeler', {method:'POST', credentials:'same-origin'});
      const text = await res.text();
      if(text.trim().startsWith('<')) throw new Error('Session expired — please refresh.');
      const d = JSON.parse(text);
      if(d.error) throw new Error(d.error);

      showStatus('run-labeler-status', `✓ Done — processed ${d.processed} emails.`, 'success');

      // Stats chips
      const statsEl = document.getElementById('run-stats');
      statsEl.innerHTML = [
        ['Processed', d.processed],
        ['Rule Labeled', d.rule_labeled],
        ['AI Labeled', d.ai_labeled],
        ['Skipped', (d.processed - d.rule_labeled - d.ai_labeled)]
      ].map(([label, val]) => `<div class="stat-chip">
        <div class="stat-val">${val}</div>
        <div class="stat-label">${label}</div>
      </div>`).join('');
      statsEl.style.display = 'flex';

      // Show log download
      const logLink = document.getElementById('download-run-log-link');
      if(logLink) logLink.style.display = 'inline-flex';

    } catch(e) {
      showStatus('run-labeler-status', 'Error: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run Now';
    }
  });

});

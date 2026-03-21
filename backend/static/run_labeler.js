function showStatus(id, msg, type){
  const el = document.getElementById(id);
  if(!el) return;
  el.className = 'status-msg ' + type;
  el.innerHTML = msg;
  el.style.display = msg ? 'block' : 'none';
}

// ── AI Instructions List ───────────────────────────────────
let aiItems = []; // [{id, text}]
let nextId = 1;

function saveItems(){
  return fetch('/api/ai-instructions', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({items: aiItems})
  }).then(r=>r.json());
}

function renderList(){
  const list = document.getElementById('ai-instructions-list');
  if(!list) return;
  if(!aiItems.length){
    list.innerHTML = '<div style="font-size:.82rem;color:var(--txm);padding:.25rem 0">No instructions yet. Add one below.</div>';
    return;
  }
  list.innerHTML = aiItems.map((item, idx) => `
    <div class="d-flex gap-2 align-items-center" data-idx="${idx}" style="background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:7px;padding:.4rem .65rem">
      <i class="bi bi-grip-vertical" style="color:var(--txm);font-size:.85rem"></i>
      <span class="ai-item-text flex-grow-1" style="font-size:.87rem;color:var(--txt);cursor:pointer" data-idx="${idx}" title="Click to edit">${item.text.replace(/</g,'&lt;')}</span>
      <button class="btn btn-sm btn-link p-0 ai-edit-btn" data-idx="${idx}" title="Edit" style="color:var(--txt2)"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-link p-0 ai-del-btn" data-idx="${idx}" title="Delete" style="color:#e57373"><i class="bi bi-trash"></i></button>
    </div>
  `).join('');

  // Edit
  list.querySelectorAll('.ai-edit-btn, .ai-item-text').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.idx);
      const item = aiItems[idx];
      const row = list.querySelector(`[data-idx="${idx}"]`);
      const span = row.querySelector('.ai-item-text');
      const input = document.createElement('input');
      input.className = 'form-control form-control-sm flex-grow-1';
      input.value = item.text;
      input.style.cssText = 'color:var(--txt);background:#252525;border-color:#3a3a3a';
      span.replaceWith(input);
      input.focus();
      input.select();
      const save = async () => {
        const newText = input.value.trim();
        if(newText) { aiItems[idx].text = newText; await saveItems(); }
        renderList();
      };
      input.addEventListener('blur', save);
      input.addEventListener('keydown', e => { if(e.key==='Enter') save(); if(e.key==='Escape') renderList(); });
    });
  });

  // Delete
  list.querySelectorAll('.ai-del-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.idx);
      aiItems.splice(idx, 1);
      await saveItems();
      renderList();
      showStatus('ai-instructions-status', 'Deleted.', 'info');
      setTimeout(()=>showStatus('ai-instructions-status','',''),2000);
    });
  });
}

async function loadAiInstructions(){
  try {
    const res = await fetch('/api/ai-instructions', {credentials:'same-origin'});
    const data = await res.json();
    aiItems = data.items || [];
    nextId = aiItems.length ? Math.max(...aiItems.map(i=>i.id||0)) + 1 : 1;
    renderList();
  } catch(e) { console.error('Failed to load AI instructions', e); }
}

document.addEventListener('DOMContentLoaded', async () => {

  await loadAiInstructions();

  // Add new instruction
  const addBtn = document.getElementById('add-instruction-btn');
  const input = document.getElementById('new-instruction-input');

  const addItem = async () => {
    const text = input?.value.trim();
    if(!text) return;
    aiItems.push({id: nextId++, text});
    input.value = '';
    try {
      await saveItems();
      renderList();
      showStatus('ai-instructions-status', '✓ Saved', 'success');
      setTimeout(()=>showStatus('ai-instructions-status','',''),2000);
    } catch(e) { showStatus('ai-instructions-status', 'Error: '+e.message, 'error'); }
  };

  addBtn?.addEventListener('click', addItem);
  input?.addEventListener('keydown', e => { if(e.key==='Enter') addItem(); });

  // ── Init Default Labels ──────────────────────────────────
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

  // ── Run Labeler ──────────────────────────────────────────
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
      const statsEl = document.getElementById('run-stats');
      statsEl.innerHTML = [
        ['Processed', d.processed], ['Rule Labeled', d.rule_labeled],
        ['AI Labeled', d.ai_labeled], ['Skipped', d.processed - d.rule_labeled - d.ai_labeled]
      ].map(([label, val]) => `<div class="stat-chip"><div class="stat-val">${val}</div><div class="stat-label">${label}</div></div>`).join('');
      statsEl.style.display = 'flex';
      document.getElementById('download-run-log-link').style.display = 'inline-flex';
    } catch(e) {
      showStatus('run-labeler-status', 'Error: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run Now';
    }
  });

});

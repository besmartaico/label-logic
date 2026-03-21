function showStatus(id, msg, type){
  const el = document.getElementById(id);
  if(!el) return;
  el.className = 'status-msg ' + type;
  el.innerHTML = msg;
  el.style.display = msg ? 'block' : 'none';
}

function fmt(d){ return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); }
function fmtFull(d){ return d.toLocaleDateString([], {month:'short', day:'numeric'}) + ' ' + fmt(d); }

let rlTimer = null;
let lrTimer = null;
let rlNextAt = null;
let lrNextAt = null;
let countdownInterval = null;

function updateCountdowns(){
  const now = new Date();
  if(rlNextAt){
    const diff = Math.max(0, rlNextAt - now);
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    const el = document.getElementById('rl-next-run');
    if(el) el.textContent = diff > 0
      ? 'Next run in ' + (mins > 0 ? mins + 'm ' : '') + secs + 's'
      : 'Running...';
  }
  if(lrNextAt){
    const diff = Math.max(0, lrNextAt - now);
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    const el = document.getElementById('lr-next-run');
    if(el) el.textContent = diff > 0
      ? 'Next run in ' + (mins > 0 ? mins + 'm ' : '') + secs + 's'
      : 'Running...';
  }
}

async function runLabeler(){
  try{
    const res = await fetch('/run-labeler', {method:'POST', credentials:'same-origin'});
    const text = await res.text();
    if(text.trim().startsWith('<')) return;
    const d = JSON.parse(text);
    const now = new Date();
    const el = document.getElementById('rl-last-run');
    if(el) el.textContent = 'Last run: ' + fmtFull(now) + ' — Processed: ' + (d.processed||0) + ', Labeled: ' + ((d.rule_labeled||0)+(d.ai_labeled||0));
  }catch(e){ console.error('Scheduled run-labeler failed', e); }
}

async function runLearnRules(){
  try{
    const res = await fetch('/learn-rules', {method:'POST', credentials:'same-origin'});
    const text = await res.text();
    if(text.trim().startsWith('<')) return;
    const d = JSON.parse(text);
    const now = new Date();
    const el = document.getElementById('lr-last-run');
    if(el) el.textContent = 'Last run: ' + fmtFull(now) + ' — Created: ' + (d.created||0) + ' rule(s)';
  }catch(e){ console.error('Scheduled learn-rules failed', e); }
}

function scheduleRL(intervalMs){
  clearInterval(rlTimer);
  rlNextAt = new Date(Date.now() + intervalMs);
  rlTimer = setInterval(async () => {
    rlNextAt = new Date(Date.now() + intervalMs);
    await runLabeler();
  }, intervalMs);
}

function scheduleLR(intervalMs){
  clearInterval(lrTimer);
  lrNextAt = new Date(Date.now() + intervalMs);
  lrTimer = setInterval(async () => {
    lrNextAt = new Date(Date.now() + intervalMs);
    await runLearnRules();
  }, intervalMs);
}

function stopRL(){
  clearInterval(rlTimer); rlTimer = null; rlNextAt = null;
  const el = document.getElementById('rl-next-run');
  if(el) el.textContent = 'Not scheduled';
}

function stopLR(){
  clearInterval(lrTimer); lrTimer = null; lrNextAt = null;
  const el = document.getElementById('lr-next-run');
  if(el) el.textContent = 'Not scheduled';
}

async function loadSchedule(){
  try{
    const res = await fetch('/api/schedule', {credentials:'same-origin'});
    const cfg = await res.json();

    const rlEnabled = document.getElementById('rl-enabled');
    const rlInterval = document.getElementById('rl-interval');
    const lrEnabled = document.getElementById('lr-enabled');
    const lrInterval = document.getElementById('lr-interval');

    if(rlEnabled) rlEnabled.checked = cfg.run_labeler?.enabled || false;
    if(rlInterval) rlInterval.value = cfg.run_labeler?.interval_minutes || 60;
    if(lrEnabled) lrEnabled.checked = cfg.learn_rules?.enabled || false;
    if(lrInterval) lrInterval.value = cfg.learn_rules?.interval_minutes || 1440;

    // Start timers if enabled
    if(cfg.run_labeler?.enabled){
      scheduleRL((cfg.run_labeler.interval_minutes || 60) * 60000);
    }
    if(cfg.learn_rules?.enabled){
      scheduleLR((cfg.learn_rules.interval_minutes || 1440) * 60000);
    }
  }catch(e){ console.error('Failed to load schedule', e); }
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadSchedule();

  // Live countdown
  countdownInterval = setInterval(updateCountdowns, 1000);

  // Toggle Run Labeler
  document.getElementById('rl-enabled')?.addEventListener('change', (e) => {
    if(e.target.checked){
      const mins = parseInt(document.getElementById('rl-interval').value) || 60;
      scheduleRL(mins * 60000);
    } else {
      stopRL();
    }
  });

  // Change RL interval
  document.getElementById('rl-interval')?.addEventListener('change', () => {
    if(document.getElementById('rl-enabled')?.checked){
      const mins = parseInt(document.getElementById('rl-interval').value) || 60;
      scheduleRL(mins * 60000);
    }
  });

  // Toggle Learn Rules
  document.getElementById('lr-enabled')?.addEventListener('change', (e) => {
    if(e.target.checked){
      const mins = parseInt(document.getElementById('lr-interval').value) || 1440;
      scheduleLR(mins * 60000);
    } else {
      stopLR();
    }
  });

  // Change LR interval
  document.getElementById('lr-interval')?.addEventListener('change', () => {
    if(document.getElementById('lr-enabled')?.checked){
      const mins = parseInt(document.getElementById('lr-interval').value) || 1440;
      scheduleLR(mins * 60000);
    }
  });

  // Save button
  document.getElementById('save-schedule-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('save-schedule-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-1"></span>Saving...';
    const cfg = {
      run_labeler: {
        enabled: document.getElementById('rl-enabled')?.checked || false,
        interval_minutes: parseInt(document.getElementById('rl-interval')?.value) || 60
      },
      learn_rules: {
        enabled: document.getElementById('lr-enabled')?.checked || false,
        interval_minutes: parseInt(document.getElementById('lr-interval')?.value) || 1440
      }
    };
    try{
      const res = await fetch('/api/schedule', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(cfg)
      });
      const d = await res.json();
      if(d.error) throw new Error(d.error);
      showStatus('schedule-status', '✓ Schedule saved. Keep this page open for automatic runs.', 'success');
      setTimeout(()=>showStatus('schedule-status','',''), 5000);
    }catch(e){
      showStatus('schedule-status', 'Error: ' + e.message, 'error');
    }finally{
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-floppy me-1"></i>Save Schedule';
    }
  });

  // Cleanup on unload
  window.addEventListener('beforeunload', () => {
    clearInterval(rlTimer);
    clearInterval(lrTimer);
    clearInterval(countdownInterval);
  });
});

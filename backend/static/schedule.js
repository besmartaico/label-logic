function showStatus(id, msg, type){
  const el = document.getElementById(id);
  if(!el) return;
  el.className = 'status-msg ' + type;
  el.innerHTML = msg;
  el.style.display = msg ? 'block' : 'none';
}

function fmtFull(iso){
  if(!iso) return 'Never';
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
  return d.toLocaleDateString([], {month:'short', day:'numeric', year:'numeric'}) + ' ' +
         d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}

let rlTimer = null, lrTimer = null, rlNextAt = null, lrNextAt = null, countdownInterval = null;

function updateCountdowns(){
  const now = new Date();
  if(rlNextAt){
    const diff = Math.max(0, rlNextAt - now);
    const mins = Math.floor(diff/60000), secs = Math.floor((diff%60000)/1000);
    const el = document.getElementById('rl-next-run');
    if(el) el.textContent = diff > 0 ? 'Next run in ' + (mins>0?mins+'m ':'')+secs+'s' : 'Running...';
  }
  if(lrNextAt){
    const diff = Math.max(0, lrNextAt - now);
    const mins = Math.floor(diff/60000), secs = Math.floor((diff%60000)/1000);
    const el = document.getElementById('lr-next-run');
    if(el) el.textContent = diff > 0 ? 'Next run in ' + (mins>0?mins+'m ':'')+secs+'s' : 'Running...';
  }
}

function renderLastRun(type, data){
  const elId = type === 'run_labeler' ? 'rl-last-run' : 'lr-last-run';
  const el = document.getElementById(elId);
  if(!el || !data) return;
  if(type === 'run_labeler'){
    const skipped = (data.processed||0) - (data.rule_labeled||0) - (data.ai_labeled||0);
    el.innerHTML =
      '<div style="margin-top:.6rem;padding:.6rem .75rem;background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:7px">' +
      '<div style="font-size:.78rem;color:var(--txm);margin-bottom:.4rem">Last scheduled run: <strong style="color:var(--txt2)">' + fmtFull(data.ran_at) + '</strong></div>' +
      '<div class="d-flex gap-3 flex-wrap">' +
      '<div class="stat-chip" style="padding:.3rem .6rem"><div class="stat-val" style="font-size:1.1rem">' + (data.processed||0) + '</div><div class="stat-label">Processed</div></div>' +
      '<div class="stat-chip" style="padding:.3rem .6rem"><div class="stat-val" style="font-size:1.1rem">' + (data.rule_labeled||0) + '</div><div class="stat-label">Rule Labeled</div></div>' +
      '<div class="stat-chip" style="padding:.3rem .6rem"><div class="stat-val" style="font-size:1.1rem">' + (data.ai_labeled||0) + '</div><div class="stat-label">AI Labeled</div></div>' +
      '<div class="stat-chip" style="padding:.3rem .6rem"><div class="stat-val" style="font-size:1.1rem">' + Math.max(0,skipped) + '</div><div class="stat-label">Skipped</div></div>' +
      '</div></div>';
  } else {
    el.innerHTML =
      '<div style="margin-top:.6rem;padding:.6rem .75rem;background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:7px">' +
      '<div style="font-size:.78rem;color:var(--txm);margin-bottom:.4rem">Last scheduled run: <strong style="color:var(--txt2)">' + fmtFull(data.ran_at) + '</strong></div>' +
      '<div style="font-size:.85rem;color:var(--txt2)">Rules created: <strong>' + (data.rules_created||0) + '</strong></div>' +
      '</div>';
  }
}

async function saveRunResult(type, data){
  try{
    await fetch('/api/schedule-runs', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({run_type: type, ...data})
    });
  } catch(e){ console.error('Failed to save schedule run', e); }
}

async function loadLastRuns(){
  try{
    const res = await fetch('/api/schedule-runs', {credentials:'same-origin'});
    const data = await res.json();
    if(data.run_labeler) renderLastRun('run_labeler', data.run_labeler);
    if(data.learn_rules) renderLastRun('learn_rules', data.learn_rules);
  } catch(e){ console.error('Failed to load schedule runs', e); }
}

async function runLabeler(){
  try{
    const res = await fetch('/run-labeler', {method:'POST', credentials:'same-origin'});
    const text = await res.text();
    if(text.trim().startsWith('<')) return;
    const d = JSON.parse(text);
    const result = {
      processed: d.processed||0,
      rule_labeled: d.rule_labeled||0,
      ai_labeled: d.ai_labeled||0,
      skipped: Math.max(0,(d.processed||0)-(d.rule_labeled||0)-(d.ai_labeled||0))
    };
    await saveRunResult('run_labeler', result);
    renderLastRun('run_labeler', result);
  } catch(e){ console.error('Scheduled run-labeler failed', e); }
}

async function runLearnRules(){
  try{
    const res = await fetch('/learn-rules', {method:'POST', credentials:'same-origin'});
    const text = await res.text();
    if(text.trim().startsWith('<')) return;
    const d = JSON.parse(text);
    const result = { rules_created: d.created||0 };
    await saveRunResult('learn_rules', result);
    renderLastRun('learn_rules', result);
  } catch(e){ console.error('Scheduled learn-rules failed', e); }
}

function scheduleRL(intervalMs){
  clearInterval(rlTimer);
  rlNextAt = new Date(Date.now() + intervalMs);
  rlTimer = setInterval(async () => { rlNextAt = new Date(Date.now() + intervalMs); await runLabeler(); }, intervalMs);
}
function scheduleLR(intervalMs){
  clearInterval(lrTimer);
  lrNextAt = new Date(Date.now() + intervalMs);
  lrTimer = setInterval(async () => { lrNextAt = new Date(Date.now() + intervalMs); await runLearnRules(); }, intervalMs);
}
function stopRL(){ clearInterval(rlTimer); rlTimer=null; rlNextAt=null; const el=document.getElementById('rl-next-run'); if(el) el.textContent='Not scheduled'; }
function stopLR(){ clearInterval(lrTimer); lrTimer=null; lrNextAt=null; const el=document.getElementById('lr-next-run'); if(el) el.textContent='Not scheduled'; }

async function loadSchedule(){
  try{
    const res = await fetch('/api/schedule', {credentials:'same-origin'});
    const cfg = await res.json();
    const rlEnabled = document.getElementById('rl-enabled');
    const rlInterval = document.getElementById('rl-interval');
    const lrEnabled = document.getElementById('lr-enabled');
    const lrInterval = document.getElementById('lr-interval');
    if(rlEnabled) rlEnabled.checked = cfg.run_labeler?.enabled || false;
    if(rlInterval) rlInterval.value = cfg.run_labeler?.interval_minutes || 480;
    if(lrEnabled) lrEnabled.checked = cfg.learn_rules?.enabled || false;
    if(lrInterval) lrInterval.value = cfg.learn_rules?.interval_minutes || 1440;
    if(cfg.run_labeler?.enabled) scheduleRL((cfg.run_labeler.interval_minutes||480)*60000);
    if(cfg.learn_rules?.enabled) scheduleLR((cfg.learn_rules.interval_minutes||1440)*60000);
  } catch(e){ console.error('Failed to load schedule', e); }
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadSchedule();
  await loadLastRuns();
  countdownInterval = setInterval(updateCountdowns, 1000);

  document.getElementById('rl-enabled')?.addEventListener('change', e => {
    if(e.target.checked){ const m=parseInt(document.getElementById('rl-interval').value)||480; scheduleRL(m*60000); }
    else stopRL();
  });
  document.getElementById('rl-interval')?.addEventListener('change', () => {
    if(document.getElementById('rl-enabled')?.checked){ const m=parseInt(document.getElementById('rl-interval').value)||480; scheduleRL(m*60000); }
  });
  document.getElementById('lr-enabled')?.addEventListener('change', e => {
    if(e.target.checked){ const m=parseInt(document.getElementById('lr-interval').value)||1440; scheduleLR(m*60000); }
    else stopLR();
  });
  document.getElementById('lr-interval')?.addEventListener('change', () => {
    if(document.getElementById('lr-enabled')?.checked){ const m=parseInt(document.getElementById('lr-interval').value)||1440; scheduleLR(m*60000); }
  });

  document.getElementById('save-schedule-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('save-schedule-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-1"></span>Saving...';
    const cfg = {
      run_labeler: { enabled: document.getElementById('rl-enabled')?.checked||false, interval_minutes: parseInt(document.getElementById('rl-interval')?.value)||480 },
      learn_rules:  { enabled: document.getElementById('lr-enabled')?.checked||false,  interval_minutes: parseInt(document.getElementById('lr-interval')?.value)||1440 }
    };
    try{
      const res = await fetch('/api/schedule', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});
      const d = await res.json();
      if(d.error) throw new Error(d.error);
      showStatus('schedule-status', '\u2713 Schedule saved. Keep this page open for automatic runs.', 'success');
      setTimeout(()=>showStatus('schedule-status','',''),5000);
    } catch(e){
      showStatus('schedule-status','Error: '+e.message,'error');
    } finally{
      btn.disabled=false;
      btn.innerHTML='<i class="bi bi-floppy me-1"></i>Save Schedule';
    }
  });

  window.addEventListener('beforeunload', () => {
    clearInterval(rlTimer); clearInterval(lrTimer); clearInterval(countdownInterval);
  });
});

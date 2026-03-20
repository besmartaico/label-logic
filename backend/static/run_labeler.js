function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('init-default-labels-btn')?.addEventListener('click',async()=>{
    showStatus('init-labels-status','Initializing…','info');
    try{const d=await fetch('/init-default-labels',{method:'POST'}).then(r=>r.json());showStatus('init-labels-status',`✓ Ensured ${d.count} labels.`,'success');}
    catch(e){showStatus('init-labels-status','Error: '+e.message,'error');}
  });
  const btn=document.getElementById('run-labeler-btn');
  btn?.addEventListener('click',async()=>{
    btn.disabled=true;btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Running…';
    showStatus('run-labeler-status','Scanning your inbox…','info');
    document.getElementById('run-stats').style.display='none';
    try{
      const res=await fetch('/run-labeler',{method:'POST'});
      const d=await res.json();
      if(!res.ok||d.error)throw new Error(d.error||res.statusText);
      showStatus('run-labeler-status','✓ Run complete.','success');
      const s=document.getElementById('run-stats');s.style.display='flex';
      s.innerHTML=`<div class="stat-chip"><div class="stat-val">${d.processed}</div><div class="stat-label">Processed</div></div>
        <div class="stat-chip"><div class="stat-val" style="color:#58d68d">${d.rule_labeled}</div><div class="stat-label">Rule Labeled</div></div>
        <div class="stat-chip"><div class="stat-val" style="color:#5dade2">${d.ai_labeled}</div><div class="stat-label">AI Labeled</div></div>
        <div class="stat-chip"><div class="stat-val" style="color:#666">${d.processed-d.rule_labeled-d.ai_labeled}</div><div class="stat-label">Skipped</div></div>`;
      const l=document.getElementById('download-run-log-link');if(l)l.style.display='inline-flex';
    }catch(e){showStatus('run-labeler-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-play-fill me-1"></i>Run Now';}
  });
});

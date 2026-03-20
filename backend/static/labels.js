function escH(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
let allLabels=[];
function renderLabels(labels){
  const tbody=document.getElementById('labels-table-body');
  if(!labels.length){tbody.innerHTML='<tr><td colspan="4" class="text-center py-4" style="color:var(--txm)">No labels found.</td></tr>';return;}
  tbody.innerHTML=labels.map(l=>{const u=l.messagesUnread||0,t=l.messagesTotal||0;
    return `<tr><td><i class="bi bi-tag me-2" style="color:var(--marb)"></i>${escH(l.name)}</td>
    <td class="text-end">${u>0?`<span class="badge-unread">${u}</span>`:'<span style="color:var(--txm)">—</span>'}</td>
    <td class="text-end"><span class="badge-total">${t}</span></td>
    <td class="text-end">${u>0?`<button class="btn btn-sm btn-outline-secondary" data-markread="${escH(l.id)}"><i class="bi bi-check2-all me-1"></i>Mark Read</button>`:''}</td></tr>`;
  }).join('');
  tbody.querySelectorAll('[data-markread]').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      if(!confirm('Mark all unread in this label as read?'))return;
      const id=btn.getAttribute('data-markread');
      showStatus('labels-status','Marking…','info');
      try{const d=await fetch(`/api/labels/${id}/mark-read`,{method:'POST'}).then(r=>r.json());showStatus('labels-status',d.message||'Done.','success');await loadLabels();}
      catch(e){showStatus('labels-status','Error: '+e.message,'error');}
    });
  });
}
async function loadLabels(){
  document.getElementById('labels-table-body').innerHTML='<tr><td colspan="4" class="text-center py-3" style="color:var(--txm)"><div class="spinner-border spinner-sm text-secondary me-2"></div>Loading…</td></tr>';
  try{
    allLabels=await fetch('/api/labels').then(r=>r.json());
    document.getElementById('total-labels-count').textContent=allLabels.length;
    document.getElementById('total-unread-count').textContent=allLabels.reduce((s,l)=>s+(l.messagesUnread||0),0);
    const q=(document.getElementById('label-search')?.value||'').toLowerCase();
    renderLabels(q?allLabels.filter(l=>l.name.toLowerCase().includes(q)):allLabels);
  }catch(e){document.getElementById('labels-table-body').innerHTML=`<tr><td colspan="4" class="text-center py-3" style="color:#e57373">Failed: ${e.message}</td></tr>`;}
}
document.addEventListener('DOMContentLoaded',async()=>{
  await loadLabels();
  document.getElementById('refresh-labels-btn')?.addEventListener('click',loadLabels);
  document.getElementById('label-search')?.addEventListener('input',e=>{const q=e.target.value.toLowerCase();renderLabels(q?allLabels.filter(l=>l.name.toLowerCase().includes(q)):allLabels);});
  document.getElementById('init-default-labels-btn')?.addEventListener('click',async()=>{
    showStatus('init-labels-status','Initializing…','info');
    try{const d=await fetch('/init-default-labels',{method:'POST'}).then(r=>r.json());showStatus('init-labels-status',`✓ Ensured ${d.count} labels.`,'success');await loadLabels();}
    catch(e){showStatus('init-labels-status','Error: '+e.message,'error');}
  });
});

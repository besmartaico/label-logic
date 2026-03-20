function escH(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
function pill(t){if(!t)return'<span style="color:var(--txm)">—</span>';return'<span style="background:rgba(255,255,255,.07);border:1px solid #3a3a3a;border-radius:4px;padding:2px 7px;font-size:.78rem">'+escH(t)+'</span>';}
let allRules=[];
function renderRules(rules){
  const c=document.getElementById('rules-container');
  if(!rules.length){c.innerHTML='<div class="text-center py-5" style="color:var(--txm)"><i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:.5rem"></i>No rules found.</div>';return;}
  const groups={};
  rules.forEach(r=>{const k=r.label_name||'Unlabeled';if(!groups[k])groups[k]=[];groups[k].push(r);});
  c.innerHTML=Object.entries(groups).map(([label,rs])=>`
    <div class="mb-4">
      <div class="rule-group-header"><i class="bi bi-tag-fill"></i>${escH(label)}<span style="margin-left:auto;font-size:.78rem;color:var(--txm)">${rs.length} rule${rs.length!==1?'s':''}</span></div>
      <div class="card"><div class="card-body p-0"><div class="table-responsive">
        <table class="table mb-0">
          <thead><tr><th style="width:40px">#</th><th>From</th><th>Subject</th><th>Body</th><th style="width:80px">Status</th><th style="width:80px">Mark Read</th><th class="text-end" style="width:120px">Actions</th></tr></thead>
          <tbody>
            ${rs.map(r=>`<tr style="${r.is_active?'':'opacity:.45'}">
              <td style="color:var(--txm);font-size:.78rem">${r.id}</td>
              <td>${pill(r.from_contains)}</td><td>${pill(r.subject_contains)}</td><td>${pill(r.body_contains)}</td>
              <td>${r.is_active?'<span style="color:#58d68d;font-size:.8rem"><i class="bi bi-check-circle-fill me-1"></i>Active</span>':'<span style="color:var(--txm);font-size:.8rem"><i class="bi bi-pause-circle me-1"></i>Off</span>'}</td>
              <td>${r.mark_as_read?'<i class="bi bi-check2 text-success"></i>':'<span style="color:var(--txm)">—</span>'}</td>
              <td class="text-end">
                <a href="/rule-editor?edit=${r.id}" class="btn btn-sm btn-outline-primary me-1"><i class="bi bi-pencil"></i></a>
                <button class="btn btn-sm btn-outline-danger" data-del="${r.id}"><i class="bi bi-trash"></i></button>
              </td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div></div></div>
    </div>
  `).join('');
  c.querySelectorAll('[data-del]').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      const id=btn.getAttribute('data-del');
      if(!confirm('Delete rule #'+id+'?'))return;
      try{await fetch('/api/rules/'+id,{method:'DELETE'});await loadRules();}
      catch(e){alert('Delete failed: '+e.message);}
    });
  });
}
function filterAndRender(){
  const q=(document.getElementById('rules-search')?.value||'').toLowerCase();
  const f=document.getElementById('rules-filter')?.value||'all';
  let rules=allRules;
  if(f==='active')rules=rules.filter(r=>r.is_active);
  if(f==='inactive')rules=rules.filter(r=>!r.is_active);
  if(q)rules=rules.filter(r=>(r.label_name||'').toLowerCase().includes(q)||(r.from_contains||'').toLowerCase().includes(q)||(r.subject_contains||'').toLowerCase().includes(q)||(r.body_contains||'').toLowerCase().includes(q));
  renderRules(rules);
}
async function loadRules(){
  try{
    allRules=await fetch('/api/rules').then(r=>r.json());
    document.getElementById('total-rules-count').textContent=allRules.length;
    document.getElementById('active-rules-count').textContent=allRules.filter(r=>r.is_active).length;
    document.getElementById('label-groups-count').textContent=new Set(allRules.map(r=>r.label_name)).size;
    filterAndRender();
  }catch(e){document.getElementById('rules-container').innerHTML='<div class="status-msg error">Failed to load rules: '+e.message+'</div>';}
}
document.addEventListener('DOMContentLoaded',async()=>{
  await loadRules();
  document.getElementById('rules-search')?.addEventListener('input',filterAndRender);
  document.getElementById('rules-filter')?.addEventListener('change',filterAndRender);
  document.getElementById('learn-rules-btn')?.addEventListener('click',async()=>{
    const btn=document.getElementById('learn-rules-btn');
    btn.disabled=true;btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Learning…';
    showStatus('learn-status','Analyzing labeled emails…','info');
    try{const d=await fetch('/learn-rules',{method:'POST'}).then(r=>r.json());showStatus('learn-status','✓ Created '+(d.created||0)+' new rule(s).','success');await loadRules();}
    catch(e){showStatus('learn-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-cpu me-1"></i>Learn Rules from Emails';}
  });
});

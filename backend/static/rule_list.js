function escH(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
function pill(t){if(!t)return'<span style="color:var(--txm)">—</span>';return'<span style="background:rgba(255,255,255,.07);border:1px solid #3a3a3a;border-radius:4px;padding:2px 8px;font-size:.8rem;color:var(--txt)">'+escH(t)+'</span>';}

let allRules=[];

async function patchRule(id,patch){
  const all=await fetch('/api/rules').then(r=>r.json());
  const rule=all.find(x=>String(x.id)===String(id));
  if(!rule)return;
  await fetch('/api/rules/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...rule,...patch})});
}

function renderRules(rules){
  const c=document.getElementById('rules-container');
  if(!rules.length){
    c.innerHTML='<div class="text-center py-5" style="color:var(--txm)"><i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:.5rem"></i>No rules found.</div>';
    return;
  }
  const groups={};
  rules.forEach(r=>{const k=r.label_name||'Unlabeled';if(!groups[k])groups[k]=[];groups[k].push(r);});

  c.innerHTML=Object.entries(groups).map(([label,rs])=>{
    const allActive=rs.every(r=>r.is_active);
    const allRead=rs.every(r=>r.mark_as_read);
    const gid='g-'+btoa(label).replace(/[^a-z0-9]/gi,'');
    return `<div class="mb-4">
      <div class="rule-group-header">
        <i class="bi bi-tag-fill"></i>
        <span style="color:var(--txt)">${escH(label)}</span>
        <span style="margin-left:auto;font-size:.75rem;color:var(--txm)">${rs.length} rule${rs.length!==1?'s':''}</span>
        <div class="d-flex gap-3 ms-3">
          <label class="group-toggle-label" style="cursor:pointer;font-size:.8rem;color:var(--txt2);display:flex;align-items:center;gap:6px">
            <div class="form-check form-switch mb-0">
              <input class="form-check-input group-active-cb" type="checkbox" role="switch" data-gid="${gid}" ${allActive?'checked':''} style="cursor:pointer;margin-top:0">
            </div>
            All Active
          </label>
          <label class="group-toggle-label" style="cursor:pointer;font-size:.8rem;color:var(--txt2);display:flex;align-items:center;gap:6px">
            <div class="form-check form-switch mb-0">
              <input class="form-check-input group-read-cb" type="checkbox" role="switch" data-gid="${gid}" ${allRead?'checked':''} style="cursor:pointer;margin-top:0">
            </div>
            All Mark Read
          </label>
        </div>
      </div>
      <div class="card">
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table mb-0">
              <thead>
                <tr>
                  <th style="width:40px">#</th>
                  <th>From</th><th>Subject</th><th>Body</th>
                  <th style="width:90px;text-align:center">Active</th>
                  <th style="width:100px;text-align:center">Mark Read</th>
                  <th class="text-end" style="width:90px">Actions</th>
                </tr>
              </thead>
              <tbody data-gid="${gid}">
                ${rs.map(r=>`<tr data-id="${r.id}" style="opacity:${r.is_active?1:.45}">
                  <td style="color:var(--txm);font-size:.78rem">${r.id}</td>
                  <td>${pill(r.from_contains)}</td>
                  <td>${pill(r.subject_contains)}</td>
                  <td>${pill(r.body_contains)}</td>
                  <td style="text-align:center">
                    <div class="form-check form-switch d-flex justify-content-center mb-0">
                      <input class="form-check-input rule-active-cb" type="checkbox" role="switch" data-id="${r.id}" ${r.is_active?'checked':''} style="cursor:pointer">
                    </div>
                  </td>
                  <td style="text-align:center">
                    <div class="form-check form-switch d-flex justify-content-center mb-0">
                      <input class="form-check-input rule-read-cb" type="checkbox" role="switch" data-id="${r.id}" ${r.mark_as_read?'checked':''} style="cursor:pointer">
                    </div>
                  </td>
                  <td class="text-end">
                    <a href="/rule-editor?edit=${r.id}" class="btn btn-sm btn-outline-primary me-1" title="Edit"><i class="bi bi-pencil"></i></a>
                    <button class="btn btn-sm btn-outline-danger del-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
                  </td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');

  // Group-level active toggle
  c.querySelectorAll('.group-active-cb').forEach(cb=>{
    cb.addEventListener('change',async()=>{
      const tbody=c.querySelector(`tbody[data-gid="${cb.dataset.gid}"]`);
      const rows=tbody?tbody.querySelectorAll('tr[data-id]'):[];
      for(const row of rows){
        const id=row.dataset.id;
        row.style.opacity=cb.checked?1:.45;
        const ruleCb=row.querySelector('.rule-active-cb');
        if(ruleCb)ruleCb.checked=cb.checked;
        await patchRule(id,{is_active:cb.checked});
      }
      // refresh counts
      const active=allRules.filter(r=>r.is_active).length;
      document.getElementById('active-rules-count').textContent=active;
    });
  });

  // Group-level mark-read toggle
  c.querySelectorAll('.group-read-cb').forEach(cb=>{
    cb.addEventListener('change',async()=>{
      const tbody=c.querySelector(`tbody[data-gid="${cb.dataset.gid}"]`);
      const rows=tbody?tbody.querySelectorAll('tr[data-id]'):[];
      for(const row of rows){
        const id=row.dataset.id;
        const ruleCb=row.querySelector('.rule-read-cb');
        if(ruleCb)ruleCb.checked=cb.checked;
        await patchRule(id,{mark_as_read:cb.checked});
      }
    });
  });

  // Individual active switch
  c.querySelectorAll('.rule-active-cb').forEach(cb=>{
    cb.addEventListener('change',async()=>{
      const row=c.querySelector(`tr[data-id="${cb.dataset.id}"]`);
      if(row)row.style.opacity=cb.checked?1:.45;
      await patchRule(cb.dataset.id,{is_active:cb.checked});
      allRules.forEach(r=>{if(String(r.id)===String(cb.dataset.id))r.is_active=cb.checked;});
      document.getElementById('active-rules-count').textContent=allRules.filter(r=>r.is_active).length;
    });
  });

  // Individual mark-read switch
  c.querySelectorAll('.rule-read-cb').forEach(cb=>{
    cb.addEventListener('change',async()=>{
      await patchRule(cb.dataset.id,{mark_as_read:cb.checked});
    });
  });

  // Delete buttons
  c.querySelectorAll('.del-btn').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      if(!confirm('Delete rule #'+btn.dataset.id+'?'))return;
      try{await fetch('/api/rules/'+btn.dataset.id,{method:'DELETE'});await loadRules();}
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
  if(q)rules=rules.filter(r=>((r.label_name||'')+(r.from_contains||'')+(r.subject_contains||'')+(r.body_contains||'')).toLowerCase().includes(q));
  renderRules(rules);
}

async function loadRules(){
  try{
    allRules=await fetch('/api/rules').then(r=>r.json());
    document.getElementById('total-rules-count').textContent=allRules.length;
    document.getElementById('active-rules-count').textContent=allRules.filter(r=>r.is_active).length;
    document.getElementById('label-groups-count').textContent=new Set(allRules.map(r=>r.label_name)).size;
    filterAndRender();
  }catch(e){
    document.getElementById('rules-container').innerHTML='<div class="status-msg error">Failed to load: '+e.message+'</div>';
  }
}

document.addEventListener('DOMContentLoaded',async()=>{
  await loadRules();
  document.getElementById('rules-search')?.addEventListener('input',filterAndRender);
  document.getElementById('rules-filter')?.addEventListener('change',filterAndRender);
  document.getElementById('learn-rules-btn')?.addEventListener('click',async()=>{
    const btn=document.getElementById('learn-rules-btn');
    btn.disabled=true;
    btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Learning...';
    showStatus('learn-status','Analyzing your labeled emails...','info');
    try{
      const d=await fetch('/learn-rules',{method:'POST'}).then(r=>r.json());
      showStatus('learn-status','Created '+(d.created||0)+' new rule(s) from your labeled emails.','success');
      await loadRules();
    }catch(e){showStatus('learn-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-cpu me-1"></i>Learn Rules';}
  });
});

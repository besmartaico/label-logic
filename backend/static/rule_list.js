function escH(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
function pill(t){if(!t)return'<span style="color:var(--txm)">—</span>';return'<span style="background:rgba(255,255,255,.07);border:1px solid #3a3a3a;border-radius:4px;padding:2px 8px;font-size:.8rem;color:var(--txt)">'+escH(t)+'</span>';}

let allRules=[];
// Track collapsed state per group
const collapsed = {};

async function patchRule(id, patch){
  const all = await fetch('/api/rules').then(r=>r.json());
  const rule = all.find(x=>String(x.id)===String(id));
  if(!rule) return;
  await fetch('/api/rules/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({...rule,...patch})});
}

function setAllCollapsed(state){
  document.querySelectorAll('.group-body').forEach(body=>{
    const gid = body.dataset.gid;
    collapsed[gid] = state;
    body.style.display = state ? 'none' : '';
    const icon = document.querySelector('.collapse-icon[data-gid="'+gid+'"]');
    if(icon) icon.className = 'bi ' + (state ? 'bi-chevron-right' : 'bi-chevron-down') + ' collapse-icon';
    icon?.setAttribute('data-gid', gid);
  });
}

function renderRules(rules){
  const c = document.getElementById('rules-container');
  if(!rules.length){
    c.innerHTML='<div class="text-center py-5" style="color:var(--txm)"><i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:.5rem"></i>No rules found.</div>';
    return;
  }

  const groups={};
  rules.forEach(r=>{const k=r.label_name||'Unlabeled';if(!groups[k])groups[k]=[];groups[k].push(r);});

  // Global expand/collapse bar
  const globalBar = `<div class="d-flex justify-content-end gap-2 mb-3">
    <button class="btn btn-sm btn-outline-secondary" id="expand-all-btn"><i class="bi bi-arrows-expand me-1"></i>Expand All</button>
    <button class="btn btn-sm btn-outline-secondary" id="collapse-all-btn"><i class="bi bi-arrows-collapse me-1"></i>Collapse All</button>
  </div>`;

  c.innerHTML = globalBar + Object.entries(groups).map(([label,rs])=>{
    const allActive = rs.every(r=>r.is_active);
    const allRead = rs.every(r=>r.mark_as_read);
    const gid = 'g' + label.replace(/[^a-z0-9]/gi,'_');
    const isCollapsed = collapsed[gid] || false;
    return `<div class="mb-3">
      <div class="rule-group-header" style="cursor:pointer" data-gid="${gid}">
        <i class="bi ${isCollapsed?'bi-chevron-right':'bi-chevron-down'} collapse-icon me-1" data-gid="${gid}" style="font-size:.85rem;transition:transform .2s"></i>
        <i class="bi bi-tag-fill me-1"></i>
        <span style="color:var(--txt);font-size:.95rem">${escH(label)}</span>
        <span style="margin-left:.5rem;font-size:.72rem;color:var(--txm)">${rs.length} rule${rs.length!==1?'s':''}</span>
        <div class="d-flex gap-2 ms-auto" onclick="event.stopPropagation()">
          <div class="form-check form-switch mb-0" title="Toggle all active">
            <input class="form-check-input group-active-cb" type="checkbox" role="switch" data-gid="${gid}" ${allActive?'checked':''} style="cursor:pointer;margin-top:2px">
          </div>
          <div class="form-check form-switch mb-0" title="Toggle all mark read">
            <input class="form-check-input group-read-cb" type="checkbox" role="switch" data-gid="${gid}" ${allRead?'checked':''} style="cursor:pointer;margin-top:2px">
          </div>
          <a href="/rule-editor" class="btn btn-sm btn-outline-primary py-0 px-2" title="New rule for this label" onclick="event.stopPropagation();window.location='/rule-editor?label=${encodeURIComponent(label)}'"><i class="bi bi-plus"></i></a>
        </div>
      </div>
      <div class="group-body" data-gid="${gid}" style="display:${isCollapsed?'none':''}">
        <div class="card" style="border-top-left-radius:0;border-top-right-radius:0;border-top:none">
          <div class="card-body p-0">
            <div class="table-responsive">
              <table class="table mb-0" style="background:var(--card);color:var(--txt)">
                <thead style="background:var(--cardh)">
                  <tr>
                    <th style="width:40px;color:var(--txt2);background:var(--cardh)">#</th>
                    <th style="color:var(--txt2);background:var(--cardh)">From</th>
                    <th style="color:var(--txt2);background:var(--cardh)">Subject</th>
                    <th style="color:var(--txt2);background:var(--cardh)">Body</th>
                    <th style="width:60px;text-align:center;color:var(--txt2);background:var(--cardh)" title="Active"><i class="bi bi-toggle-on"></i></th>
                    <th style="width:60px;text-align:center;color:var(--txt2);background:var(--cardh)" title="Mark Read"><i class="bi bi-envelope-open"></i></th>
                    <th style="width:80px;text-align:right;color:var(--txt2);background:var(--cardh)">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${rs.map(r=>`<tr data-id="${r.id}" style="background:var(--card);opacity:${r.is_active?1:.45}">
                    <td style="color:var(--txm);font-size:.78rem;border-color:#2a2a2a">${r.id}</td>
                    <td style="border-color:#2a2a2a">${pill(r.from_contains)}</td>
                    <td style="border-color:#2a2a2a">${pill(r.subject_contains)}</td>
                    <td style="border-color:#2a2a2a">${pill(r.body_contains)}</td>
                    <td style="text-align:center;border-color:#2a2a2a">
                      <div class="form-check form-switch d-flex justify-content-center mb-0">
                        <input class="form-check-input rule-active-cb" type="checkbox" role="switch" data-id="${r.id}" ${r.is_active?'checked':''} style="cursor:pointer">
                      </div>
                    </td>
                    <td style="text-align:center;border-color:#2a2a2a">
                      <div class="form-check form-switch d-flex justify-content-center mb-0">
                        <input class="form-check-input rule-read-cb" type="checkbox" role="switch" data-id="${r.id}" ${r.mark_as_read?'checked':''} style="cursor:pointer">
                      </div>
                    </td>
                    <td style="text-align:right;border-color:#2a2a2a">
                      <a href="/rule-editor?edit=${r.id}" class="btn btn-sm btn-outline-primary me-1" title="Edit"><i class="bi bi-pencil"></i></a>
                      <button class="btn btn-sm btn-outline-danger del-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
                    </td>
                  </tr>`).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');

  // Global expand/collapse
  c.querySelector('#expand-all-btn')?.addEventListener('click', ()=>setAllCollapsed(false));
  c.querySelector('#collapse-all-btn')?.addEventListener('click', ()=>setAllCollapsed(true));

  // Group header click to toggle collapse
  c.querySelectorAll('.rule-group-header').forEach(hdr=>{
    hdr.addEventListener('click', ()=>{
      const gid = hdr.dataset.gid;
      const body = c.querySelector('.group-body[data-gid="'+gid+'"]');
      const icon = hdr.querySelector('.collapse-icon');
      collapsed[gid] = !collapsed[gid];
      body.style.display = collapsed[gid] ? 'none' : '';
      if(icon){
        icon.className = 'bi ' + (collapsed[gid]?'bi-chevron-right':'bi-chevron-down') + ' collapse-icon me-1';
      }
    });
  });

  // Group active toggle
  c.querySelectorAll('.group-active-cb').forEach(cb=>{
    cb.addEventListener('change', async()=>{
      const gid = cb.dataset.gid;
      const rows = c.querySelectorAll('tr[data-id]');
      // Find rows in this group's table
      const groupBody = c.querySelector('.group-body[data-gid="'+gid+'"]');
      if(!groupBody) return;
      const groupRows = groupBody.querySelectorAll('tr[data-id]');
      for(const row of groupRows){
        const id = row.dataset.id;
        row.style.opacity = cb.checked ? 1 : .45;
        const ruleCb = row.querySelector('.rule-active-cb');
        if(ruleCb) ruleCb.checked = cb.checked;
        await patchRule(id, {is_active: cb.checked});
        allRules.forEach(r=>{if(String(r.id)===String(id))r.is_active=cb.checked;});
      }
      document.getElementById('active-rules-count').textContent = allRules.filter(r=>r.is_active).length;
    });
  });

  // Group read toggle
  c.querySelectorAll('.group-read-cb').forEach(cb=>{
    cb.addEventListener('change', async()=>{
      const gid = cb.dataset.gid;
      const groupBody = c.querySelector('.group-body[data-gid="'+gid+'"]');
      if(!groupBody) return;
      const groupRows = groupBody.querySelectorAll('tr[data-id]');
      for(const row of groupRows){
        const id = row.dataset.id;
        const ruleCb = row.querySelector('.rule-read-cb');
        if(ruleCb) ruleCb.checked = cb.checked;
        await patchRule(id, {mark_as_read: cb.checked});
      }
    });
  });

  // Individual active switch
  c.querySelectorAll('.rule-active-cb').forEach(cb=>{
    cb.addEventListener('change', async()=>{
      const row = c.querySelector('tr[data-id="'+cb.dataset.id+'"]');
      if(row) row.style.opacity = cb.checked ? 1 : .45;
      await patchRule(cb.dataset.id, {is_active: cb.checked});
      allRules.forEach(r=>{if(String(r.id)===String(cb.dataset.id))r.is_active=cb.checked;});
      document.getElementById('active-rules-count').textContent = allRules.filter(r=>r.is_active).length;
    });
  });

  // Individual mark-read switch
  c.querySelectorAll('.rule-read-cb').forEach(cb=>{
    cb.addEventListener('change', async()=>{
      await patchRule(cb.dataset.id, {mark_as_read: cb.checked});
    });
  });

  // Delete
  c.querySelectorAll('.del-btn').forEach(btn=>{
    btn.addEventListener('click', async()=>{
      if(!confirm('Delete rule #'+btn.dataset.id+'?')) return;
      try{ await fetch('/api/rules/'+btn.dataset.id,{method:'DELETE'}); await loadRules(); }
      catch(e){ alert('Delete failed: '+e.message); }
    });
  });
}

function filterAndRender(){
  const q = (document.getElementById('rules-search')?.value||'').toLowerCase();
  const f = document.getElementById('rules-filter')?.value||'all';
  let rules = allRules;
  if(f==='active') rules=rules.filter(r=>r.is_active);
  if(f==='inactive') rules=rules.filter(r=>!r.is_active);
  if(q) rules=rules.filter(r=>((r.label_name||'')+(r.from_contains||'')+(r.subject_contains||'')+(r.body_contains||'')).toLowerCase().includes(q));
  renderRules(rules);
}

async function loadRules(){
  try{
    allRules = await fetch('/api/rules').then(r=>r.json());
    document.getElementById('total-rules-count').textContent = allRules.length;
    document.getElementById('active-rules-count').textContent = allRules.filter(r=>r.is_active).length;
    document.getElementById('label-groups-count').textContent = new Set(allRules.map(r=>r.label_name)).size;
    filterAndRender();
  }catch(e){
    document.getElementById('rules-container').innerHTML='<div class="status-msg error">Failed to load: '+e.message+'</div>';
  }
}

document.addEventListener('DOMContentLoaded', async()=>{
  await loadRules();
  document.getElementById('rules-search')?.addEventListener('input', filterAndRender);
  document.getElementById('rules-filter')?.addEventListener('change', filterAndRender);
  document.getElementById('learn-rules-btn')?.addEventListener('click', async()=>{
    const btn = document.getElementById('learn-rules-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-2"></span>Learning...';
    showStatus('learn-status','Scanning your labeled emails for patterns...','info');
    try{
      const d = await fetch('/learn-rules',{method:'POST'}).then(r=>r.json());
      if(d.error) throw new Error(d.error);
      showStatus('learn-status','✓ Created '+(d.created||0)+' new rule(s) from your labeled emails.','success');
      await loadRules();
    }catch(e){showStatus('learn-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-cpu me-1"></i>Learn Rules';}
  });
});

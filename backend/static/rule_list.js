function escH(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
function pill(t){if(!t)return'<span style="color:var(--txm)">—</span>';return'<span style="background:rgba(255,255,255,.07);border:1px solid #3a3a3a;border-radius:4px;padding:2px 8px;font-size:.8rem;color:var(--txt)">'+escH(t)+'</span>';}
function sw(id,checked,cls){return'<div class="form-check form-switch d-flex justify-content-center mb-0"><input class="form-check-input '+cls+'" type="checkbox" role="switch" data-id="'+id+'" '+(checked?'checked':'')+'  style="cursor:pointer"></div>';}

let allRules=[];
// Default ALL groups collapsed on load
const collapsed={};
// Track pending changes {id: {field:val,...}}
const pendingChanges={};

async function saveAllChanges(){
  const btn=document.getElementById('save-changes-btn');
  if(!Object.keys(pendingChanges).length){showStatus('learn-status','No changes to save.','info');return;}
  btn.disabled=true;btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Saving...';
  try{
    const all=await fetch('/api/rules',{credentials:'same-origin'}).then(r=>r.json());
    let saved=0;
    for(const[id,patch]of Object.entries(pendingChanges)){
      const rule=all.find(x=>String(x.id)===String(id));
      if(!rule)continue;
      await fetch('/api/rules/'+id,{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({...rule,...patch})});
      saved++;
    }
    Object.keys(pendingChanges).forEach(k=>delete pendingChanges[k]);
    showStatus('learn-status',`✓ Saved ${saved} rule(s).`,'success');
    await loadRules();
  }catch(e){showStatus('learn-status','Save failed: '+e.message,'error');}
  finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-floppy me-1"></i>Save Changes';}
}

function markPending(id,field,val){
  if(!pendingChanges[id])pendingChanges[id]={};
  pendingChanges[id][field]=val;
  const saveBtn=document.getElementById('save-changes-btn');
  if(saveBtn){saveBtn.classList.remove('btn-outline-secondary');saveBtn.classList.add('btn-warning');saveBtn.style.color='#000';}
}

function setAllCollapsed(state){
  document.querySelectorAll('.group-body').forEach(body=>{
    const gid=body.dataset.gid;
    collapsed[gid]=state;
    body.style.display=state?'none':'';
    const icon=document.querySelector(`.collapse-icon[data-gid="${gid}"]`);
    if(icon)icon.className='bi '+(state?'bi-chevron-right':'bi-chevron-down')+' collapse-icon me-1';
  });
}

function renderRules(rules){
  if(typeof selectedIds !== "undefined") selectedIds.clear();

  const c=document.getElementById('rules-container');
  if(!rules.length){c.innerHTML='<div class="text-center py-5" style="color:var(--txm)"><i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:.5rem"></i>No rules found.</div>';return;}
  const groups={};
  rules.forEach(r=>{const k=r.label_name||'Unlabeled';if(!groups[k])groups[k]=[];groups[k].push(r);});

  const globalBar=`<div class="d-flex justify-content-between align-items-center gap-2 mb-3">
    <div class="d-flex gap-2">
      <button class="btn btn-sm btn-outline-secondary" id="expand-all-btn"><i class="bi bi-arrows-expand me-1"></i>Expand All</button>
      <button class="btn btn-sm btn-outline-secondary" id="collapse-all-btn"><i class="bi bi-arrows-collapse me-1"></i>Collapse All</button>
    </div>
    <button class="btn btn-sm btn-outline-secondary" id="save-changes-btn"><i class="bi bi-floppy me-1"></i>Save Changes</button>
  </div>`;

  c.innerHTML=globalBar+Object.entries(groups).map(([label,rs])=>{
    const allActive=rs.every(r=>r.is_active);
    const allRead=rs.every(r=>r.mark_as_read);
    const gid='g'+label.replace(/[^a-z0-9]/gi,'_');
    // Default collapsed unless explicitly expanded
    const isCollapsed=collapsed[gid]!==false;
    if(collapsed[gid]===undefined)collapsed[gid]=true;
    return `<div class="mb-3">
      <div class="rule-group-header d-flex align-items-center gap-2" style="cursor:pointer" data-gid="${gid}">
        <i class="bi ${isCollapsed?'bi-chevron-right':'bi-chevron-down'} collapse-icon me-1" data-gid="${gid}" style="font-size:.85rem"></i>
        <i class="bi bi-tag-fill"></i>
        <span style="color:var(--txt);font-size:.95rem">${escH(label)}</span>
        <span style="font-size:.72rem;color:var(--txm)">${rs.length} rule${rs.length!==1?'s':''}</span>
        <div class="ms-auto d-flex align-items-center" onclick="event.stopPropagation()">
          <div class="d-flex flex-column align-items-center" style="width:65px">
            <span style="font-size:.7rem;color:var(--txt2);line-height:1;margin-bottom:2px">All Active</span>
            <div class="form-check form-switch mb-0 d-flex justify-content-center">
              <input class="form-check-input group-active-cb" type="checkbox" role="switch" data-gid="${gid}" ${allActive?'checked':''} style="cursor:pointer;margin-top:0">
            </div>
          </div>
          <div class="d-flex flex-column align-items-center" style="width:65px">
            <span style="font-size:.7rem;color:var(--txt2);line-height:1;margin-bottom:2px">All Read</span>
            <div class="form-check form-switch mb-0 d-flex justify-content-center">
              <input class="form-check-input group-read-cb" type="checkbox" role="switch" data-gid="${gid}" ${allRead?'checked':''} style="cursor:pointer;margin-top:0">
            </div>
          </div>
          <div style="width:80px"></div>
        </div>
      </div>
      <div class="group-body" data-gid="${gid}" style="display:${isCollapsed?'none':''}">
        <div class="card" style="border-radius:0 0 8px 8px;border-top:none">
          <div class="card-body p-0">
            <div class="table-responsive">
              <table class="table mb-0">
                <thead>
                  <tr>
                    <th style="width:28px"><input type="checkbox" id="select-all-cb" title="Select all" style="cursor:pointer;accent-color:var(--marb)"></th>
                    <th style="width:35px">#</th>
                    <th style="width:60px">Source</th>
                    <th>From</th><th>Subject</th><th>Body</th>
                    <th style="width:65px;text-align:center" title="Active"><i class="bi bi-toggle-on"></i> Active</th>
                    <th style="width:65px;text-align:center" title="Mark Read"><i class="bi bi-envelope-open"></i> Read</th>
                    <th style="width:65px;text-align:center" title="Keep in Inbox"><i class="bi bi-inbox"></i> Keep</th>
                    <th style="width:65px;text-align:center" title="Star Email"><i class="bi bi-star"></i> Star</th>
                    <th style="width:80px;text-align:right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${rs.map(r=>`<tr data-id="${r.id}" style="opacity:${r.is_active?1:.45}">
                    <td><input type="checkbox" class="rule-cb" data-id="${r.id}" style="cursor:pointer;accent-color:var(--marb)"></td>
                    <td style="font-size:.78rem">${r.id}</td>
                    <td>${r.created_by==='ai'
                      ? '<span style="background:rgba(59,130,246,.18);color:#60a5fa;border:1px solid rgba(59,130,246,.3);border-radius:4px;padding:1px 6px;font-size:.72rem;font-weight:600">AI</span>'
                      : '<span style="background:rgba(255,255,255,.07);color:var(--txt2);border:1px solid #3a3a3a;border-radius:4px;padding:1px 6px;font-size:.72rem">User</span>'
                    }</td>
                    <td>${pill(r.from_contains)}</td>
                    <td>${pill(r.subject_contains)}</td>
                    <td>${pill(r.body_contains)}</td>
                    <td style="text-align:center">${sw(r.id,r.is_active,'rule-active-cb')}</td>
                    <td style="text-align:center">${sw(r.id,r.mark_as_read,'rule-read-cb')}</td>
                    <td style="text-align:center">${sw(r.id,r.keep_in_inbox,'rule-keep-cb')}</td>
                    <td style="text-align:center">${sw(r.id,r.star_email,'rule-star-cb')}</td>
                    <td style="text-align:right">
                      <div class="d-flex gap-1 justify-content-end">
                        <a href="/rule-editor?edit=${r.id}" class="btn btn-sm btn-outline-primary" title="Edit"><i class="bi bi-pencil"></i></a>
                        <button class="btn btn-sm btn-outline-danger del-btn" data-id="${r.id}" title="Delete"><i class="bi bi-trash"></i></button>
                      </div>
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

  // Global buttons
  c.querySelector('#expand-all-btn')?.addEventListener('click',()=>setAllCollapsed(false));
  c.querySelector('#collapse-all-btn')?.addEventListener('click',()=>setAllCollapsed(true));
  c.querySelector('#save-changes-btn')?.addEventListener('click',saveAllChanges);

  // Group collapse toggle
  c.querySelectorAll('.rule-group-header').forEach(hdr=>{
    hdr.addEventListener('click',()=>{
      const gid=hdr.dataset.gid;
      const body=c.querySelector('.group-body[data-gid="'+gid+'"]');
      const icon=hdr.querySelector('.collapse-icon');
      collapsed[gid]=!collapsed[gid];
      body.style.display=collapsed[gid]?'none':'';
      if(icon)icon.className='bi '+(collapsed[gid]?'bi-chevron-right':'bi-chevron-down')+' collapse-icon me-1';
    });
  });

  // Group active/read toggles
  c.querySelectorAll('.group-active-cb').forEach(cb=>{
    cb.addEventListener('change',()=>{
      const gid=cb.dataset.gid;
      c.querySelector('.group-body[data-gid="'+gid+'"]')?.querySelectorAll('tr[data-id]').forEach(row=>{
        const id=row.dataset.id;
        row.style.opacity=cb.checked?1:.45;
        const rc=row.querySelector('.rule-active-cb');if(rc)rc.checked=cb.checked;
        markPending(id,'is_active',cb.checked);
        allRules.forEach(r=>{if(String(r.id)===String(id))r.is_active=cb.checked;});
      });
      document.getElementById('active-rules-count').textContent=allRules.filter(r=>r.is_active).length;
    });
  });
  c.querySelectorAll('.group-read-cb').forEach(cb=>{
    cb.addEventListener('change',()=>{
      const gid=cb.dataset.gid;
      c.querySelector('.group-body[data-gid="'+gid+'"]')?.querySelectorAll('tr[data-id]').forEach(row=>{
        const rc=row.querySelector('.rule-read-cb');if(rc)rc.checked=cb.checked;
        markPending(row.dataset.id,'mark_as_read',cb.checked);
      });
    });
  });

  // Individual switches — all just queue pending changes
  const switchMap={'.rule-active-cb':'is_active','.rule-read-cb':'mark_as_read','.rule-keep-cb':'keep_in_inbox','.rule-star-cb':'star_email'};
  for(const[sel,field]of Object.entries(switchMap)){
    c.querySelectorAll(sel).forEach(cb=>{
      cb.addEventListener('change',()=>{
        if(field==='is_active'){
          const row=c.querySelector('tr[data-id="'+cb.dataset.id+'"]');
          if(row)row.style.opacity=cb.checked?1:.45;
          allRules.forEach(r=>{if(String(r.id)===String(cb.dataset.id))r.is_active=cb.checked;});
          document.getElementById('active-rules-count').textContent=allRules.filter(r=>r.is_active).length;
        }
        markPending(cb.dataset.id,field,cb.checked);
      });
    });
  }

  // Delete buttons
  c.querySelectorAll('.del-btn').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      if(!confirm('Delete rule #'+btn.dataset.id+'?'))return;
      try{await fetch('/api/rules/'+btn.dataset.id,{method:'DELETE',credentials:'same-origin'});await loadRules();}
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
    allRules=await fetch('/api/rules',{credentials:'same-origin'}).then(r=>r.json());
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
    btn.disabled=true;btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Learning...';
    showStatus('learn-status','Scanning your labeled emails for patterns...','info');
    try{
      const res=await fetch('/learn-rules',{method:'POST',credentials:'same-origin'});
      const text=await res.text();
      if(text.trim().startsWith('<')){throw new Error('Session expired — please log out and log back in.');}
      const d=JSON.parse(text);
      if(d.error){
        if(d.error.includes('Not logged in') || res.status===401){
          throw new Error('Google session expired — please <a href="/logout" style="color:#f87171">log out</a> and log back in.');
        }
        throw new Error(d.error);
      }
      showStatus('learn-status',`✓ Created ${d.created||0} new rule(s).`+(d.created===0?' (Needs 2+ emails from same domain in a @LL- label.)':''),'success');
      await loadRules();
    }catch(e){showStatus('learn-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-cpu me-1"></i>Learn Rules';}
  });

  // ── Bulk selection & delete ──────────────────────────────
  let selectedIds = new Set();

  function updateBulkBar(){
    const bar = document.getElementById('bulk-bar');
    const cnt = document.getElementById('bulk-count');
    if(!bar) return;
    if(selectedIds.size > 0){
      bar.style.display = 'flex';
      cnt.textContent = selectedIds.size + ' rule' + (selectedIds.size !== 1 ? 's' : '') + ' selected';
    } else {
      bar.style.display = 'none';
    }
  }

  document.addEventListener('change', e => {
    if(e.target.classList.contains('rule-cb')){
      const id = parseInt(e.target.dataset.id);
      if(e.target.checked) selectedIds.add(id);
      else selectedIds.delete(id);
      updateBulkBar();
      const all = document.querySelectorAll('.rule-cb');
      const checked = document.querySelectorAll('.rule-cb:checked');
      const cb = document.getElementById('select-all-cb');
      if(cb){ cb.indeterminate = checked.length > 0 && checked.length < all.length; cb.checked = checked.length === all.length && all.length > 0; }
    }
    if(e.target.id === 'select-all-cb'){
      document.querySelectorAll('.rule-cb').forEach(cb => {
        cb.checked = e.target.checked;
        const id = parseInt(cb.dataset.id);
        if(e.target.checked) selectedIds.add(id);
        else selectedIds.delete(id);
      });
      updateBulkBar();
    }
  });

  document.getElementById('bulk-deselect-btn')?.addEventListener('click', () => {
    selectedIds.clear();
    document.querySelectorAll('.rule-cb').forEach(cb => cb.checked = false);
    const cb = document.getElementById('select-all-cb');
    if(cb){ cb.checked = false; cb.indeterminate = false; }
    updateBulkBar();
  });

  document.getElementById('bulk-delete-btn')?.addEventListener('click', async () => {
    if(selectedIds.size === 0) return;
    const n = selectedIds.size;
    if(!confirm('Delete ' + n + ' rule' + (n !== 1 ? 's' : '') + '? This cannot be undone.')) return;
    const btn = document.getElementById('bulk-delete-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-sm me-1"></span>Deleting...';
    const ids = Array.from(selectedIds);
    let failed = 0;
    for(const id of ids){
      try{
        const r = await fetch('/api/rules/' + id, {method:'DELETE', credentials:'same-origin'});
        if(!r.ok) failed++;
      } catch(e){ failed++; }
    }
    selectedIds.clear();
    updateBulkBar();
    await loadRules();
    if(failed > 0) showStatus('learn-status', 'Deleted ' + (ids.length-failed) + ' rule(s). ' + failed + ' failed.', 'error');
    else showStatus('learn-status', '\u2713 Deleted ' + ids.length + ' rule(s).', 'success');
    setTimeout(() => showStatus('learn-status','',''), 3000);
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete Selected';
  });

});

function showStatus(id,msg,type){const el=document.getElementById(id);if(!el)return;el.className='status-msg '+type;el.innerHTML=msg;el.style.display=msg?'block':'none';}
function getForm(){return{label_name:document.getElementById('label-name').value.trim(),from_contains:document.getElementById('from-contains').value.trim(),subject_contains:document.getElementById('subject-contains').value.trim(),body_contains:document.getElementById('body-contains').value.trim(),is_active:document.getElementById('is-active').checked,mark_as_read:document.getElementById('mark-as-read').checked};}
function setForm(r){document.getElementById('label-name').value=r.label_name||'';document.getElementById('from-contains').value=r.from_contains||'';document.getElementById('subject-contains').value=r.subject_contains||'';document.getElementById('body-contains').value=r.body_contains||'';document.getElementById('is-active').checked=r.is_active!==false;document.getElementById('mark-as-read').checked=!!r.mark_as_read;document.getElementById('rule-form').dataset.editingId=r.id;document.getElementById('form-card-title').innerHTML='<i class="bi bi-pencil me-2" style="color:var(--marb)"></i>Editing Rule #'+r.id;document.getElementById('submit-btn-text').textContent='Update Rule';}
function clearForm(){document.getElementById('rule-form').reset();document.getElementById('is-active').checked=true;delete document.getElementById('rule-form').dataset.editingId;document.getElementById('form-card-title').innerHTML='<i class="bi bi-plus-circle me-2" style="color:var(--marb)"></i>New Rule';document.getElementById('submit-btn-text').textContent='Save Rule';showStatus('rule-status','','');}
document.addEventListener('DOMContentLoaded',async()=>{
  const params=new URLSearchParams(window.location.search);
  const editId=params.get('edit');
  if(editId){try{const rules=await fetch('/api/rules').then(r=>r.json());const rule=rules.find(r=>String(r.id)===String(editId));if(rule)setForm(rule);}catch(e){console.error(e);}}
  document.getElementById('clear-btn')?.addEventListener('click',clearForm);
  document.getElementById('rule-form')?.addEventListener('submit',async(e)=>{
    e.preventDefault();
    const data=getForm();
    if(!data.label_name){showStatus('rule-status','Label name is required.','error');return;}
    if(!data.from_contains&&!data.subject_contains&&!data.body_contains){showStatus('rule-status','At least one match condition is required.','error');return;}
    const editingId=document.getElementById('rule-form').dataset.editingId;
    const url=editingId?'/api/rules/'+editingId:'/api/rules';
    const method=editingId?'PUT':'POST';
    const btn=document.querySelector('#rule-form button[type="submit"]');
    btn.disabled=true;btn.innerHTML='<span class="spinner-border spinner-sm me-2"></span>Saving…';
    try{
      const res=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
      const result=await res.json();
      if(!res.ok)throw new Error(result.error||res.statusText);
      showStatus('rule-status',editingId?'✓ Rule updated! <a href="/rule-list" style="color:#58d68d">View all rules</a>':'✓ Rule saved! <a href="/rule-list" style="color:#58d68d">View all rules</a>','success');
      if(!editingId)clearForm();
    }catch(e){showStatus('rule-status','Error: '+e.message,'error');}
    finally{btn.disabled=false;btn.innerHTML='<i class="bi bi-check-circle me-1"></i><span id="submit-btn-text">'+(document.getElementById('rule-form').dataset.editingId?'Update Rule':'Save Rule')+'</span>';}
  });
});
